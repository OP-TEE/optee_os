/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <types_ext.h>
#include <drivers/ps2mouse.h>
#include <drivers/serial.h>
#include <string.h>
#include <keep.h>
#include <trace.h>

#define PS2_CMD_RESET			0xff
#define PS2_CMD_ACK			0xfa
#define PS2_CMD_ENABLE_DATA_REPORTING	0xf4
#define PS2_BAT_OK			0xaa
#define PS2_MOUSE_ID			0x00

#define PS2_BYTE0_Y_OVERFLOW		(1 << 7)
#define PS2_BYTE0_X_OVERFLOW		(1 << 6)
#define PS2_BYTE0_Y_SIGN		(1 << 5)
#define PS2_BYTE0_X_SIGN		(1 << 4)
#define PS2_BYTE0_ALWAYS_ONE		(1 << 3)
#define PS2_BYTE0_MIDDLE_DOWN		(1 << 2)
#define PS2_BYTE0_RIGHT_DOWN		(1 << 1)
#define PS2_BYTE0_LEFT_DOWN		(1 << 0)

static void call_callback(struct ps2mouse_data *d, uint8_t byte1,
			  uint8_t byte2, uint8_t byte3)
{
	uint8_t button;
	int16_t xdelta;
	int16_t ydelta;

	button = byte1 & (PS2_BYTE0_MIDDLE_DOWN | PS2_BYTE0_RIGHT_DOWN |
			  PS2_BYTE0_LEFT_DOWN);

	if (byte1 & PS2_BYTE0_X_OVERFLOW) {
		xdelta = byte1 & PS2_BYTE0_X_SIGN ? -255 : 255;
	} else {
		xdelta = byte2;
		if (byte1 & PS2_BYTE0_X_SIGN)
			xdelta |= 0xff00; /* sign extend */
	}

	if (byte1 & PS2_BYTE0_Y_OVERFLOW) {
		ydelta = byte1 & PS2_BYTE0_Y_SIGN ? -255 : 255;
	} else {
		ydelta = byte3;
		if (byte1 & PS2_BYTE0_Y_SIGN)
			ydelta |= 0xff00; /* sign extend */
	}

	d->callback(d->callback_data, button, xdelta, -ydelta);
}

static void psm_consume(struct ps2mouse_data *d, uint8_t b)
{
	switch (d->state) {
	case PS2MS_RESET:
		if (b != PS2_CMD_ACK)
			goto reset;
		d->state = PS2MS_INIT;
		return;
	case PS2MS_INIT:
		if (b != PS2_BAT_OK)
			goto reset;
		d->state = PS2MS_INIT2;
		return;
	case PS2MS_INIT2:
		if (b != PS2_MOUSE_ID) {
			EMSG("Unexpected byte 0x%x in state %d", b, d->state);
			d->state = PS2MS_INACTIVE;
			return;
		}
		d->state = PS2MS_INIT3;
		d->serial->ops->putc(d->serial, PS2_CMD_ENABLE_DATA_REPORTING);
		return;
	case PS2MS_INIT3:
		d->state = PS2MS_ACTIVE1;
		return;
	case PS2MS_ACTIVE1:
		if (!(b & PS2_BYTE0_ALWAYS_ONE))
			goto reset;
		d->bytes[0] = b;
		d->state = PS2MS_ACTIVE2;
		return;
	case PS2MS_ACTIVE2:
		d->bytes[1] = b;
		d->state = PS2MS_ACTIVE3;
		return;
	case PS2MS_ACTIVE3:
		d->state = PS2MS_ACTIVE1;
		call_callback(d, d->bytes[0], d->bytes[1], b);
		return;
	default:
		EMSG("Unexpected byte 0x%x in state %d", b, d->state);
		return;
	}

reset:
	EMSG("Unexpected byte 0x%x in state %d, resetting", b, d->state);
	d->state = PS2MS_RESET;
	d->serial->ops->putc(d->serial, PS2_CMD_RESET);
}

static enum itr_return ps2mouse_itr_cb(struct itr_handler *h)
{
	struct ps2mouse_data *d = h->data;

	if (!d->serial->ops->have_rx_data(d->serial))
		return ITRR_NONE;

	while (true) {
		psm_consume(d, d->serial->ops->getchar(d->serial));
		if (!d->serial->ops->have_rx_data(d->serial))
			return ITRR_HANDLED;
	}
}
KEEP_PAGER(ps2mouse_itr_cb);

void ps2mouse_init(struct ps2mouse_data *d, struct serial_chip *serial,
		   size_t serial_it, ps2mouse_callback cb, void *cb_data)
{
	memset(d, 0, sizeof(*d));
	d->serial = serial;
	d->state = PS2MS_RESET;
	d->itr_handler.it = serial_it;
	d->itr_handler.flags = ITRF_TRIGGER_LEVEL;
	d->itr_handler.handler = ps2mouse_itr_cb;
	d->itr_handler.data = d;
	d->callback = cb;
	d->callback_data = cb_data;

	itr_add(&d->itr_handler);
	itr_enable(serial_it);
	d->serial->ops->putc(d->serial, PS2_CMD_RESET);
}
