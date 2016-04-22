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
#ifndef __DRIVERS_PS2MOUSE_H
#define __DRIVERS_PS2MOUSE_H

#include <types_ext.h>
#include <kernel/interrupt.h>
#include <drivers/serial.h>

enum ps2mouse_state {
	PS2MS_RESET,
	PS2MS_INIT,
	PS2MS_INIT2,
	PS2MS_INIT3,
	PS2MS_ACTIVE1,
	PS2MS_ACTIVE2,
	PS2MS_ACTIVE3,
	PS2MS_INACTIVE,
};

#define PS2MOUSE_BUTTON_LEFT_DOWN	(1 << 0)
#define PS2MOUSE_BUTTON_RIGHT_DOWN	(1 << 1)
#define PS2MOUSE_BUTTON_MIDDLE_DOWN	(1 << 2)

typedef void (*ps2mouse_callback)(void *data, uint8_t button, int16_t xdelta,
				  int16_t ydelta);

struct ps2mouse_data {
	struct serial_chip *serial;
	enum ps2mouse_state state;
	uint8_t bytes[2];
	struct itr_handler itr_handler;
	ps2mouse_callback callback;
	void *callback_data;
};


void ps2mouse_init(struct ps2mouse_data *d, struct serial_chip *serial,
		   size_t serial_it, ps2mouse_callback cb, void *cb_data);


#endif /*__DRIVERS_PS2MOUSE_H*/

