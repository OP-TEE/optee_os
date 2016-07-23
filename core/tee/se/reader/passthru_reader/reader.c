/*
 * Copyright (c) 2014, Linaro Limited
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

#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <stdio.h>
#include <trace.h>

#include <tee/se/util.h>
#include <tee/se/reader/interface.h>

#include "pcsc.h"
#include "reader.h"

static void pcsc_reader_dump(struct pcsc_reader *r)
{
	DMSG("[%s]:", r->se_reader.name);
	if (r->state & PCSC_READER_STATE_IGNORE)
		DMSG("  Ignore this reader");

	if (r->state & PCSC_READER_STATE_UNKNOWN)
		DMSG("  Reader unknown");

	if (r->state & PCSC_READER_STATE_UNAVAILABLE)
		DMSG("  Status unavailable");

	if (r->state & PCSC_READER_STATE_EMPTY)
		DMSG("  Card removed");

	if (r->state & PCSC_READER_STATE_PRESENT)
		DMSG("  Card inserted");

	if (r->state & PCSC_READER_STATE_ATRMATCH)
		DMSG("  ATR matches card");

	if (r->state & PCSC_READER_STATE_EXCLUSIVE)
		DMSG("  Exclusive Mode");

	if (r->state & PCSC_READER_STATE_INUSE)
		DMSG("  Shared Mode");

	if (r->state & PCSC_READER_STATE_MUTE)
		DMSG("  Unresponsive card");

	if (r->state & PCSC_READER_STATE_UNPOWERED)
		DMSG("  Reader Unpowered,");

	if (r->state & PCSC_READER_STATE_PRESENT)
		DMSG("Card Connected: [%s]",
				r->connected ? "Yes" : "No");

	if (r->connected) {
		char dumpbuf[DUMP_BUF_MAX], *buf = dumpbuf;
		size_t remain = DUMP_BUF_MAX;

		buf = print_buf(buf, &remain, "ATR: ");
		dump_hex(buf, &remain, r->atr, r->atr_len);
		DMSG("%s", buf);
	}
}

static uint32_t pcsc_reader_read_reg(struct pcsc_reader *r, uint32_t offset)
{
	return read32(r->mmio_base + offset);
}

static void pcsc_reader_write_reg(struct pcsc_reader *r, uint32_t offset,
		uint32_t value)
{
	write32(value, r->mmio_base + offset);
}

static void pcsc_reader_get_atr(struct pcsc_reader *r)
{
	uint32_t atr_paddr = 0;
	uint32_t atr_len = pcsc_reader_read_reg(r, PCSC_REG_READER_ATR_LEN);

	atr_paddr = virt_to_phys((void *)r->atr);
	pcsc_reader_write_reg(r, PCSC_REG_READER_RX_ADDR,
			atr_paddr);
	pcsc_reader_write_reg(r, PCSC_REG_READER_RX_SIZE,
			atr_len);
	pcsc_reader_write_reg(r, PCSC_REG_READER_CONTROL,
			PCSC_READER_CTL_READ_ATR);
	r->atr_len = atr_len;
}

static void pcsc_reader_connect(struct pcsc_reader *r)
{
	if (r->connected)
		panic();

	pcsc_reader_write_reg(r, PCSC_REG_READER_CONTROL,
			PCSC_READER_CTL_CONNECT |
			PCSC_READER_CTL_PROTOCOL_T1 |
			PCSC_READER_CTL_SHARE_SHARED);
	r->connected = true;
	pcsc_reader_get_atr(r);
}

static void pcsc_reader_disconnect(struct pcsc_reader *r)
{
	if (!r->connected)
		panic();

	pcsc_reader_write_reg(r, PCSC_REG_READER_CONTROL,
			PCSC_READER_CTL_DISCONNECT |
			PCSC_READER_CTL_DISPOSITION_RESET_CARD);
	r->connected = false;
	r->atr_len = 0;
}

static TEE_Result pcsc_reader_transmit(struct pcsc_reader *r, uint8_t *tx_buf,
		size_t tx_len, uint8_t *rx_buf, size_t *rx_len)
{
	uint32_t tx_buf_paddr = 0, rx_buf_paddr = 0;

	if (!r->connected)
		panic();

	tx_buf_paddr = virt_to_phys((void *)tx_buf);
	rx_buf_paddr = virt_to_phys((void *)rx_buf);

	pcsc_reader_write_reg(r, PCSC_REG_READER_TX_ADDR,
			tx_buf_paddr);
	pcsc_reader_write_reg(r, PCSC_REG_READER_TX_SIZE,
			tx_len);
	pcsc_reader_write_reg(r, PCSC_REG_READER_RX_ADDR,
			rx_buf_paddr);
	pcsc_reader_write_reg(r, PCSC_REG_READER_RX_SIZE,
			*rx_len);
	pcsc_reader_write_reg(r, PCSC_REG_READER_CONTROL,
			PCSC_READER_CTL_TRANSMIT);

	*rx_len = pcsc_reader_read_reg(r, PCSC_REG_READER_RX_SIZE);
	return TEE_SUCCESS;
}

static TEE_Result pcsc_passthru_reader_open(struct tee_se_reader *se_reader)
{
	struct pcsc_reader *r = se_reader->private_data;

	if (!se_reader->prop.sePresent) {
		EMSG("SE is not present");
		return TEE_ERROR_COMMUNICATION;
	}

	pcsc_reader_connect(r);

	pcsc_reader_dump(r);

	return TEE_SUCCESS;
}

static void pcsc_passthru_reader_close(struct tee_se_reader *se_reader)
{
	struct pcsc_reader *r = se_reader->private_data;

	pcsc_reader_disconnect(r);

	pcsc_reader_dump(r);
}

static TEE_Result pcsc_passthru_reader_transmit(struct tee_se_reader *se_reader,
		uint8_t *tx_buf, size_t tx_len, uint8_t *rx_buf, size_t *rx_len)
{
	struct pcsc_reader *r = se_reader->private_data;

	return pcsc_reader_transmit(r, tx_buf, tx_len, rx_buf, rx_len);
}

static enum tee_se_reader_state pcsc_passthru_reader_get_state(
		struct tee_se_reader *se_reader)
{
	struct pcsc_reader *r = se_reader->private_data;

	if (r->state & PCSC_READER_STATE_PRESENT)
		return READER_STATE_SE_INSERTED;
	else
		return READER_STATE_SE_EJECTED;
}

static TEE_Result pcsc_passthru_reader_get_atr(
		struct tee_se_reader *se_reader, uint8_t **atr,
		size_t *atr_len)
{
	struct pcsc_reader *r = se_reader->private_data;

	if (r->atr_len > 0) {
		*atr = r->atr;
		*atr_len = r->atr_len;
		return TEE_SUCCESS;
	} else
		return TEE_ERROR_COMMUNICATION;
}

static struct tee_se_reader_ops pcsc_passthru_reader_ops = {
	.open = pcsc_passthru_reader_open,
	.close = pcsc_passthru_reader_close,
	.get_state = pcsc_passthru_reader_get_state,
	.get_atr = pcsc_passthru_reader_get_atr,
	.transmit = pcsc_passthru_reader_transmit,
};

void init_reader(struct pcsc_reader *r, uint8_t index, uint32_t mmio_base)
{
	r->index = index;
	r->mmio_base = mmio_base;
	r->atr_len = 0;
	r->state = pcsc_reader_read_reg(r, PCSC_REG_READER_STATE);

	snprintf(r->se_reader.name, TEE_SE_READER_NAME_MAX,
			"tee_reader_pcsc#%d", index);
	r->se_reader.ops = &pcsc_passthru_reader_ops;
	r->se_reader.prop.teeOnly = true;
	r->se_reader.prop.selectResponseEnable = true;
	if (r->state & PCSC_READER_STATE_PRESENT)
		r->se_reader.prop.sePresent = true;
	else
		r->se_reader.prop.sePresent = false;
	r->se_reader.private_data = r;
}

