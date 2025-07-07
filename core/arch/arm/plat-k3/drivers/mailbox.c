// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments K3 Mailbox Driver
 * Copyright (C) 2025 Texas Instruments Incorporated - https://www.ti.com/
 */

#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ti_sci_protocol.h"
#include "ti_sci_transport.h"

/**
 * TI K3 Mailbox structure
 * @tx_base: Base address for the transmit mailbox
 * @rx_base: Base address for the receive mailbox
 * @tx_sram_va: Virtual address for the transmit mailbox SRAM
 */
struct ti_k3_mailbox_cfg {
	vaddr_t tx_base;
	vaddr_t rx_base;
	vaddr_t tx_sram_va;
} mailbox_obj;

struct ti_k3_mailbox_cfg *mailbox_ctx = &mailbox_obj;

static TEE_Result ti_mailbox_poll_rx_status(void)
{
	uint32_t num_messages_pending = 0U;
	uint32_t retry_count = 100U;

	while (num_messages_pending == 0U) {
		num_messages_pending = io_read32(mailbox_ctx->rx_base +
						 TI_MAILBOX_MSG_STATUS);

		if (retry_count-- == 0U) {
			EMSG("Mailbox RX status polling timed out");
			return TEE_ERROR_TIMEOUT;
		}
		mdelay(10);
	}

	return TEE_SUCCESS;
}

TEE_Result ti_sci_transport_send(const struct ti_sci_msg *msg)
{
	uint32_t num_bytes;
	paddr_t phys_addr;

	if (!msg)
		return TEE_ERROR_BAD_PARAMETERS;

	num_bytes = msg->len;

	if (io_read32(mailbox_ctx->tx_base +
		      TI_MAILBOX_FIFO_STATUS) != 0U) {
		EMSG("Mailbox TX FIFO is not empty");
		return TEE_ERROR_BUSY;
	}

	if (num_bytes > MAILBOX_MAX_MESSAGE_SIZE) {
		EMSG("Message size exceeds maximum allowed size");
		return TEE_ERROR_BAD_STATE;
	}

	memmove((void *)mailbox_ctx->tx_sram_va, msg->buf, num_bytes);
	phys_addr = virt_to_phys((void *)mailbox_ctx->tx_sram_va);
	io_write32(mailbox_ctx->tx_base + TI_MAILBOX_MSG, (uint32_t)phys_addr);

	return TEE_SUCCESS;
}

TEE_Result ti_sci_transport_recv(struct ti_sci_msg *msg)
{
	uint32_t num_bytes;
	uint64_t recv_pa;
	void *recv_va;
	TEE_Result ret = TEE_SUCCESS;

	if (!msg)
		return TEE_ERROR_BAD_PARAMETERS;

	num_bytes = msg->len;
	ret = ti_mailbox_poll_rx_status();
	if (ret != 0) {
		EMSG("Mailbox RX status polling failed");
		return ret;
	}

	recv_pa = io_read32(mailbox_ctx->rx_base + TI_MAILBOX_MSG);

	if (recv_pa < MAILBOX_RX_START_REGION) {
		EMSG("Message not received invalid address\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (num_bytes > MAILBOX_MAX_MESSAGE_SIZE) {
		EMSG("Message size exceeds maximum allowed size\n");
		return TEE_ERROR_BAD_STATE;
	}

	recv_va = (uint8_t *)core_mmu_get_va(recv_pa, MEM_AREA_IO_SEC, 0x1000);
	if (!recv_va) {
		EMSG("Failed to get virtual address for RX");
		return TEE_ERROR_COMMUNICATION;
	}

	memmove(msg->buf, (uint8_t *)recv_va, num_bytes);
	return TEE_SUCCESS;
}

TEE_Result ti_sci_transport_clear_thread(uint32_t chan_id)
{
	uint32_t try_count;
	(void)chan_id;

	try_count = io_read32(mailbox_ctx->rx_base + TI_MAILBOX_MSG_STATUS);
	while (io_read32(mailbox_ctx->rx_base +
			 TI_MAILBOX_MSG_STATUS) != 0U) {
		io_read32(mailbox_ctx->rx_base + TI_MAILBOX_MSG);
		if (try_count == 0U) {
			EMSG("Mailbox RX status polling timed out");
			return TEE_ERROR_TIMEOUT;
		}
		try_count--;
	}

	return TEE_SUCCESS;
}

TEE_Result ti_sci_transport_init(void)
{
	mailbox_ctx->rx_base = core_mmu_get_va(TI_MAILBOX_RX_BASE,
					       MEM_AREA_IO_SEC, 0x1000);
	if (!mailbox_ctx->rx_base)
		return TEE_ERROR_OUT_OF_MEMORY;

	mailbox_ctx->tx_base = core_mmu_get_va(TI_MAILBOX_TX_BASE,
					       MEM_AREA_IO_SEC, 0x1000);
	if (!mailbox_ctx->tx_base)
		return TEE_ERROR_OUT_OF_MEMORY;

	mailbox_ctx->tx_sram_va = core_mmu_get_va(MAILBOX_TX_START_REGION,
						  MEM_AREA_IO_SEC, 0x1000);
	if (!mailbox_ctx->tx_sram_va)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}
