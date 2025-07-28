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

static vaddr_t mailbox_tx_base;
static vaddr_t mailbox_rx_base;
static vaddr_t mailbox_tx_sram_va;
static vaddr_t mailbox_rx_sram_va;

static TEE_Result ti_mailbox_poll_rx_status(void)
{
	uint32_t num_messages_pending = 0U;
	vaddr_t mailbox_status_addr = mailbox_rx_base + TI_MAILBOX_MSG_STATUS;

	if (IO_READ32_POLL_TIMEOUT(mailbox_status_addr, num_messages_pending,
				   num_messages_pending != 0, 10, 1000)) {
		EMSG("Mailbox RX status polling timed out");
		return TEE_ERROR_TIMEOUT;
	}

	return TEE_SUCCESS;
}

TEE_Result ti_sci_transport_send(const struct ti_sci_msg *msg)
{
	uint32_t num_bytes = 0;
	paddr_t phys_addr = 0;

	if (!msg)
		return TEE_ERROR_BAD_PARAMETERS;

	num_bytes = msg->len;
	if (num_bytes > TI_SCI_MAX_MESSAGE_SIZE) {
		EMSG("Message size exceeds maximum allowed size");
		return TEE_ERROR_BAD_STATE;
	}

	if (io_read32(mailbox_tx_base + TI_MAILBOX_FIFO_STATUS) != 0U) {
		EMSG("Mailbox TX FIFO is full");
		return TEE_ERROR_BUSY;
	}

	memmove((void *)mailbox_tx_sram_va, msg->buf, num_bytes);
	phys_addr = virt_to_phys((void *)mailbox_tx_sram_va);
	io_write32(mailbox_tx_base + TI_MAILBOX_MSG, (uint32_t)phys_addr);

	return TEE_SUCCESS;
}

TEE_Result ti_sci_transport_recv(struct ti_sci_msg *msg)
{
	uint32_t num_bytes = 0;
	uint64_t recv_pa = 0;
	vaddr_t recv_offset = 0;
	vaddr_t recv_va = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!msg)
		return TEE_ERROR_BAD_PARAMETERS;

	num_bytes = msg->len;
	if (num_bytes > TI_SCI_MAX_MESSAGE_SIZE) {
		EMSG("Message size exceeds maximum allowed size\n");
		return TEE_ERROR_BAD_STATE;
	}

	ret = ti_mailbox_poll_rx_status();
	if (ret != TEE_SUCCESS) {
		EMSG("Mailbox RX status polling failed");
		return ret;
	}

	recv_pa = io_read32(mailbox_rx_base + TI_MAILBOX_MSG);
	if (recv_pa < MAILBOX_RX_START_REGION) {
		EMSG("Message not received invalid address\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	recv_offset = (vaddr_t)(recv_pa - MAILBOX_RX_START_REGION);
	recv_va = (vaddr_t)(mailbox_rx_sram_va + recv_offset);
	memmove(msg->buf, (uint8_t *)recv_va, num_bytes);
	return TEE_SUCCESS;
}

TEE_Result ti_sci_transport_init(void)
{
	mailbox_rx_base = core_mmu_get_va(TI_MAILBOX_RX_BASE,
					  MEM_AREA_IO_SEC,
					  TI_MAILBOX_DEFAULT_SIZE);
	if (!mailbox_rx_base)
		return TEE_ERROR_OUT_OF_MEMORY;

	mailbox_tx_base = core_mmu_get_va(TI_MAILBOX_TX_BASE,
					  MEM_AREA_IO_SEC,
					  TI_MAILBOX_DEFAULT_SIZE);
	if (!mailbox_tx_base)
		return TEE_ERROR_OUT_OF_MEMORY;

	mailbox_tx_sram_va = core_mmu_get_va(MAILBOX_TX_START_REGION,
					     MEM_AREA_IO_SEC,
					     TI_MAILBOX_DEFAULT_SIZE);
	if (!mailbox_tx_sram_va)
		return TEE_ERROR_OUT_OF_MEMORY;

	mailbox_rx_sram_va = core_mmu_get_va(MAILBOX_RX_START_REGION,
					     MEM_AREA_IO_SEC,
					     TI_MAILBOX_DEFAULT_SIZE);
	if (!mailbox_rx_sram_va)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}
