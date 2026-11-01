// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <arm.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

#include "rpm_hal.h"
#include "rpm_protocol.h"
#include "rpm_target.h"

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, RPM_MSG_RAM_BASE,
			RPM_MSG_RAM_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, RPM_IPCC_LEGACY_BASE, SMALL_PAGE_SIZE);

static vaddr_t ipcc_base;

static enum rpm_hal_status
rpm_hal_find_fifo(vaddr_t msg_ram_base, vaddr_t toc_va, uint32_t fifo_id,
		  struct rpm_hal_fifo *fifo)
{
	uint32_t num_entries =
		io_read32(toc_va + RPM_TOC_LENGTH_IDX * sizeof(uint32_t));
	uint32_t max_entries = (RPM_TOC_SIZE -
				 RPM_TOC_ENTRIES_IDX * sizeof(uint32_t)) /
				sizeof(struct rpm_toc_entry);
	vaddr_t entries_va = toc_va + RPM_TOC_ENTRIES_IDX * sizeof(uint32_t);
	uint32_t fifo_end = 0;
	uint32_t i = 0;

	if (num_entries > max_entries)
		return RPM_HAL_ERROR;

	for (i = 0; i < num_entries; i++) {
		vaddr_t entry_va = entries_va +
				    i * sizeof(struct rpm_toc_entry);
		uint32_t id = io_read32(entry_va +
					 offsetof(struct rpm_toc_entry,
						  fifo_id));
		uint32_t offset = io_read32(entry_va +
						 offsetof(struct rpm_toc_entry,
							  fifo_offset));
		uint32_t size = io_read32(entry_va +
					   offsetof(struct rpm_toc_entry,
						    fifo_size));

		if (id != fifo_id)
			continue;

		if (!size || !IS_ALIGNED(size, 8) ||
		    !IS_ALIGNED(offset, sizeof(uint32_t)) ||
		    ADD_OVERFLOW(offset, 8, &fifo_end) ||
		    ADD_OVERFLOW(fifo_end, size, &fifo_end) ||
		    fifo_end > RPM_MSG_RAM_SIZE - RPM_TOC_SIZE)
			return RPM_HAL_ERROR;

		fifo->desc_va = msg_ram_base + offset;
		fifo->data_va = fifo->desc_va + 8;
		fifo->size = size;

		return RPM_HAL_OK;
	}

	return RPM_HAL_FIFO_NOT_FOUND;
}

enum rpm_hal_status rpm_hal_init(uint32_t tx_fifo_id, uint32_t rx_fifo_id,
				 struct rpm_hal_fifo *tx,
				  struct rpm_hal_fifo *rx)
{
	vaddr_t msg_ram_base = 0;
	vaddr_t toc_va = 0;
	enum rpm_hal_status status = RPM_HAL_OK;

	if (!tx || !rx)
		return RPM_HAL_INVALID_PARAM;

	msg_ram_base = (vaddr_t)phys_to_virt(RPM_MSG_RAM_BASE,
					      MEM_AREA_IO_NSEC,
					      RPM_MSG_RAM_SIZE);
	if (!msg_ram_base)
		return RPM_HAL_ERROR;

	toc_va = msg_ram_base + RPM_MSG_RAM_SIZE - RPM_TOC_SIZE;
	if (io_read32(toc_va + RPM_TOC_MAGIC_IDX * sizeof(uint32_t)) !=
	    RPM_TOC_MAGIC)
		return RPM_HAL_TOC_NOT_FOUND;

	status = rpm_hal_find_fifo(msg_ram_base, toc_va, tx_fifo_id, tx);
	if (status != RPM_HAL_OK)
		return status;

	status = rpm_hal_find_fifo(msg_ram_base, toc_va, rx_fifo_id, rx);
	if (status != RPM_HAL_OK)
		return status;

	ipcc_base = (vaddr_t)phys_to_virt(RPM_IPCC_LEGACY_BASE, MEM_AREA_IO_SEC,
					   SMALL_PAGE_SIZE);
	if (!ipcc_base)
		return RPM_HAL_ERROR;

	return RPM_HAL_OK;
}

uint32_t rpm_hal_fifo_copy(const struct rpm_hal_fifo *fifo,
			   uint32_t byte_ind, void *buffer,
			   uint32_t size, bool to_fifo)
{
	uint32_t full_words = size / sizeof(uint32_t);
	uint32_t remainder = size % sizeof(uint32_t);
	uint8_t *bytes = buffer;
	uint32_t i = 0;

	for (i = 0; i < full_words; i++) {
		vaddr_t word_va = fifo->data_va + byte_ind;
		uint32_t word = 0;

		if (to_fifo) {
			memcpy(&word, bytes, sizeof(word));
			io_write32(word_va, word);
		} else {
			word = io_read32(word_va);
			memcpy(bytes, &word, sizeof(word));
		}

		bytes += sizeof(word);
		byte_ind += sizeof(word);
		if (byte_ind >= fifo->size)
			byte_ind = 0;
	}

	if (remainder) {
		vaddr_t word_va = fifo->data_va + byte_ind;
		uint32_t word = 0;

		if (to_fifo) {
			memcpy(&word, bytes, remainder);
			io_write32(word_va, word);
		} else {
			word = io_read32(word_va);
			memcpy(bytes, &word, remainder);
		}

		byte_ind += sizeof(uint32_t);
		if (byte_ind >= fifo->size)
			byte_ind = 0;
	}

	return byte_ind;
}

void rpm_hal_ring_doorbell(void)
{
	vaddr_t send_reg = ipcc_base + RPM_IPCC_LEGACY_RPM_FW_OFFS;

	dsb();
	io_write32(send_reg, RPM_IPCC_LEGACY_RPM_FW_MASK);
}
