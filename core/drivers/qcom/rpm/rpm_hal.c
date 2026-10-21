// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <arm.h>
#include <inttypes.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "rpm_hal.h"
#include "rpm_ipcc.h"
#include "rpm_protocol.h"
#include "rpm_target.h"

/*
 * Both regions are mapped MEM_AREA_IO_{NSEC,SEC}, which core_mmu_type_to_attr()
 * resolves to TEE_MATTR_MEM_TYPE_DEV -- Device memory, non-cacheable and
 * (per the Arm memory model) implicitly ordered against other Device/Normal
 * accesses from this core. That covers access ordering; it does not cover
 * completion -- a dsb() is still needed wherever a write must be guaranteed
 * visible to RPM (a separate observer) before the next step depends on it.
 */
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, RPM_MSG_RAM_BASE,
			 RPM_MSG_RAM_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, RPM_IPCC_BASE, CORE_MMU_PGDIR_SIZE);

static vaddr_t ipcc_base;

static vaddr_t rpm_hal_find_toc(vaddr_t msg_ram_base)
{
	vaddr_t toc_va = msg_ram_base + RPM_MSG_RAM_SIZE - RPM_TOC_SIZE;

	if (io_read32(toc_va + RPM_TOC_MAGIC_IDX * sizeof(uint32_t)) !=
	    RPM_TOC_MAGIC)
		return 0;

	return toc_va;
}

static enum rpm_hal_status
rpm_hal_find_fifo(vaddr_t msg_ram_base, vaddr_t toc_va, uint32_t fifo_id,
		   struct rpm_hal_fifo *fifo)
{
	uint32_t num_entries = io_read32(toc_va +
					  RPM_TOC_LENGTH_IDX * sizeof(uint32_t));
	uint32_t max_entries = (RPM_TOC_SIZE -
				 RPM_TOC_ENTRIES_IDX * sizeof(uint32_t)) /
				sizeof(struct rpm_toc_entry);
	vaddr_t entries_va = toc_va + RPM_TOC_ENTRIES_IDX * sizeof(uint32_t);
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

		if (!size || offset + 8 + size > RPM_MSG_RAM_SIZE)
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

	toc_va = rpm_hal_find_toc(msg_ram_base);
	if (!toc_va)
		return RPM_HAL_TOC_NOT_FOUND;

	status = rpm_hal_find_fifo(msg_ram_base, toc_va, tx_fifo_id, tx);
	if (status != RPM_HAL_OK)
		return status;

	status = rpm_hal_find_fifo(msg_ram_base, toc_va, rx_fifo_id, rx);
	if (status != RPM_HAL_OK)
		return status;

	ipcc_base = (vaddr_t)phys_to_virt(RPM_IPCC_BASE, MEM_AREA_IO_SEC,
					   CORE_MMU_PGDIR_SIZE);
	if (!ipcc_base)
		return RPM_HAL_ERROR;

	/*
	 * Diagnostic only, semantics not yet confirmed against the
	 * reference: dump every readable IPCC register for the TZ client
	 * once, right after mapping, before any send/recv traffic. If the
	 * receive-signal-enable mask is 0, TZ's own IPCC endpoint may not
	 * be set up to ever latch RPM's incoming signal at all -- a cause
	 * upstream of anything RPM does.
	 */
	DMSG("RPM hal: ipcc_base=%#"PRIxVA" tz recv_id=%#"PRIx32,
	     ipcc_base,
	     io_read32(rpm_ipcc_reg(ipcc_base, RPM_IPCC_PROTOCOL_MPROC,
				     RPM_IPCC_CLIENT_TZ,
				     RPM_IPCC_RECV_ID_OFFS)));

	return RPM_HAL_OK;
}

/* FIFO descriptor layout: { read_ind: u32, write_ind: u32 }. */
uint32_t rpm_hal_fifo_read_ind(const struct rpm_hal_fifo *fifo)
{
	return io_read32(fifo->desc_va);
}

uint32_t rpm_hal_fifo_write_ind(const struct rpm_hal_fifo *fifo)
{
	return io_read32(fifo->desc_va + sizeof(uint32_t));
}

void rpm_hal_fifo_set_read_ind(const struct rpm_hal_fifo *fifo, uint32_t ind)
{
	/* Ensure the data this read index exposes as "consumed" has itself
	 * been fully read before RPM can see the index move and reuse that
	 * ring space.
	 */
	dsb();
	io_write32(fifo->desc_va, ind);
}

void rpm_hal_fifo_set_write_ind(const struct rpm_hal_fifo *fifo, uint32_t ind)
{
	/* Ensure the payload just written into the ring is visible before
	 * the write index that advertises it is updated.
	 */
	dsb();
	io_write32(fifo->desc_va + sizeof(uint32_t), ind);
}

/*
 * 32-bit-only copy of @count words between @fifo's data region
 * (starting at word index @start) and @buffer, wrapping around the
 * ring. @direction selects which way the copy goes. MSG RAM does not
 * tolerate sub-word access cycles -- every
 * word in @buffer, including a padded trailing remainder, must be
 * read/written as a full 32-bit access against the FIFO.
 */
static uint32_t rpm_hal_fifo_copy(const struct rpm_hal_fifo *fifo,
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

uint32_t rpm_hal_fifo_write(const struct rpm_hal_fifo *fifo,
			     uint32_t write_ind, const void *buffer,
			     uint32_t size)
{
	return rpm_hal_fifo_copy(fifo, write_ind, (void *)buffer, size, true);
}

uint32_t rpm_hal_fifo_read(const struct rpm_hal_fifo *fifo, uint32_t read_ind,
			    void *buffer, uint32_t size)
{
	return rpm_hal_fifo_copy(fifo, read_ind, buffer, size, false);
}

void rpm_hal_ring_doorbell(void)
{
	vaddr_t send_reg = ipcc_base + RPM_IPCC_LEGACY_AOP_OFFS;

	/* The write index update that precedes this call must be visible to
	 * RPM before the doorbell tells it to look.
	 */
	dsb();
	io_write32(send_reg, RPM_IPCC_LEGACY_AOP_MASK);
}

uint32_t rpm_hal_doorbell_poll(void)
{
	vaddr_t recv_reg = rpm_ipcc_reg(ipcc_base, RPM_IPCC_PROTOCOL_MPROC,
					 RPM_IPCC_CLIENT_TZ,
					 RPM_IPCC_RECV_ID_OFFS);

	return io_read32(recv_reg);
}

void rpm_hal_doorbell_clear(uint32_t raw)
{
	vaddr_t clear_reg = rpm_ipcc_reg(ipcc_base, RPM_IPCC_PROTOCOL_MPROC,
					  RPM_IPCC_CLIENT_TZ,
					  RPM_IPCC_RECV_SIGNAL_CLEAR_OFFS);

	io_write32(clear_reg, raw);
}
