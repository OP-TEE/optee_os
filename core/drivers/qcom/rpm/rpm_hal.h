/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPM_HAL_H__
#define __RPM_HAL_H__

#include <arm.h>
#include <io.h>
#include <stdbool.h>
#include <stdint.h>
#include <types_ext.h>

#include "rpm_target.h"

enum rpm_hal_status {
	RPM_HAL_OK = 0,
	RPM_HAL_ERROR,
	RPM_HAL_INVALID_PARAM,
	RPM_HAL_TOC_NOT_FOUND,
	RPM_HAL_FIFO_NOT_FOUND,
};

/* One side (tx or rx) of a discovered MSG RAM FIFO. */
struct rpm_hal_fifo {
	vaddr_t desc_va; /* { read_ind, write_ind }, 8 bytes */
	vaddr_t data_va; /* fifo data region, desc_va + 8 */
	uint32_t size; /* data region size, bytes (always a multiple of 4) */
};

extern vaddr_t rpm_hal_ipcc_base;

/*
 * Map MSG RAM, locate the ToC, and resolve the tx/rx FIFO entries
 * matching @tx_fifo_id/@rx_fifo_id. Must be called once before any
 * other rpm_hal_*() call.
 */
enum rpm_hal_status rpm_hal_init(uint32_t tx_fifo_id, uint32_t rx_fifo_id,
				 struct rpm_hal_fifo *tx,
				 struct rpm_hal_fifo *rx);

/* FIFO descriptor layout: { read_ind: u32, write_ind: u32 }. */
static inline uint32_t rpm_hal_fifo_read_ind(const struct rpm_hal_fifo *fifo)
{
	return io_read32(fifo->desc_va);
}

static inline uint32_t rpm_hal_fifo_write_ind(const struct rpm_hal_fifo *fifo)
{
	return io_read32(fifo->desc_va + sizeof(uint32_t));
}

static inline void rpm_hal_fifo_set_read_ind(const struct rpm_hal_fifo *fifo,
					      uint32_t ind)
{
	io_write32(fifo->desc_va, ind);
}

static inline void rpm_hal_fifo_set_write_ind(const struct rpm_hal_fifo *fifo,
					       uint32_t ind)
{
	io_write32(fifo->desc_va + sizeof(uint32_t), ind);
}

/*
 * 32-bit-only copy of @count words between @fifo's data region
 * (starting at word index @start) and @buffer, wrapping around the
 * ring. @to_fifo selects which way the copy goes. MSG RAM does not
 * tolerate sub-word access cycles -- every word in @buffer, including
 * a padded trailing remainder, must be read/written as a full 32-bit
 * access against the FIFO. Returns the new index. Caller must have
 * already validated available space/data.
 */
uint32_t rpm_hal_fifo_copy(const struct rpm_hal_fifo *fifo,
			   uint32_t byte_ind, void *buffer, uint32_t size,
			    bool to_fifo);

/* Ring the doorbell telling RPM that new data is waiting in the tx FIFO. */
static inline void rpm_hal_ring_doorbell(void)
{
	vaddr_t send_reg = rpm_hal_ipcc_base + RPM_IPCC_LEGACY_RPM_FW_OFFS;

	dsb();
	io_write32(send_reg, RPM_IPCC_LEGACY_RPM_FW_MASK);
}

#endif /* __RPM_HAL_H__ */
