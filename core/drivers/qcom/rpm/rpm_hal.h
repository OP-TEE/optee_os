/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */


#ifndef __RPM_HAL_H__
#define __RPM_HAL_H__

#include <stdint.h>
#include <types_ext.h>

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

/*
 * Map MSG RAM, locate the ToC, and resolve the tx/rx FIFO entries
 * matching @tx_fifo_id/@rx_fifo_id. Must be called once before any
 * other rpm_hal_*() call.
 */
enum rpm_hal_status rpm_hal_init(uint32_t tx_fifo_id, uint32_t rx_fifo_id,
				  struct rpm_hal_fifo *tx,
				  struct rpm_hal_fifo *rx);

uint32_t rpm_hal_fifo_read_ind(const struct rpm_hal_fifo *fifo);
uint32_t rpm_hal_fifo_write_ind(const struct rpm_hal_fifo *fifo);
void rpm_hal_fifo_set_read_ind(const struct rpm_hal_fifo *fifo, uint32_t ind);
void rpm_hal_fifo_set_write_ind(const struct rpm_hal_fifo *fifo,
				 uint32_t ind);

/*
 * Copy @size bytes from @buffer into @fifo starting at @write_ind,
 * wrapping around the ring as needed. @size need not be a multiple of
 * 4; the trailing remainder is still written as a full 32-bit word
 * (never a sub-word MSG RAM access). Returns the new write index.
 * Caller must have already validated available space.
 */
uint32_t rpm_hal_fifo_write(const struct rpm_hal_fifo *fifo,
			     uint32_t write_ind, const void *buffer,
			     uint32_t size);

/*
 * Copy @size bytes out of @fifo starting at @read_ind into @buffer,
 * wrapping around the ring as needed. Returns the new read index.
 * Caller must have already validated available data.
 */
uint32_t rpm_hal_fifo_read(const struct rpm_hal_fifo *fifo, uint32_t read_ind,
			    void *buffer, uint32_t size);

/* Ring the doorbell telling RPM that new data is waiting in the tx FIFO. */
void rpm_hal_ring_doorbell(void);

/*
 * Read IPC_RECV_ID. Returns RPM_IPCC_NO_DATA (see common/rpm_ipcc.h)
 * if nothing is pending, otherwise the raw register value -- pass it
 * to rpm_hal_doorbell_clear() verbatim once consumed (the clear
 * register takes the same {client, signal} encoding that was read,
 * not a freshly-constructed one).
 */
uint32_t rpm_hal_doorbell_poll(void);

/* Clear a pending doorbell signal previously returned by
 * rpm_hal_doorbell_poll().
 */
void rpm_hal_doorbell_clear(uint32_t raw);

#endif /* __RPM_HAL_H__ */
