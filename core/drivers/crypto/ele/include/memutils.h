/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2025 NXP
 *
 * Memory management utilities.
 * Primitive to allocate, free memory.
 */

#ifndef __MEMUTILS_H__
#define __MEMUTILS_H__

#include <kernel/cache_helpers.h>
#include <stddef.h>
#include <tee_api_types.h>
#include <tee/cache.h>

/*
 * struct imx_ele_buf - Definition of a IMX ELE buffer type
 * @data: Data buffer
 * @size: Number of bytes in the data buffer
 * @paddr: Physical address of the buffer
 * @paddr_msb: MSB of the physical address
 * @paddr_lsb: LSB of the physical address
 */
struct imx_ele_buf {
	uint8_t *data;
	size_t size;
	paddr_t paddr;
	uint32_t paddr_msb;
	uint32_t paddr_lsb;
};

/*
 * Allocate cache aligned buffer, initialize it with 0's, copy data from
 * @buf to newly allocated buffer and cache flush the buffer.
 *
 * @ele_buf: Buffer allocated
 * @buf: If valid, will copy contents from this buffer to newly allocated
 *        buffer. Otherwise it is ignored.
 * @size: Size in bytes of the memory to allocate.
 */
TEE_Result imx_ele_buf_alloc(struct imx_ele_buf *ele_buf, const uint8_t *buf,
			     size_t size);

/*
 * Free buffer allocated memory
 *
 * @ele_buf:  Buffer to free
 */
void imx_ele_buf_free(struct imx_ele_buf *ele_buf);

/*
 * Copy data from ele_buf to data
 *
 * @ele_buf: Buffer from data to be copied
 * @buf: Buffer to which data to be copied
 * @size: Size of buf
 */
TEE_Result imx_ele_buf_copy(struct imx_ele_buf *ele_buf, uint8_t *buf,
			    size_t size);

#endif /* __MEMUTILS_H__ */
