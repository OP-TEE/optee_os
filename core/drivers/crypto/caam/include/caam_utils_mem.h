/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Memory management utilities.
 *         Primitive to allocate, free memory.
 */

#ifndef __CAAM_UTILS_MEM_H__
#define __CAAM_UTILS_MEM_H__

#include <caam_common.h>

/*
 * Allocate normal memory.
 * Depending on the MEM_TYPE_DEFAULT value initialized it to 0's.
 *
 * @size  size in bytes of the memory to allocate
 */
void *caam_alloc(size_t size);

/*
 * Allocate memory aligned with a cache line.
 * Depending on the MEM_TYPE_DEFAULT value initialized it to 0's.
 *
 * @size  size in bytes of the memory to allocate
 */
void *caam_alloc_align(size_t size);

/*
 * Free allocated memory
 *
 * @ptr  reference to the object to free
 */
void caam_free(void *ptr);

/*
 * Allocate Job descriptor.
 * Depending on the MEM_TYPE_DEFAULT value initialized it to 0's.
 *
 * @nbentries  Number of descriptor entries
 */
uint32_t *caam_alloc_desc(uint8_t nbentries);

/*
 * Free descriptor
 *
 * @ptr  Reference to the descriptor to free
 */
void caam_free_desc(uint32_t **ptr);

/*
 * Allocate internal driver buffer and initialize it with 0s
 *
 * @buf   [out] buffer allocated
 * @size  size in bytes of the memory to allocate
 */
enum CAAM_Status caam_alloc_buf(struct caambuf *buf, size_t size);

/*
 * Allocate internal driver buffer aligned with a cache line
 *
 * @buf   [out] buffer allocated
 * @size  size in bytes of the memory to allocate
 */
enum CAAM_Status caam_alloc_align_buf(struct caambuf *buf, size_t size);

/*
 * Free internal driver buffer allocated memory
 *
 * @buf   Driver buffer to free
 */
void caam_free_buf(struct caambuf *buf);

/*
 * Free data of type struct sgtbuf
 *
 * @data    Data sgtbuf to free
 */
void caam_sgtbuf_free(struct caamsgtbuf *data);

/*
 * Allocate data of type struct sgtbuf
 *
 * @data    [out] Data sgtbuf allocated
 */
enum CAAM_Status caam_sgtbuf_alloc(struct caamsgtbuf *data);

/*
 * Re-Allocate a buffer if it's not aligned on a cache line and
 * if it's cacheable. If buffer is not cacheable no need to
 * reallocate.
 *
 * @orig  Buffer origin
 * @dst   [out] CAAM Buffer object with origin or reallocated buffer
 * @size  Size in bytes of the buffer
 *
 * Returns:
 * 0    if destination is the same as origin
 * 1    if reallocation of the buffer
 * (-1) if allocation error
 */
int caam_set_or_alloc_align_buf(void *orig, struct caambuf *dst, size_t size);

/*
 * Copy source data into the block buffer
 *
 * @block  [in/out] Block buffer information. Return buffer filled.
 * @src    Source to copy
 * @offset Source offset to start
 */
enum CAAM_Status caam_cpy_block_src(struct caamblock *block,
				    struct caambuf *src, size_t offset);

#endif /* __CAAM_UTILS_MEM_H__ */
