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
 * Allocate normal memory and initialize it to 0's.
 *
 * @size  size in bytes of the memory to allocate
 */
void *caam_calloc(size_t size);

/*
 * Allocate memory aligned with a cache line and initialize it to 0's.
 *
 * @size  size in bytes of the memory to allocate
 */
void *caam_calloc_align(size_t size);

/*
 * Free allocated memory
 *
 * @ptr  reference to the object to free
 */
void caam_free(void *ptr);

/*
 * Allocate Job descriptor and initialize it to 0's.
 *
 * @nbentries  Number of descriptor entries
 */
uint32_t *caam_calloc_desc(uint8_t nbentries);

/*
 * Free descriptor
 *
 * @ptr  Reference to the descriptor to free
 */
void caam_free_desc(uint32_t **ptr);

/*
 * Allocate internal driver buffer and initialize it with 0s.
 *
 * @buf   [out] buffer allocated
 * @size  size in bytes of the memory to allocate
 */
enum caam_status caam_calloc_buf(struct caambuf *buf, size_t size);

/*
 * Allocate internal driver buffer aligned with a cache line and initialize
 * if with 0's.
 *
 * @buf   [out] buffer allocated
 * @size  size in bytes of the memory to allocate
 */
enum caam_status caam_calloc_align_buf(struct caambuf *buf, size_t size);

/*
 * Allocate internal driver buffer aligned with a cache line.
 *
 * @buf   [out] buffer allocated
 * @size  size in bytes of the memory to allocate
 */
enum caam_status caam_alloc_align_buf(struct caambuf *buf, size_t size);

/*
 * Free internal driver buffer allocated memory
 *
 * @buf   Driver buffer to free
 */
void caam_free_buf(struct caambuf *buf);

/*
 * Free data of type struct caamsgtbuf
 *
 * @data    Data object to free
 */
void caam_sgtbuf_free(struct caamsgtbuf *data);

/*
 * Allocate data of type struct caamsgtbuf
 *
 * @data    [out] Data object allocated
 */
enum caam_status caam_sgtbuf_alloc(struct caamsgtbuf *data);

/*
 * Initialize struct caambuf with buffer reference, eventually
 * reallocating the buffer if not matching cache line alignment.
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
 * Copy source data into the block buffer. Allocate block buffer if
 * it's not defined.
 *
 * @block  [in/out] Block buffer information. Return buffer filled.
 * @src    Source to copy
 * @offset Source offset to start
 */
enum caam_status caam_cpy_block_src(struct caamblock *block,
				    struct caambuf *src, size_t offset);

/*
 * Return the number of Physical Areas used by the buffer @buf.
 * If @pabufs is not NULL, function fills it with the Physical Areas used
 * to map the buffer @buf.
 *
 * @buf         Data buffer to analyze
 * @pabufs[out] If not NULL, list the Physical Areas of the @buf
 *
 * Returns:
 * Number of physical area used
 * (-1) if error
 */
int caam_mem_get_pa_area(struct caambuf *buf, struct caambuf **pabufs);

/*
 * Return if the buffer @buf is cacheable or not
 *
 * @buf  Buffer address
 * @size Buffer size
 */
bool caam_mem_is_cached_buf(void *buf, size_t size);
#endif /* __CAAM_UTILS_MEM_H__ */
