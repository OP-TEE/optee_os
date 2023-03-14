// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2025 NXP
 */
#include <io.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <utils_mem.h>

/*
 * Allocate cache aligned memory of given size in bytes.
 * Size will also be rounded up to cachec line size.
 *
 * @size   Size in bytes to allocate
 */
static void *imx_ele_calloc_align(size_t size)
{
	void *ptr = NULL;
	size_t alloc_size = size;
	size_t cacheline_size = dcache_get_line_size();

	if (ROUNDUP_OVERFLOW(alloc_size, cacheline_size, &alloc_size))
		return NULL;

	ptr = memalign(cacheline_size, alloc_size);
	if (!ptr) {
		EMSG("alloc Error - NULL");
		return NULL;
	}

	memset(ptr, 0, alloc_size);

	return ptr;
}

/*
 * Free allocated area
 *
 * @ptr  area to free
 */
static void imx_ele_free(void *ptr)
{
	if (ptr)
		free(ptr);
}

void imx_ele_buf_cache_op(enum utee_cache_operation op,
			  struct imx_ele_buf *ele_buf)
{
	if (ele_buf && ele_buf->data)
		cache_operation(op, ele_buf->data, ele_buf->size);
}

TEE_Result imx_ele_buf_alloc(struct imx_ele_buf *ele_buf, const uint8_t *buf,
			     size_t size)
{
	if (!ele_buf || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	ele_buf->data = imx_ele_calloc_align(size);
	if (!ele_buf->data) {
		EMSG("buffer allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ele_buf->paddr = virt_to_phys(ele_buf->data);
	if (!ele_buf->paddr) {
		imx_ele_free(ele_buf->data);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	reg_pair_from_64((uint64_t)ele_buf->paddr, &ele_buf->paddr_msb,
			 &ele_buf->paddr_lsb);

	ele_buf->size = size;

	if (buf)
		memcpy(ele_buf->data, buf, size);

	imx_ele_buf_cache_op(TEE_CACHEFLUSH, ele_buf);

	return TEE_SUCCESS;
}

void imx_ele_buf_free(struct imx_ele_buf *ele_buf)
{
	if (ele_buf) {
		imx_ele_free(ele_buf->data);
		ele_buf->data = NULL;
		ele_buf->paddr = 0;
		ele_buf->size = 0;
	}
}

TEE_Result imx_ele_buf_copy(struct imx_ele_buf *ele_buf, uint8_t *buf,
			    size_t size)
{
	if (!ele_buf || !buf || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size < ele_buf->size)
		return TEE_ERROR_SHORT_BUFFER;

	imx_ele_buf_cache_op(TEE_CACHEINVALIDATE, ele_buf);
	memcpy(buf, ele_buf->data, ele_buf->size);

	return TEE_SUCCESS;
}
