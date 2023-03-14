// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2025 NXP
 */
#include <io.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <memutils.h>

static void imx_ele_buf_cache_op(enum utee_cache_operation op,
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

	ele_buf->data = alloc_cache_aligned(size);
	if (!ele_buf->data) {
		EMSG("buffer allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ele_buf->paddr = virt_to_phys(ele_buf->data);
	if (!ele_buf->paddr) {
		free(ele_buf->data);
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
		free(ele_buf->data);
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
