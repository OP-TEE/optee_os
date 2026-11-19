// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Block buffer helpers for Crypto Engine transfers.
 */

#include <stdlib.h>
#include <stdlib_ext.h>
#include <string.h>
#include <util.h>

#include "util_blkbuf.h"

struct blk_buf {
	uint8_t *blk_buf; /* Input retained until it can be transferred */
	size_t buf_sz; /* Allocated size of @blk_buf */
	size_t blk_sz; /* Hash block size for each transfer */
	size_t sz; /* Number of bytes retained in @blk_buf */
	bool first; /* True until the first successful callback transfer */
	blk_buf_out_cb out_cb; /* Output callback */
	void *ctx; /* Caller context passed to @out_cb */
};

struct blk_buf *util_blk_buf_new(void)
{
	return calloc(1, sizeof(struct blk_buf));
}

TEE_Result util_blk_buf_reset(struct blk_buf *h)
{
	if (!h)
		return TEE_ERROR_BAD_PARAMETERS;

	h->sz = 0;
	h->first = true;
	if (h->blk_buf)
		memset(h->blk_buf, 0, h->buf_sz);

	return TEE_SUCCESS;
}

TEE_Result util_blk_buf_free(struct blk_buf *h)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!h)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = util_blk_buf_reset(h);
	if (ret)
		return ret;

	free_wipe(h->blk_buf);
	free_wipe(h);

	return TEE_SUCCESS;
}

size_t util_blk_buf_size(struct blk_buf *h)
{
	return h ? h->sz : 0;
}

TEE_Result util_blk_buf_init(struct blk_buf *h, size_t blk_sz,
			     bool min_hold_sz_req, blk_buf_out_cb out_cb,
			     void *ctx)
{
	size_t min_last_update_sz = 0;

	if (!h || !blk_sz || !out_cb)
		return TEE_ERROR_BAD_PARAMETERS;

	min_last_update_sz = min_hold_sz_req ? blk_sz + 1 : 1;
	free_wipe(h->blk_buf);
	h->blk_buf = NULL;
	h->buf_sz = 0;

	h->buf_sz = ((blk_sz + min_last_update_sz) / blk_sz) * blk_sz;
	h->blk_buf = calloc(1, h->buf_sz);
	if (!h->blk_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	h->blk_sz = blk_sz;
	h->out_cb = out_cb;
	h->ctx = ctx;
	h->first = true;

	return TEE_SUCCESS;
}

TEE_Result util_blk_buf_set_ctx(struct blk_buf *h, void *ctx)
{
	if (!h)
		return TEE_ERROR_BAD_PARAMETERS;

	h->ctx = ctx;
	return TEE_SUCCESS;
}

static TEE_Result util_blk_buf_xfer(struct blk_buf *h,
				    const uint8_t *ibuf, size_t isz,
				     bool last)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = h->out_cb(h->ctx, ibuf, isz, h->first, last);
	if (!ret)
		h->first = false;

	return ret;
}

static size_t copy_to_blk_buf(struct blk_buf *h, const uint8_t *ibuf,
			      size_t isz)
{
	size_t copy_sz = MIN(h->buf_sz - h->sz, isz);

	memcpy(h->blk_buf + h->sz, ibuf, copy_sz);
	h->sz += copy_sz;
	return copy_sz;
}

TEE_Result util_blk_buf_out(struct blk_buf *h, const uint8_t *ibuf,
			    size_t isz)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t bbuf_xfer_sz = 0;
	size_t to_copy = 0;
	size_t to_push = 0;

	if (!h || !h->blk_buf || !h->blk_sz || !h->out_cb || (!ibuf && isz))
		return TEE_ERROR_BAD_PARAMETERS;

	/* A NULL input flushes the remaining data as the final transfer. */
	if (!ibuf) {
		memset(h->blk_buf + h->sz, 0, h->buf_sz - h->sz);
		ret = util_blk_buf_xfer(h, h->blk_buf, h->sz, true);
		if (!ret)
			h->sz = 0;
		return ret;
	}
	if (!isz)
		return TEE_SUCCESS;

	if (h->sz) {
		to_copy = copy_to_blk_buf(h, ibuf, isz);
		isz -= to_copy;
		ibuf += to_copy;
		if (!isz)
			return TEE_SUCCESS;

		bbuf_xfer_sz = MIN(ROUNDUP(isz, h->blk_sz), h->buf_sz);
		ret = util_blk_buf_xfer(h, h->blk_buf, bbuf_xfer_sz, false);
		if (ret)
			return ret;

		memmove(h->blk_buf, h->blk_buf + bbuf_xfer_sz,
			h->sz - bbuf_xfer_sz);
		h->sz -= bbuf_xfer_sz;
	}

	if (isz > h->buf_sz - h->sz) {
		to_push = ROUNDUP(isz, h->blk_sz) - h->buf_sz;
		ret = util_blk_buf_xfer(h, ibuf, to_push, false);
		if (ret)
			return ret;
		ibuf += to_push;
		isz -= to_push;
	}

	copy_to_blk_buf(h, ibuf, isz);
	return TEE_SUCCESS;
}

TEE_Result util_blk_buf_copy(struct blk_buf *dest_handle,
			     struct blk_buf *src_handle, void *ctx)
{
	uint8_t *blk_buf = NULL;

	if (!dest_handle || !src_handle || !src_handle->blk_buf ||
	    !src_handle->blk_sz || !src_handle->out_cb)
		return TEE_ERROR_BAD_PARAMETERS;

	blk_buf = calloc(1, src_handle->buf_sz);
	if (!blk_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(blk_buf, src_handle->blk_buf, src_handle->buf_sz);
	memcpy(dest_handle, src_handle, sizeof(*dest_handle));
	dest_handle->blk_buf = blk_buf;
	dest_handle->ctx = ctx;

	return TEE_SUCCESS;
}
