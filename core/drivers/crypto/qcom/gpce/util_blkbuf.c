// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 * Implementation of block input buffering.
 */

#include <stdlib.h>
#include <string.h>
#include <util.h>

#include "util_blkbuf.h"

struct Blk_buf_s *util_blk_buf_new(void)
{
	return calloc(1, sizeof(struct Blk_buf_s));
}

TEE_Result util_blk_buf_reset(struct Blk_buf_s *h)
{
	struct Blk_buf_s *me = (struct Blk_buf_s *)h;

	if (!BLK_BUF_IS_CTX_VALID(me))
		return TEE_ERROR_BAD_PARAMETERS;
	me->sz = 0;
	me->first = true;
	if (me->blk_buf && me->buf_sz)
		memset(me->blk_buf, 0, me->buf_sz);

	return TEE_SUCCESS;
}

TEE_Result util_blk_buf_free(struct Blk_buf_s *h)
{
	struct Blk_buf_s *me = (struct Blk_buf_s *)h;
	TEE_Result ret = TEE_SUCCESS;

	ret = util_blk_buf_reset(h);
	if (ret != TEE_SUCCESS)
		return ret;
	if (me->blk_buf)
		free(me->blk_buf);
	memset(me, 0, sizeof(*me));
	free(me);

	return TEE_SUCCESS;
}

TEE_Result util_blk_buf_init(struct Blk_buf_s *h, size_t blk_sz,
			     blk_buf_out_op_cb out_cb, void *ctx)
{
	struct Blk_buf_s *me = (struct Blk_buf_s *)h;

	if (!BLK_BUF_IS_CTX_VALID(me))
		return TEE_ERROR_BAD_STATE;
	if (!out_cb || !blk_sz || blk_sz >= UINT16_MAX)
		return TEE_ERROR_BAD_PARAMETERS;
	if (me->blk_buf) {
		memset(me->blk_buf, 0, me->buf_sz);
		free(me->blk_buf);
	}

	me->blk_sz = (uint16_t)blk_sz;
	me->buf_sz = (uint16_t)blk_sz;
	me->blk_buf = calloc(1, me->buf_sz);
	if (!me->blk_buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	me->out_cb = out_cb;
	me->ctx = ctx;
	me->sz = 0;
	me->first = true;

	return TEE_SUCCESS;
}

static TEE_Result util_blk_buf_submit(struct Blk_buf_s *me,
				      const uint8_t *ibuf, size_t isz,
				      bool last)
{
	TEE_Result ret = me->out_cb(me->ctx, ibuf, isz, me->first, last);

	if (ret == TEE_SUCCESS)
		me->first = false;
	return ret;
}

TEE_Result util_blk_buf_out(struct Blk_buf_s *h,
			    const uint8_t *ibuf, size_t isz)
{
	struct Blk_buf_s *me = (struct Blk_buf_s *)h;
	TEE_Result ret = TEE_SUCCESS;

	if (!BLK_BUF_IS_CTX_VALID(me) || !me->blk_buf || !me->out_cb)
		return TEE_ERROR_BAD_STATE;
	if (!ibuf) {
		memset(me->blk_buf + me->sz, 0, me->buf_sz - me->sz);
		ret = util_blk_buf_submit(me, me->blk_buf, me->sz, true);
		if (ret == TEE_SUCCESS)
			me->sz = 0;
		return ret;
	}
	if (!isz)
		return TEE_SUCCESS;

	if (me->sz) {
		size_t capacity = (size_t)me->buf_sz - me->sz;
		size_t copied = isz;

		if (copied > capacity)
			copied = capacity;
		memcpy(me->blk_buf + me->sz, ibuf, copied);

		me->sz += copied;
		ibuf += copied;
		isz -= copied;
		if (!isz)
			return TEE_SUCCESS;
		ret = util_blk_buf_submit(me, me->blk_buf, me->sz, false);
		if (ret != TEE_SUCCESS)
			return ret;
		me->sz = 0;
	}

	if (isz > me->blk_sz) {
		size_t xfer_sz = isz - (isz % me->blk_sz);

		if (xfer_sz == isz)
			xfer_sz -= me->blk_sz;
		ret = util_blk_buf_submit(me, ibuf, xfer_sz, false);
		if (ret != TEE_SUCCESS)
			return ret;
		ibuf += xfer_sz;
		isz -= xfer_sz;
	}

	memcpy(me->blk_buf, ibuf, isz);
	me->sz = isz;
	return TEE_SUCCESS;
}

TEE_Result util_blk_buf_copy(struct Blk_buf_s *dest_handle,
			     struct Blk_buf_s *src_handle, void *ctx)
{
	struct Blk_buf_s *src = (struct Blk_buf_s *)src_handle;
	struct Blk_buf_s *dest = (struct Blk_buf_s *)dest_handle;

	if (!BLK_BUF_IS_CTX_VALID(src) || !BLK_BUF_IS_CTX_VALID(dest))
		return TEE_ERROR_BAD_STATE;
	memcpy(dest, src, sizeof(*dest));
	dest->ctx = ctx;
	dest->blk_buf = NULL;
	if (!src->blk_buf)
		return TEE_SUCCESS;

	dest->blk_buf = calloc(1, dest->buf_sz);
	if (!dest->blk_buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(dest->blk_buf, src->blk_buf, src->buf_sz);

	return TEE_SUCCESS;
}
