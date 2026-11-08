// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Implementation of common GPCE hash operations.
 */

#include <kernel/mutex.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>

#include "ce_hwio.h"
#include "hash.h"

static const uint32_t sha256_initial_state[] = {
	TEE_U32_TO_BIG_ENDIAN(UINT32_C(0x6a09e667)),
	TEE_U32_TO_BIG_ENDIAN(UINT32_C(0xbb67ae85)),
	TEE_U32_TO_BIG_ENDIAN(UINT32_C(0x3c6ef372)),
	TEE_U32_TO_BIG_ENDIAN(UINT32_C(0xa54ff53a)),
	TEE_U32_TO_BIG_ENDIAN(UINT32_C(0x510e527f)),
	TEE_U32_TO_BIG_ENDIAN(UINT32_C(0x9b05688c)),
	TEE_U32_TO_BIG_ENDIAN(UINT32_C(0x1f83d9ab)),
	TEE_U32_TO_BIG_ENDIAN(UINT32_C(0x5be0cd19)),
};

static TEE_Result sha_cmn_hwio_process_din(struct qce_hash_state *me,
					   const uint8_t *buf,
					   size_t buf_sz, bool first,
					   bool last)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_ERROR_BAD_STATE;
	size_t seg_sz = 0;

	if (qce_hash_get_sha_ctx(me, &c) != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;
	mutex_lock(&me->dev->mutex);

	/* Set CE Context */
	seg_sz = ROUNDUP(buf_sz, QCE_HW_BLOCK_SIZE);
	ret = ce_hwio_set_ce_ctx(me, buf_sz, seg_sz, first, last);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Transfer data to CE */
	ret = ce_hwio_xfer_data(me, buf, seg_sz);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Get CE Context */
	ret = ce_hwio_get_ce_ctx(me);

out:
	mutex_unlock(&me->dev->mutex);
	return ret;
}

TEE_Result sha_cmn_ce_update(struct qce_hash_state *me, const uint8_t *msg,
			     size_t msg_sz)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (qce_hash_get_sha_ctx(me, &c) != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;
	if (!msg && msg_sz)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!msg_sz)
		return TEE_SUCCESS;

	if (c->block_len) {
		size_t count = QCE_SHA_BLOCK_SIZE - c->block_len;

		if (count > msg_sz)
			count = msg_sz;
		memcpy(c->block + c->block_len, msg, count);
		c->block_len += count;
		msg += count;
		msg_sz -= count;
		if (!msg_sz)
			return TEE_SUCCESS;

		if (c->block_len != QCE_SHA_BLOCK_SIZE)
			return TEE_ERROR_BAD_STATE;

		ret = sha_cmn_hwio_process_din(me, c->block, c->block_len,
					       c->first, false);
		if (ret != TEE_SUCCESS)
			return ret;
		c->block_len = 0;
		c->first = false;
	}

	if (msg_sz > QCE_SHA_BLOCK_SIZE) {
		size_t xfer_sz = msg_sz - (msg_sz % QCE_SHA_BLOCK_SIZE);

		if (xfer_sz == msg_sz)
			xfer_sz -= QCE_SHA_BLOCK_SIZE;
		ret = sha_cmn_hwio_process_din(me, msg, xfer_sz, c->first,
					       false);
		if (ret != TEE_SUCCESS)
			return ret;
		c->first = false;
		msg += xfer_sz;
		msg_sz -= xfer_sz;
	}

	memcpy(c->block, msg, msg_sz);
	c->block_len = msg_sz;

	return TEE_SUCCESS;
}

TEE_Result sha_cmn_ce_final(struct qce_hash_state *me, uint8_t *md)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (qce_hash_get_sha_ctx(me, &c) != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;

	memzero_explicit(c->block + c->block_len,
			 QCE_SHA_BLOCK_SIZE - c->block_len);
	ret = sha_cmn_hwio_process_din(me, c->block, c->block_len,
				       c->first, true);
	if (ret != TEE_SUCCESS)
		return ret;
	c->block_len = 0;
	c->first = false;

	return ce_hal_get_auth_iv(c->ce_ctx, md, TEE_SHA256_HASH_SIZE);
}

TEE_Result sha_cmn_ce_cleanup(struct qce_hash_state *me)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (qce_hash_get_sha_ctx(me, &c) != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;

	if (c->ce_ctx) {
		ret = ce_hal_free(c->ce_ctx);
		if (ret != TEE_SUCCESS)
			return ret;
	}
	memzero_explicit(me->ctx, sizeof(struct ce_sha_ctx));
	free(me->ctx);
	me->ctx_sz = 0;

	return TEE_SUCCESS;
}

static TEE_Result sha_cmn_init_iv(struct ce_sha_ctx *c)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(sha256_initial_state); n++) {
		ret = ce_hal_set_auth_iv(c->ce_ctx, n, sha256_initial_state[n]);
		if (ret != TEE_SUCCESS)
			return ret;
	}

	return TEE_SUCCESS;
}

TEE_Result sha_cmn_ce_init(struct qce_hash_state *me)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (HASH_IS_CTX_NULL(me) || !me->dev)
		return TEE_ERROR_BAD_STATE;

	if (!me->ctx || me->ctx_sz != sizeof(struct ce_sha_ctx)) {
		free(me->ctx);
		me->ctx = NULL;
		me->ctx_sz = 0;
		me->ctx = calloc(1, sizeof(struct ce_sha_ctx));
		if (!me->ctx)
			return TEE_ERROR_OUT_OF_MEMORY;
		me->ctx_sz = sizeof(struct ce_sha_ctx);
	} else {
		c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx);
		if (c->ce_ctx) {
			ret = ce_hal_free(c->ce_ctx);
			if (ret != TEE_SUCCESS)
				return ret;
		}
		memzero_explicit(c, sizeof(*c));
	}

	c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx);
	c->first = true;
	c->ce_ctx = ce_hal_new();
	if (!c->ce_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = ce_hal_init(c->ce_ctx, true);
	if (ret != TEE_SUCCESS)
		return ret;

	return sha_cmn_init_iv(c);
}

TEE_Result sha_cmn_ce_copy(struct qce_hash_state *dest,
			   struct qce_hash_state *src)
{
	struct ce_sha_ctx *src_inner_ctx = NULL;
	struct ce_sha_ctx *dest_inner_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (qce_hash_get_sha_ctx(dest, &dest_inner_ctx) != TEE_SUCCESS ||
	    qce_hash_get_sha_ctx(src, &src_inner_ctx) != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;

	if (dest_inner_ctx->ce_ctx) {
		ret = ce_hal_free(dest_inner_ctx->ce_ctx);
		if (ret != TEE_SUCCESS)
			return ret;
	}

	*dest_inner_ctx = *src_inner_ctx;
	dest_inner_ctx->ce_ctx = NULL;

	if (src_inner_ctx->ce_ctx) {
		dest_inner_ctx->ce_ctx =
			calloc(1, sizeof(*src_inner_ctx->ce_ctx));
		if (!dest_inner_ctx->ce_ctx)
			return TEE_ERROR_OUT_OF_MEMORY;
		ret = ce_hal_copy(dest_inner_ctx->ce_ctx,
				  src_inner_ctx->ce_ctx);
		if (ret != TEE_SUCCESS)
			return ret;
	}
	return TEE_SUCCESS;
}
