// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * Implementation of common GPCE hash operations.
 */

#include <kernel/mutex.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>

#include "ce_hwio.h"
#include "hash.h"

static TEE_Result SHA_CMN_HWIO_process_din(struct qce_hash_state *me,
					   const uint8_t *buf,
					   size_t buf_sz, bool first,
					   bool last)
{
	TEE_Result ret = TEE_ERROR_BAD_STATE;
	size_t seg_sz = 0;

	if (HASH_IS_CTX_NULL(me))
		return TEE_ERROR_BAD_STATE;
	if (!me->dev)
		return TEE_ERROR_BAD_STATE;
	mutex_lock(&me->dev->mutex);

	/* Set CE Context */
	if (HASH_IS_CTX_NULL(me) || !me->ctx ||
	    me->ctx_sz != sizeof(struct ce_sha_ctx_s))
		goto out;

	seg_sz = ROUNDUP(buf_sz, CE_HW_BLOCK_SIZE);
	ret = CE_HWIO_set_ce_ctx(me, buf_sz, seg_sz, first, last);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Transfer data to CE */
	ret = CE_HWIO_xfer_data(me, buf, seg_sz);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Get CE Context */
	ret = CE_HWIO_get_ce_ctx(me);

out:
	mutex_unlock(&me->dev->mutex);
	return ret;
}

TEE_Result SHA_CMN_CE_update(struct qce_hash_state *me, const uint8_t *msg,
			     size_t msg_sz)
{
	struct ce_sha_ctx_s *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (HASH_IS_CTX_NULL(me) || !me->ctx ||
	    me->ctx_sz != sizeof(struct ce_sha_ctx_s))
		return TEE_ERROR_BAD_STATE;
	if (!msg && msg_sz)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!msg_sz)
		return TEE_SUCCESS;

	c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
	if (c->block_len) {
		size_t count = CE_MAX_BLOCK_SIZE - c->block_len;

		if (count > msg_sz)
			count = msg_sz;
		memcpy(c->block + c->block_len, msg, count);
		c->block_len += count;
		msg += count;
		msg_sz -= count;
		if (!msg_sz)
			return TEE_SUCCESS;

		if (c->block_len != CE_MAX_BLOCK_SIZE)
			return TEE_ERROR_BAD_STATE;

		ret = SHA_CMN_HWIO_process_din(me, c->block, c->block_len,
					       c->first, false);
		if (ret != TEE_SUCCESS)
			return ret;
		c->block_len = 0;
		c->first = false;
	}

	if (msg_sz > CE_MAX_BLOCK_SIZE) {
		size_t xfer_sz = msg_sz - (msg_sz % CE_MAX_BLOCK_SIZE);

		if (xfer_sz == msg_sz)
			xfer_sz -= CE_MAX_BLOCK_SIZE;
		ret = SHA_CMN_HWIO_process_din(me, msg, xfer_sz, c->first,
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

TEE_Result SHA_CMN_CE_final(struct qce_hash_state *me, uint8_t *md,
			    size_t md_sz)
{
	struct ce_sha_ctx_s *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (HASH_IS_CTX_NULL(me) || !me->ctx ||
	    me->ctx_sz != sizeof(struct ce_sha_ctx_s))
		return TEE_ERROR_BAD_STATE;

	c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
	memzero_explicit(c->block + c->block_len,
			 CE_MAX_BLOCK_SIZE - c->block_len);
	ret = SHA_CMN_HWIO_process_din(me, c->block, c->block_len,
				       c->first, true);
	if (ret != TEE_SUCCESS)
		return ret;
	c->block_len = 0;
	c->first = false;

	if (md_sz > me->md_sz)
		md_sz = me->md_sz;

	return CE_HAL_get_auth_iv(c->ce_ctx, md, md_sz);
}

TEE_Result SHA_CMN_CE_reset(struct qce_hash_state *me)
{
	if (!HASH_IS_CTX_NULL(me) && me->ctx &&
	    me->ctx_sz == sizeof(struct ce_sha_ctx_s)) {
		struct ce_sha_ctx_s *c =
			HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
		TEE_Result ret = TEE_SUCCESS;

		memzero_explicit(c->block, sizeof(c->block));
		c->block_len = 0;
		c->first = true;
		if (c->ce_ctx) {
			ret = CE_HAL_reset(c->ce_ctx);
			if (ret != TEE_SUCCESS)
				return ret;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result SHA_CMN_CE_cleanup(struct qce_hash_state *me)
{
	struct ce_sha_ctx_s *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (HASH_IS_CTX_NULL(me) || !me->ctx ||
	    me->ctx_sz != sizeof(struct ce_sha_ctx_s))
		return TEE_ERROR_BAD_STATE;

	c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
	if (c->ce_ctx) {
		ret = CE_HAL_free(c->ce_ctx);
		if (ret != TEE_SUCCESS)
			return ret;
	}
	memzero_explicit(me->ctx, sizeof(struct ce_sha_ctx_s));
	free(me->ctx);
	me->ctx_sz = 0;

	return TEE_SUCCESS;
}

static TEE_Result SHA_CMN_init_iv(struct ce_sha_ctx_s *c)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = CE_HAL_set_auth_iv(c->ce_ctx, 0, INIT_DATA_CE_SHA1_h0);
	if (ret != TEE_SUCCESS)
		return ret;
	ret = CE_HAL_set_auth_iv(c->ce_ctx, 1, INIT_DATA_CE_SHA1_h1);
	if (ret != TEE_SUCCESS)
		return ret;
	ret = CE_HAL_set_auth_iv(c->ce_ctx, 2, INIT_DATA_CE_SHA1_h2);
	if (ret != TEE_SUCCESS)
		return ret;
	ret = CE_HAL_set_auth_iv(c->ce_ctx, 3, INIT_DATA_CE_SHA1_h3);
	if (ret != TEE_SUCCESS)
		return ret;

	return CE_HAL_set_auth_iv(c->ce_ctx, 4, INIT_DATA_CE_SHA1_h4);
}

TEE_Result SHA_CMN_CE_init(struct qce_hash_state *me)
{
	struct ce_sha_ctx_s *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (HASH_IS_CTX_NULL(me) || !me->dev)
		return TEE_ERROR_BAD_STATE;

	me->md_sz = SHA1_DIGEST_SIZE;
	if (!me->ctx || me->ctx_sz != sizeof(struct ce_sha_ctx_s)) {
		free(me->ctx);
		me->ctx = NULL;
		me->ctx_sz = 0;
		me->ctx = calloc(1, sizeof(struct ce_sha_ctx_s));
		if (!me->ctx)
			return TEE_ERROR_OUT_OF_MEMORY;
		me->ctx_sz = sizeof(struct ce_sha_ctx_s);
	} else {
		c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
		if (c->ce_ctx) {
			ret = CE_HAL_free(c->ce_ctx);
			if (ret != TEE_SUCCESS)
				return ret;
		}
		memzero_explicit(c, sizeof(*c));
	}

	c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
	c->first = true;
	c->ce_ctx = CE_HAL_new();
	if (!c->ce_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = CE_HAL_init(c->ce_ctx, true);
	if (ret != TEE_SUCCESS)
		return ret;

	return SHA_CMN_init_iv(c);
}

TEE_Result SHA_CMN_CE_copy(struct qce_hash_state *dest,
			   struct qce_hash_state *src)
{
	struct ce_sha_ctx_s *src_inner_ctx = NULL;
	struct ce_sha_ctx_s *dest_inner_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (HASH_IS_CTX_NULL(dest) || HASH_IS_CTX_NULL(src) ||
	    !dest->ctx || !src->ctx ||
	    dest->ctx_sz != sizeof(struct ce_sha_ctx_s) ||
	    src->ctx_sz != sizeof(struct ce_sha_ctx_s))
		return TEE_ERROR_BAD_STATE;

	src_inner_ctx = HASH_GET_DIGEST_CTX(src, struct ce_sha_ctx_s);
	dest_inner_ctx = HASH_GET_DIGEST_CTX(dest, struct ce_sha_ctx_s);
	if (dest_inner_ctx->ce_ctx) {
		ret = CE_HAL_free(dest_inner_ctx->ce_ctx);
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
		ret = CE_HAL_copy(dest_inner_ctx->ce_ctx,
				  src_inner_ctx->ce_ctx);
		if (ret != TEE_SUCCESS)
			return ret;
	}
	return TEE_SUCCESS;
}
