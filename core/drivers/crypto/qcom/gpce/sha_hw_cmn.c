// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Implementation of common GPCE hash operations.
 */

#include <kernel/mutex.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib_ext.h>
#include <trace.h>

#include "ce_bam.h"
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

static const uint8_t sha256_empty_digest[TEE_SHA256_HASH_SIZE] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

static struct mutex qce_mutex = MUTEX_INITIALIZER;

static TEE_Result sha_cmn_bam_xfer_payload(void *ctx, const uint8_t *buf,
					   size_t buf_sz, bool first, bool last)
{
	struct qce_hash_state *me = ctx;
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_ERROR_BAD_STATE;

	ret = qce_hash_get_sha_ctx(me, &c);
	if (ret || !c->ce_ctx)
		return TEE_ERROR_BAD_STATE;

	mutex_lock(&qce_mutex);
	do {
		size_t xfer_sz = 0;
		bool xfer_last = false;

		ret = ce_bam_get_xfer_size(buf, buf_sz, &xfer_sz);
		if (ret)
			break;
		xfer_last = last && xfer_sz == buf_sz;

		ret = ce_bam_set_ce_ctx(c, xfer_sz, xfer_sz, first, xfer_last);
		if (ret)
			break;
		ret = ce_bam_xfer_data(buf, xfer_sz);
		if (ret)
			break;
		ret = ce_bam_get_ce_ctx(c);
		if (ret)
			break;

		buf += xfer_sz;
		buf_sz -= xfer_sz;
		first = false;
	} while (buf_sz);
	mutex_unlock(&qce_mutex);
	return ret;
}

TEE_Result sha_cmn_ce_update(struct qce_hash_state *me, const uint8_t *msg,
			     size_t msg_sz)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	ret = qce_hash_get_sha_ctx(me, &c);
	if (ret)
		return TEE_ERROR_BAD_STATE;

	return util_blk_buf_out(c->iblk_h, msg, msg_sz);
}

TEE_Result sha_cmn_ce_final(struct qce_hash_state *me, uint8_t *md,
			    size_t md_sz)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	ret = qce_hash_get_sha_ctx(me, &c);
	if (ret)
		return TEE_ERROR_BAD_STATE;

	/* Limit digest size to max defined by hash algorithm */
	if (md_sz > TEE_SHA256_HASH_SIZE)
		md_sz = TEE_SHA256_HASH_SIZE;

	if (!util_blk_buf_size(c->iblk_h)) {
		memcpy(md, sha256_empty_digest, md_sz);
		return TEE_SUCCESS;
	}

	ret = util_blk_buf_out(c->iblk_h, NULL, 0);
	if (ret)
		return ret;

	return ce_hal_get_auth_iv(c->ce_ctx, md, md_sz);
}

static TEE_Result sha_cmn_release_resources(struct ce_sha_ctx *c)
{
	TEE_Result cleanup_ret = TEE_SUCCESS;
	TEE_Result ret = TEE_SUCCESS;

	if (c->iblk_h) {
		ret = util_blk_buf_free(c->iblk_h);
		if (ret)
			cleanup_ret = ret;
	}
	c->iblk_h = NULL;

	if (c->ce_ctx) {
		ret = ce_hal_free(c->ce_ctx);
		if (ret && !cleanup_ret)
			cleanup_ret = ret;
	}
	c->ce_ctx = NULL;

	return cleanup_ret;
}

TEE_Result sha_cmn_ce_cleanup(struct qce_hash_state *me)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	ret = qce_hash_get_sha_ctx(me, &c);
	if (ret)
		return TEE_ERROR_BAD_STATE;
	ret = sha_cmn_release_resources(c);
	free_wipe(me->ctx);
	me->ctx = NULL;
	me->ctx_sz = 0;

	return ret;
}

static TEE_Result sha_cmn_init_iv(struct ce_sha_ctx *c)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(sha256_initial_state); n++) {
		ret = ce_hal_set_auth_iv(c->ce_ctx, n, sha256_initial_state[n]);
		if (ret)
			return ret;
	}

	return TEE_SUCCESS;
}

TEE_Result sha_cmn_ce_init(struct qce_hash_state *me)
{
	struct ce_sha_ctx *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!me)
		return TEE_ERROR_BAD_STATE;
	mutex_lock(&qce_mutex);
	if (!me->ctx || me->ctx_sz != sizeof(struct ce_sha_ctx)) {
		free_wipe(me->ctx);
		me->ctx = NULL;
		me->ctx_sz = 0;
		me->ctx = calloc(1, sizeof(struct ce_sha_ctx));
		if (!me->ctx) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		me->ctx_sz = sizeof(struct ce_sha_ctx);
	} else {
		c = me->ctx;
		ret = sha_cmn_release_resources(c);
		memset(c, 0, sizeof(*c));
		if (ret)
			goto out;
	}

	c = me->ctx;
	c->ce_ctx = ce_hal_new();
	if (!c->ce_ctx) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ret = ce_hal_init(c->ce_ctx, true);
	if (ret)
		goto err;

	ret = sha_cmn_init_iv(c);
	if (ret)
		goto err;

	c->iblk_h = util_blk_buf_new();
	if (!c->iblk_h) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ret = util_blk_buf_init(c->iblk_h, QCE_SHA_BLOCK_SIZE, false,
				sha_cmn_bam_xfer_payload, me);
	if (ret)
		goto err;

	ret = TEE_SUCCESS;
	goto out;
err:
	sha_cmn_release_resources(c);
out:
	mutex_unlock(&qce_mutex);
	return ret;
}

TEE_Result sha_cmn_ce_copy(struct qce_hash_state *dest,
			   struct qce_hash_state *src)
{
	struct ce_sha_ctx *src_inner_ctx = NULL;
	struct ce_sha_ctx *dest_inner_ctx = NULL;
	struct ce_sha_ctx new_inner_ctx = { };
	TEE_Result ret = TEE_SUCCESS;

	if (qce_hash_get_sha_ctx(dest, &dest_inner_ctx) != TEE_SUCCESS ||
	    qce_hash_get_sha_ctx(src, &src_inner_ctx) != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;
	if (src_inner_ctx->iblk_h) {
		new_inner_ctx.iblk_h = util_blk_buf_new();
		if (!new_inner_ctx.iblk_h)
			return TEE_ERROR_OUT_OF_MEMORY;

		ret = util_blk_buf_copy(new_inner_ctx.iblk_h,
					src_inner_ctx->iblk_h, dest);
		if (ret)
			goto err;
	}

	if (src_inner_ctx->ce_ctx) {
		new_inner_ctx.ce_ctx = ce_hal_new();
		if (!new_inner_ctx.ce_ctx) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		ret = ce_hal_copy(new_inner_ctx.ce_ctx, src_inner_ctx->ce_ctx);
		if (ret)
			goto err;
	}

	ret = sha_cmn_release_resources(dest_inner_ctx);
	if (ret)
		goto err;
	/* Transfer ownership of the independently cloned resources to dest. */
	*dest_inner_ctx = new_inner_ctx;
	return TEE_SUCCESS;
err:
	sha_cmn_release_resources(&new_inner_ctx);
	return ret;
}
