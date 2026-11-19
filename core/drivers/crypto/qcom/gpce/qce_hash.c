// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Implementation of the Qualcomm Crypto Engine hash driver.
 */
#include <assert.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt_hash.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <stdlib.h>
#include <stdlib_ext.h>
#include <string.h>
#include <trace.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <utee_defines.h>

#include "ce_bam.h"
#include "hash.h"

struct qce_hash_ctx {
	struct crypto_hash_ctx hash_ctx;
	struct qce_hash_state *state;
};

static const struct crypto_hash_ops qce_hash_ops;
static struct qce_hash_ctx *to_qce_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &qce_hash_ops);

	return container_of(ctx, struct qce_hash_ctx, hash_ctx);
}

static void qce_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct qce_hash_ctx *qce_ctx = NULL;
	struct qce_hash_state *state = NULL;
	TEE_Result ret = TEE_SUCCESS;

	qce_ctx = to_qce_hash_ctx(ctx);
	state = qce_ctx->state;
	if (state->ctx) {
		ret = sha_cmn_ce_cleanup(state);
		if (ret)
			EMSG("QCE hash context cleanup failed: %#"PRIx32, ret);
	}
	free_wipe(state);
	free_wipe(qce_ctx);
}

static TEE_Result qce_hash_init(struct crypto_hash_ctx *ctx)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	qce_ctx = to_qce_hash_ctx(ctx);
	return sha_cmn_ce_init(qce_ctx->state);
}

static TEE_Result qce_hash_update(struct crypto_hash_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	if (!data && len)
		return TEE_ERROR_BAD_PARAMETERS;

	qce_ctx = to_qce_hash_ctx(ctx);
	return sha_cmn_ce_update(qce_ctx->state, data, len);
}

static TEE_Result qce_hash_final(struct crypto_hash_ctx *ctx,
				 uint8_t *digest, size_t len)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	if (!digest)
		return TEE_ERROR_BAD_PARAMETERS;
	if (len < TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	qce_ctx = to_qce_hash_ctx(ctx);
	return sha_cmn_ce_final(qce_ctx->state, digest, len);
}

static void qce_hash_copy_state(struct crypto_hash_ctx *dst,
				struct crypto_hash_ctx *src)
{
	struct qce_hash_ctx *dst_ctx = NULL;
	struct qce_hash_ctx *src_ctx = NULL;
	struct qce_hash_state *dst_state = NULL;
	struct qce_hash_state *src_state = NULL;
	struct qce_hash_state new_state = { };
	struct ce_sha_ctx *new_inner_ctx = NULL;
	struct blk_buf *new_iblk_h = NULL;
	TEE_Result ret = TEE_ERROR_BAD_STATE;

	dst_ctx = to_qce_hash_ctx(dst);
	src_ctx = to_qce_hash_ctx(src);
	dst_state = dst_ctx->state;
	src_state = src_ctx->state;

	new_state = *src_state;
	new_state.ctx = NULL;
	if (src_state->ctx) {
		new_state.ctx = calloc(1, src_state->ctx_sz);
		if (!new_state.ctx) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		ret = sha_cmn_ce_copy(&new_state, src_state);
		if (ret)
			goto out;

		ret = qce_hash_get_sha_ctx(&new_state, &new_inner_ctx);
		if (ret)
			goto out;
		new_iblk_h = new_inner_ctx->iblk_h;
		if (new_iblk_h) {
			ret = util_blk_buf_set_ctx(new_iblk_h, dst_state);
			if (ret)
				goto out;
		}
	}

	if (dst_state->ctx) {
		ret = sha_cmn_ce_cleanup(dst_state);
		if (ret)
			goto out;
	}
	/* Publish cloned state after releasing old resources. */
	*dst_state = new_state;
	ret = TEE_SUCCESS;
out:
	if (ret && new_state.ctx) {
		(void)sha_cmn_ce_cleanup(&new_state);
		free_wipe(new_state.ctx);
	}
	if (ret)
		panic("QCE hash state copy failed");
}

static const struct crypto_hash_ops qce_hash_ops = {
	.init = qce_hash_init,
	.update = qce_hash_update,
	.final = qce_hash_final,
	.free_ctx = qce_hash_free_ctx,
	.copy_state = qce_hash_copy_state,
};

static TEE_Result qce_hash_alloc_ctx(struct crypto_hash_ctx **ctx,
				     uint32_t algo)
{
	struct qce_hash_ctx *qce_ctx = NULL;
	struct qce_hash_state *state = NULL;

	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;
	*ctx = NULL;

	if (algo != TEE_ALG_SHA256)
		return TEE_ERROR_NOT_IMPLEMENTED;

	qce_ctx = calloc(1, sizeof(*qce_ctx));
	if (!qce_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	state = calloc(1, sizeof(*state));
	if (!state) {
		free(qce_ctx);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	qce_ctx->state = state;
	qce_ctx->hash_ctx.ops = &qce_hash_ops;
	*ctx = &qce_ctx->hash_ctx;

	return TEE_SUCCESS;
}

static TEE_Result qce_hash_driver_init(void)
{
	TEE_Result res = TEE_SUCCESS;

	res = ce_bam_init();
	if (res) {
		EMSG("QCE hash: failed to initialize BAM: %#"PRIx32, res);
		return res;
	}

	res = drvcrypt_register_hash(qce_hash_alloc_ctx);

	if (res)
		EMSG("QCE hash: drvcrypt_register_hash failed: %#"PRIx32, res);

	return res;
}

driver_init(qce_hash_driver_init);
