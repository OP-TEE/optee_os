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
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdlib.h>
#include <stdlib_ext.h>
#include <string.h>
#include <trace.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <utee_defines.h>

#include "ce_hwio.h"
#include "hash.h"

struct qce_hash_ctx {
	struct crypto_hash_ctx hash_ctx;
	struct qce_hash_state *state;
};

static const struct crypto_hash_ops qce_hash_ops;
static struct qce_dev qce_dev = {
	.mutex = MUTEX_INITIALIZER,
};

static struct qce_hash_ctx *to_qce_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &qce_hash_ops);

	return container_of(ctx, struct qce_hash_ctx, hash_ctx);
}

register_phys_mem_pgdir(MEM_AREA_IO_SEC, QCOM_GPCE_REG_BASE,
			QCOM_GPCE_REG_SIZE);

static void qce_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct qce_hash_ctx *qce_ctx = NULL;
	struct qce_hash_state *state = NULL;

	if (!ctx || ctx->ops != &qce_hash_ops)
		return;

	qce_ctx = to_qce_hash_ctx(ctx);
	state = qce_ctx->state;
	if (state && state->ctx)
		sha_cmn_ce_cleanup(state);
	free_wipe(state);
	free_wipe(qce_ctx);
}

static TEE_Result qce_hash_init(struct crypto_hash_ctx *ctx)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	if (!ctx || ctx->ops != &qce_hash_ops)
		return TEE_ERROR_BAD_PARAMETERS;

	qce_ctx = to_qce_hash_ctx(ctx);
	return sha_cmn_ce_init(qce_ctx->state);
}

static TEE_Result qce_hash_update(struct crypto_hash_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	if (!ctx || ctx->ops != &qce_hash_ops || (!data && len))
		return TEE_ERROR_BAD_PARAMETERS;

	qce_ctx = to_qce_hash_ctx(ctx);
	return sha_cmn_ce_update(qce_ctx->state, data, len);
}

static TEE_Result qce_hash_final(struct crypto_hash_ctx *ctx,
				 uint8_t *digest, size_t len)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	if (!ctx || ctx->ops != &qce_hash_ops || !digest)
		return TEE_ERROR_BAD_PARAMETERS;
	if (len < TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	qce_ctx = to_qce_hash_ctx(ctx);
	return sha_cmn_ce_final(qce_ctx->state, digest);
}

static void qce_hash_copy_state(struct crypto_hash_ctx *dst,
				struct crypto_hash_ctx *src)
{
	struct qce_hash_ctx *dst_ctx = NULL;
	struct qce_hash_ctx *src_ctx = NULL;
	struct qce_hash_state *dst_state = NULL;
	struct qce_hash_state *src_state = NULL;
	void *dst_inner_ctx = NULL;
	TEE_Result ret = TEE_ERROR_BAD_STATE;

	assert(dst && src);

	dst_ctx = to_qce_hash_ctx(dst);
	src_ctx = to_qce_hash_ctx(src);
	dst_state = dst_ctx->state;
	src_state = src_ctx->state;
	if (!dst_state || !src_state)
		goto out;

	if (dst_state->ctx &&
	    (!src_state->ctx ||
	     dst_state->ctx_sz != src_state->ctx_sz)) {
		ret = sha_cmn_ce_cleanup(dst_state);
		if (ret)
			goto out;
		dst_state->ctx = NULL;
	}

	dst_inner_ctx = dst_state->ctx;
	memcpy(dst_state, src_state, sizeof(*dst_state));
	dst_state->ctx = dst_inner_ctx;
	if (src_state->ctx) {
		if (!dst_inner_ctx) {
			dst_state->ctx = calloc(1, src_state->ctx_sz);
			if (!dst_state->ctx) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto out;
			}
		}
		ret = sha_cmn_ce_copy(dst_state, src_state);
		if (ret)
			goto out;
	}
	ret = TEE_SUCCESS;
out:
	if (ret)
		EMSG("QCE hash state copy failed: %#"PRIx32, ret);
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
	state->dev = &qce_dev;
	qce_ctx->state = state;
	qce_ctx->hash_ctx.ops = &qce_hash_ops;
	*ctx = &qce_ctx->hash_ctx;

	return TEE_SUCCESS;
}

static TEE_Result qce_hash_driver_init(void)
{
	TEE_Result res = TEE_SUCCESS;

	qce_dev.base = (vaddr_t)phys_to_virt(QCOM_GPCE_REG_BASE,
						     MEM_AREA_IO_SEC,
						     QCOM_GPCE_REG_SIZE);
	if (!qce_dev.base) {
		EMSG("QCE hash: failed to map the Crypto Engine registers");
		return TEE_ERROR_GENERIC;
	}

	res = drvcrypt_register_hash(qce_hash_alloc_ctx);

	if (res)
		EMSG("QCE hash: drvcrypt_register_hash failed: %#"PRIx32, res);

	return res;
}

driver_init(qce_hash_driver_init);
