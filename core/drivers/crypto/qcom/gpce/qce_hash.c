// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 * Implementation of the Qualcomm Crypto Engine hash driver.
 */
#include <crypto/crypto_impl.h>
#include <drvcrypt_hash.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <utee_defines.h>

#include "ce_hwio.h"
#include "hash.h"

struct qce_hash_ctx {
	struct crypto_hash_ctx hash_ctx;
	struct hash_ctx_s *state;
	uint32_t tee_alg;
};

static const struct crypto_hash_ops qce_hash_ops;
static struct qce_dev_s qce_dev = {
	.mutex = MUTEX_INITIALIZER,
};

register_phys_mem_pgdir(MEM_AREA_IO_SEC, QCOM_GPCE_REG_BASE,
			QCOM_GPCE_REG_SIZE);

static void qce_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct qce_hash_ctx *qce_ctx = NULL;
	struct hash_ctx_s *state = NULL;

	if (!ctx || ctx->ops != &qce_hash_ops)
		return;

	qce_ctx = container_of(ctx, struct qce_hash_ctx, hash_ctx);
	state = qce_ctx->state;
	if (state && state->ctx)
		(void)SHA_CMN_CE_cleanup(state);
	if (state) {
		memset(state, 0, sizeof(*state));
		free(state);
	}

	memzero_explicit(qce_ctx, sizeof(*qce_ctx));
	free(qce_ctx);
}

static TEE_Result qce_hash_init(struct crypto_hash_ctx *ctx)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	if (!ctx || ctx->ops != &qce_hash_ops)
		return TEE_ERROR_BAD_PARAMETERS;

	qce_ctx = container_of(ctx, struct qce_hash_ctx, hash_ctx);
	return SHA1_CE_HWIO_init(qce_ctx->state);
}

static TEE_Result qce_hash_update(struct crypto_hash_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	if (!ctx || ctx->ops != &qce_hash_ops ||
	    (!data && len) || (uintptr_t)data > UINTPTR_MAX - len)
		return TEE_ERROR_BAD_PARAMETERS;

	qce_ctx = container_of(ctx, struct qce_hash_ctx, hash_ctx);
	return SHA_CMN_CE_update(qce_ctx->state, data, len);
}

static TEE_Result qce_hash_final(struct crypto_hash_ctx *ctx,
				 uint8_t *digest, size_t len)
{
	struct qce_hash_ctx *qce_ctx = NULL;

	if (!ctx || ctx->ops != &qce_hash_ops || !digest ||
	    (uintptr_t)digest > UINTPTR_MAX - len)
		return TEE_ERROR_BAD_PARAMETERS;
	if (len < SHA1_DIGEST_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	qce_ctx = container_of(ctx, struct qce_hash_ctx, hash_ctx);
	return SHA_CMN_CE_final(qce_ctx->state, digest, SHA1_DIGEST_SIZE);
}

static void qce_hash_copy_state(struct crypto_hash_ctx *dst,
				struct crypto_hash_ctx *src)
{
	struct qce_hash_ctx *dst_ctx = NULL;
	struct qce_hash_ctx *src_ctx = NULL;
	struct hash_ctx_s *dst_state = NULL;
	struct hash_ctx_s *src_state = NULL;
	TEE_Result ret = TEE_ERROR_BAD_STATE;

	if (!dst || !src || dst->ops != &qce_hash_ops ||
	    src->ops != &qce_hash_ops)
		goto out;

	dst_ctx = container_of(dst, struct qce_hash_ctx, hash_ctx);
	src_ctx = container_of(src, struct qce_hash_ctx, hash_ctx);
	dst_state = dst_ctx->state;
	src_state = src_ctx->state;
	if (HASH_IS_CTX_NULL(dst_state) ||
	    HASH_IS_CTX_NULL(src_state) ||
	    dst_ctx->tee_alg != src_ctx->tee_alg)
		goto out;

	if (dst_state->ctx) {
		ret = SHA_CMN_CE_cleanup(dst_state);
		if (ret != TEE_SUCCESS)
			goto out;
	}

	*dst_state = *src_state;
	dst_state->ctx = NULL;
	if (src_state->ctx) {
		dst_state->ctx = calloc(1, src_state->ctx_sz);
		if (!dst_state->ctx) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		ret = SHA_CMN_CE_copy(dst_state, src_state);
		if (ret != TEE_SUCCESS)
			goto out;
	}
	ret = TEE_SUCCESS;
out:
	if (ret != TEE_SUCCESS)
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
	struct hash_ctx_s *state = NULL;

	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;
	*ctx = NULL;

	if (algo != TEE_ALG_SHA1)
		return TEE_ERROR_NOT_IMPLEMENTED;

	qce_ctx = calloc(1, sizeof(*qce_ctx));
	if (!qce_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	qce_ctx->tee_alg = algo;
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
