// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 * Copyright (C) 2019 Huawei Technologies Co., Ltd
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

#include "sm3.h"

struct sm3_hash_ctx {
	struct crypto_hash_ctx hash_ctx;
	struct sm3_context sm3_ctx;
};

static const struct crypto_hash_ops sm3_hash_ops;

static struct sm3_hash_ctx *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &sm3_hash_ops);

	return container_of(ctx, struct sm3_hash_ctx, hash_ctx);
}

static TEE_Result op_sm3_hash_init(struct crypto_hash_ctx *ctx)
{
	sm3_init(&to_hash_ctx(ctx)->sm3_ctx);

	return TEE_SUCCESS;
}

static TEE_Result op_sm3_hash_update(struct crypto_hash_ctx *ctx,
				     const uint8_t *data, size_t len)
{
	sm3_update(&to_hash_ctx(ctx)->sm3_ctx, data, len);

	return TEE_SUCCESS;
}

static TEE_Result op_sm3_hash_final(struct crypto_hash_ctx *ctx,
				    uint8_t *digest,
				    size_t len)
{
	struct sm3_hash_ctx *hc = to_hash_ctx(ctx);
	size_t hash_size = TEE_SM3_HASH_SIZE;
	uint8_t block_digest[TEE_SM3_HASH_SIZE] = { 0 };
	uint8_t *tmp_digest = NULL;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash_size > len)
		tmp_digest = block_digest; /* use a tempory buffer */
	else
		tmp_digest = digest;

	sm3_final(&hc->sm3_ctx, tmp_digest);

	if (hash_size > len)
		memcpy(digest, tmp_digest, len);

	return TEE_SUCCESS;
}

static void op_sm3_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct sm3_hash_ctx *hc = to_hash_ctx(ctx);

	memzero_explicit(&hc->sm3_ctx, sizeof(hc->sm3_ctx));
	free(hc);
}

static void op_sm3_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
				   struct crypto_hash_ctx *src_ctx)
{
	struct sm3_hash_ctx *src = to_hash_ctx(src_ctx);
	struct sm3_hash_ctx *dst = to_hash_ctx(dst_ctx);

	dst->sm3_ctx = src->sm3_ctx;
}

static const struct crypto_hash_ops sm3_hash_ops = {
	.init = op_sm3_hash_init,
	.update = op_sm3_hash_update,
	.final = op_sm3_hash_final,
	.free_ctx = op_sm3_hash_free_ctx,
	.copy_state = op_sm3_hash_copy_state,
};

TEE_Result crypto_sm3_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	struct sm3_hash_ctx *hc = NULL;

	hc = calloc(1, sizeof(*hc));
	if (!hc)
		return TEE_ERROR_OUT_OF_MEMORY;

	hc->hash_ctx.ops = &sm3_hash_ops;

	*ctx = &hc->hash_ctx;

	return TEE_SUCCESS;
}
