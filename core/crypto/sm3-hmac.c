// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

#include "sm3.h"

struct sm3_hmac_ctx {
	struct crypto_mac_ctx mac_ctx;
	struct sm3_context sm3_ctx;
};

static const struct crypto_mac_ops sm3_hmac_ops;

static struct sm3_hmac_ctx *to_hmac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &sm3_hmac_ops);

	return container_of(ctx, struct sm3_hmac_ctx, mac_ctx);
}

static TEE_Result op_sm3_hmac_init(struct crypto_mac_ctx *ctx,
				 const uint8_t *key, size_t len)
{
	sm3_hmac_init(&to_hmac_ctx(ctx)->sm3_ctx, key, len);

	return TEE_SUCCESS;
}

static TEE_Result op_sm3_hmac_update(struct crypto_mac_ctx *ctx,
				   const uint8_t *data, size_t len)
{
	sm3_hmac_update(&to_hmac_ctx(ctx)->sm3_ctx, data, len);

	return TEE_SUCCESS;
}

static TEE_Result op_sm3_hmac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				  size_t len)
{
	struct sm3_hmac_ctx *c = to_hmac_ctx(ctx);
	size_t hmac_size = TEE_SM3_HASH_SIZE;
	uint8_t block_digest[TEE_SM3_HASH_SIZE] = { 0 };
	uint8_t *tmp_digest = NULL;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hmac_size > len)
		tmp_digest = block_digest; /* use a tempory buffer */
	else
		tmp_digest = digest;

	sm3_hmac_final(&c->sm3_ctx, tmp_digest);

	if (hmac_size > len)
		memcpy(digest, tmp_digest, len);

	return TEE_SUCCESS;
}

static void op_sm3_hmac_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct sm3_hmac_ctx *c = to_hmac_ctx(ctx);

	memzero_explicit(&c->sm3_ctx, sizeof(c->sm3_ctx));
	free(c);
}

static void op_sm3_hmac_copy_state(struct crypto_mac_ctx *dst_ctx,
				 struct crypto_mac_ctx *src_ctx)
{
	struct sm3_hmac_ctx *src = to_hmac_ctx(src_ctx);
	struct sm3_hmac_ctx *dst = to_hmac_ctx(dst_ctx);

	dst->sm3_ctx = src->sm3_ctx;
}

static const struct crypto_mac_ops sm3_hmac_ops = {
	.init = op_sm3_hmac_init,
	.update = op_sm3_hmac_update,
	.final = op_sm3_hmac_final,
	.free_ctx = op_sm3_hmac_free_ctx,
	.copy_state = op_sm3_hmac_copy_state,
};

TEE_Result crypto_hmac_sm3_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	struct sm3_hmac_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->mac_ctx.ops = &sm3_hmac_ops;

	*ctx = &c->mac_ctx;

	return TEE_SUCCESS;
}
