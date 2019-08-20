// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tomcrypt_private.h>
#include <utee_defines.h>
#include <util.h>

struct ltc_hmac_ctx {
	struct crypto_mac_ctx ctx;
	int hash_idx;
	hmac_state state;
};

static const struct crypto_mac_ops ltc_hmac_ops;

static struct ltc_hmac_ctx *to_hmac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &ltc_hmac_ops);

	return container_of(ctx, struct ltc_hmac_ctx, ctx);
}

static TEE_Result ltc_hmac_init(struct crypto_mac_ctx *ctx, const uint8_t *key,
				size_t len)
{
	struct ltc_hmac_ctx *hc = to_hmac_ctx(ctx);

	if (hmac_init(&hc->state, hc->hash_idx, key, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result ltc_hmac_update(struct crypto_mac_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	if (hmac_process(&to_hmac_ctx(ctx)->state, data, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result ltc_hmac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				 size_t len)
{
	unsigned long l = len;

	if (hmac_done(&to_hmac_ctx(ctx)->state, digest, &l) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static void ltc_hmac_free_ctx(struct crypto_mac_ctx *ctx)
{
	free(to_hmac_ctx(ctx));
}

static void ltc_hmac_copy_state(struct crypto_mac_ctx *dst_ctx,
				struct crypto_mac_ctx *src_ctx)
{
	struct ltc_hmac_ctx *src = to_hmac_ctx(src_ctx);
	struct ltc_hmac_ctx *dst = to_hmac_ctx(dst_ctx);

	assert(src->hash_idx == dst->hash_idx);
	dst->state = src->state;
}

static const struct crypto_mac_ops ltc_hmac_ops = {
	.init = ltc_hmac_init,
	.update = ltc_hmac_update,
	.final = ltc_hmac_final,
	.free_ctx = ltc_hmac_free_ctx,
	.copy_state = ltc_hmac_copy_state,
};

static TEE_Result ltc_hmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret,
				     int hash_idx)
{
	struct ltc_hmac_ctx *ctx = NULL;

	if (hash_idx < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ctx->ctx.ops = &ltc_hmac_ops;
	ctx->hash_idx = hash_idx;
	*ctx_ret = &ctx->ctx;

	return TEE_SUCCESS;
}

TEE_Result crypto_hmac_md5_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return ltc_hmac_alloc_ctx(ctx, find_hash("md5"));
}

TEE_Result crypto_hmac_sha1_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return ltc_hmac_alloc_ctx(ctx, find_hash("sha1"));
}

TEE_Result crypto_hmac_sha224_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return ltc_hmac_alloc_ctx(ctx, find_hash("sha224"));
}

TEE_Result crypto_hmac_sha256_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return ltc_hmac_alloc_ctx(ctx, find_hash("sha256"));
}

TEE_Result crypto_hmac_sha384_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return ltc_hmac_alloc_ctx(ctx, find_hash("sha384"));
}

TEE_Result crypto_hmac_sha512_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return ltc_hmac_alloc_ctx(ctx, find_hash("sha512"));
}
