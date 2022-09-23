// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tomcrypt_private.h>
#include <utee_defines.h>
#include <util.h>

/******************************************************************************
 * Message digest functions
 ******************************************************************************/

struct ltc_hash_ctx {
	struct crypto_hash_ctx ctx;
	const struct ltc_hash_descriptor *descr;
	hash_state state;
};

static const struct crypto_hash_ops ltc_hash_ops;

static struct ltc_hash_ctx *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &ltc_hash_ops);

	return container_of(ctx, struct ltc_hash_ctx, ctx);
}

static TEE_Result ltc_hash_init(struct crypto_hash_ctx *ctx)
{
	struct ltc_hash_ctx *hc = to_hash_ctx(ctx);

	if (hc->descr->init(&hc->state) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result ltc_hash_update(struct crypto_hash_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	struct ltc_hash_ctx *hc = to_hash_ctx(ctx);

	if (hc->descr->process(&hc->state, data, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result ltc_hash_final(struct crypto_hash_ctx *ctx, uint8_t *digest,
				 size_t len)
{
	struct ltc_hash_ctx *hc = to_hash_ctx(ctx);
	size_t hash_size = hc->descr->hashsize;
	uint8_t block_digest[TEE_MAX_HASH_SIZE] = { 0 };
	uint8_t *tmp_digest = NULL;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash_size > len) {
		if (hash_size > sizeof(block_digest))
			return TEE_ERROR_BAD_STATE;
		tmp_digest = block_digest; /* use a tempory buffer */
	} else {
		tmp_digest = digest;
	}

	if (hc->descr->done(&hc->state, tmp_digest) == CRYPT_OK) {
		if (hash_size > len)
			memcpy(digest, tmp_digest, len);
	} else {
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static void ltc_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	free(to_hash_ctx(ctx));
}

static void ltc_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
				struct crypto_hash_ctx *src_ctx)
{
	struct ltc_hash_ctx *src = to_hash_ctx(src_ctx);
	struct ltc_hash_ctx *dst = to_hash_ctx(dst_ctx);

	assert(src->descr == dst->descr);
	dst->state = src->state;
}

static const struct crypto_hash_ops ltc_hash_ops = {
	.init = ltc_hash_init,
	.update = ltc_hash_update,
	.final = ltc_hash_final,
	.free_ctx = ltc_hash_free_ctx,
	.copy_state = ltc_hash_copy_state,
};

static TEE_Result ltc_hash_alloc_ctx(struct crypto_hash_ctx **ctx_ret,
				     int ltc_hash_idx)
{
	struct ltc_hash_ctx *ctx = NULL;

	if (ltc_hash_idx < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ctx->ctx.ops = &ltc_hash_ops;
	ctx->descr = hash_descriptor[ltc_hash_idx];

	*ctx_ret = &ctx->ctx;

	return TEE_SUCCESS;
}

#if defined(_CFG_CORE_LTC_MD5)
TEE_Result crypto_md5_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return ltc_hash_alloc_ctx(ctx, find_hash("md5"));
}
#endif

#if defined(_CFG_CORE_LTC_SHA1)
TEE_Result crypto_sha1_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return ltc_hash_alloc_ctx(ctx, find_hash("sha1"));
}
#endif

#if defined(_CFG_CORE_LTC_SHA224)
TEE_Result crypto_sha224_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return ltc_hash_alloc_ctx(ctx, find_hash("sha224"));
}
#endif

#if defined(_CFG_CORE_LTC_SHA256)
TEE_Result crypto_sha256_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return ltc_hash_alloc_ctx(ctx, find_hash("sha256"));
}
#endif

#if defined(_CFG_CORE_LTC_SHA384)
TEE_Result crypto_sha384_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return ltc_hash_alloc_ctx(ctx, find_hash("sha384"));
}
#endif

#if defined(_CFG_CORE_LTC_SHA512)
TEE_Result crypto_sha512_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return ltc_hash_alloc_ctx(ctx, find_hash("sha512"));
}
#endif

#if defined(_CFG_CORE_LTC_SHA256)
TEE_Result hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size)
{
	hash_state hs;
	uint8_t digest[TEE_SHA256_HASH_SIZE];

	if (sha256_init(&hs) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha256_process(&hs, data, data_size) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha256_done(&hs, digest) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (consttime_memcmp(digest, hash, sizeof(digest)) != 0)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}
#endif

#if defined(_CFG_CORE_LTC_SHA512_256)
TEE_Result hash_sha512_256_compute(uint8_t *digest, const uint8_t *data,
		size_t data_size)
{
	hash_state hs;

	if (sha512_256_init(&hs) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha512_256_process(&hs, data, data_size) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha512_256_done(&hs, digest) != CRYPT_OK)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
#endif

