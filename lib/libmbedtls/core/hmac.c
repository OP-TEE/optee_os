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
#include <mbedtls/md.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

struct mbed_hmac_ctx {
	struct crypto_mac_ctx mac_ctx;
	mbedtls_md_context_t md_ctx;
};

static const struct crypto_mac_ops mbed_hmac_ops;

static struct mbed_hmac_ctx *to_hmac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &mbed_hmac_ops);

	return container_of(ctx, struct mbed_hmac_ctx, mac_ctx);
}

static TEE_Result mbed_hmac_init(struct crypto_mac_ctx *ctx,
				 const uint8_t *key, size_t len)
{
	if (mbedtls_md_hmac_starts(&to_hmac_ctx(ctx)->md_ctx, key, len))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_hmac_update(struct crypto_mac_ctx *ctx,
				   const uint8_t *data, size_t len)
{
	if (mbedtls_md_hmac_update(&to_hmac_ctx(ctx)->md_ctx, data, len))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_hmac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				  size_t len)
{
	struct mbed_hmac_ctx *c = to_hmac_ctx(ctx);
	uint8_t block_digest[TEE_MAX_HASH_SIZE] = { 0 };
	uint8_t *tmp_digest = NULL;
	size_t hmac_size = 0;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	hmac_size = mbedtls_md_get_size(mbedtls_md_info_from_ctx(&c->md_ctx));
	if (hmac_size > len) {
		if (hmac_size > sizeof(block_digest))
			return TEE_ERROR_BAD_STATE;
		tmp_digest = block_digest; /* use a tempory buffer */
	} else {
		tmp_digest = digest;
	}

	if (mbedtls_md_hmac_finish(&c->md_ctx, tmp_digest))
		return TEE_ERROR_BAD_STATE;

	if (hmac_size > len)
		memcpy(digest, tmp_digest, len);

	return TEE_SUCCESS;
}

static void mbed_hmac_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct mbed_hmac_ctx *c = to_hmac_ctx(ctx);

	mbedtls_md_free(&c->md_ctx);
	free(c);
}

static void mbed_hmac_copy_state(struct crypto_mac_ctx *dst_ctx,
				 struct crypto_mac_ctx *src_ctx)
{
	struct mbed_hmac_ctx *src = to_hmac_ctx(src_ctx);
	struct mbed_hmac_ctx *dst = to_hmac_ctx(dst_ctx);

	if (mbedtls_md_clone(&dst->md_ctx, &src->md_ctx))
		panic();
}

static const struct crypto_mac_ops mbed_hmac_ops = {
	.init = mbed_hmac_init,
	.update = mbed_hmac_update,
	.final = mbed_hmac_final,
	.free_ctx = mbed_hmac_free_ctx,
	.copy_state = mbed_hmac_copy_state,
};

static TEE_Result mbed_hmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret,
				      mbedtls_md_type_t md_type)
{
	int mbed_res = 0;
	struct mbed_hmac_ctx *c = NULL;
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);

	if (!md_info)
		return TEE_ERROR_NOT_SUPPORTED;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->mac_ctx.ops = &mbed_hmac_ops;
	mbed_res = mbedtls_md_setup(&c->md_ctx, md_info, 1);
	if (mbed_res) {
		free(c);
		if (mbed_res == MBEDTLS_ERR_MD_ALLOC_FAILED)
			return TEE_ERROR_OUT_OF_MEMORY;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	*ctx_ret = &c->mac_ctx;

	return TEE_SUCCESS;
}

#if defined(CFG_CRYPTO_MD5)
TEE_Result crypto_hmac_md5_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return mbed_hmac_alloc_ctx(ctx, MBEDTLS_MD_MD5);
}
#endif

#if defined(CFG_CRYPTO_SHA1)
TEE_Result crypto_hmac_sha1_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return mbed_hmac_alloc_ctx(ctx, MBEDTLS_MD_SHA1);
}
#endif

#if defined(CFG_CRYPTO_SHA224)
TEE_Result crypto_hmac_sha224_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return mbed_hmac_alloc_ctx(ctx, MBEDTLS_MD_SHA224);
}
#endif

#if defined(CFG_CRYPTO_SHA256)
TEE_Result crypto_hmac_sha256_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return mbed_hmac_alloc_ctx(ctx, MBEDTLS_MD_SHA256);
}
#endif

#if defined(CFG_CRYPTO_SHA384)
TEE_Result crypto_hmac_sha384_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return mbed_hmac_alloc_ctx(ctx, MBEDTLS_MD_SHA384);
}
#endif

#if defined(CFG_CRYPTO_SHA512)
TEE_Result crypto_hmac_sha512_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return mbed_hmac_alloc_ctx(ctx, MBEDTLS_MD_SHA512);
}
#endif
