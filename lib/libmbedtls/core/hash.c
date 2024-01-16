// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto_accel.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

struct mbed_hash_ctx {
	struct crypto_hash_ctx hash_ctx;
	mbedtls_md_context_t md_ctx;
};

static const struct crypto_hash_ops mbed_hash_ops;

static struct mbed_hash_ctx *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &mbed_hash_ops);

	return container_of(ctx, struct mbed_hash_ctx, hash_ctx);
}

static TEE_Result mbed_hash_init(struct crypto_hash_ctx *ctx)
{
	if (mbedtls_md_starts(&to_hash_ctx(ctx)->md_ctx))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_hash_update(struct crypto_hash_ctx *ctx,
				   const uint8_t *data, size_t len)
{
	if (mbedtls_md_update(&to_hash_ctx(ctx)->md_ctx, data, len))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_hash_final(struct crypto_hash_ctx *ctx, uint8_t *digest,
				  size_t len)
{
	struct mbed_hash_ctx *hc = to_hash_ctx(ctx);
	uint8_t block_digest[TEE_MAX_HASH_SIZE] = { 0 };
	uint8_t *tmp_digest = NULL;
	size_t hash_size = 0;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	hash_size = mbedtls_md_get_size(mbedtls_md_info_from_ctx(&hc->md_ctx));
	if (hash_size > len) {
		if (hash_size > sizeof(block_digest))
			return TEE_ERROR_BAD_STATE;
		tmp_digest = block_digest; /* use a tempory buffer */
	} else {
		tmp_digest = digest;
	}

	if (mbedtls_md_finish(&hc->md_ctx, tmp_digest))
		return TEE_ERROR_BAD_STATE;

	if (hash_size > len)
		memcpy(digest, tmp_digest, len);

	return TEE_SUCCESS;
}

static void mbed_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct mbed_hash_ctx *hc = to_hash_ctx(ctx);

	mbedtls_md_free(&hc->md_ctx);
	free(hc);
}

static void mbed_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
				 struct crypto_hash_ctx *src_ctx)
{
	struct mbed_hash_ctx *src = to_hash_ctx(src_ctx);
	struct mbed_hash_ctx *dst = to_hash_ctx(dst_ctx);

	if (mbedtls_md_clone(&dst->md_ctx, &src->md_ctx))
		panic();
}

static const struct crypto_hash_ops mbed_hash_ops = {
	.init = mbed_hash_init,
	.update = mbed_hash_update,
	.final = mbed_hash_final,
	.free_ctx = mbed_hash_free_ctx,
	.copy_state = mbed_hash_copy_state,
};

static TEE_Result mbed_hash_alloc_ctx(struct crypto_hash_ctx **ctx_ret,
				      mbedtls_md_type_t md_type)
{
	int mbed_res = 0;
	struct mbed_hash_ctx *hc = NULL;
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);

	if (!md_info)
		return TEE_ERROR_NOT_SUPPORTED;

	hc = calloc(1, sizeof(*hc));
	if (!hc)
		return TEE_ERROR_OUT_OF_MEMORY;

	hc->hash_ctx.ops = &mbed_hash_ops;
	mbed_res = mbedtls_md_setup(&hc->md_ctx, md_info, 0);
	if (mbed_res) {
		free(hc);
		if (mbed_res == MBEDTLS_ERR_MD_ALLOC_FAILED)
			return TEE_ERROR_OUT_OF_MEMORY;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	*ctx_ret = &hc->hash_ctx;

	return TEE_SUCCESS;
}

#if defined(CFG_CRYPTO_MD5)
TEE_Result crypto_md5_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return mbed_hash_alloc_ctx(ctx, MBEDTLS_MD_MD5);
}
#endif

#if defined(CFG_CRYPTO_SHA1)
TEE_Result crypto_sha1_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return mbed_hash_alloc_ctx(ctx, MBEDTLS_MD_SHA1);
}
#endif

#if defined(CFG_CRYPTO_SHA224)
TEE_Result crypto_sha224_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return mbed_hash_alloc_ctx(ctx, MBEDTLS_MD_SHA224);
}
#endif

#if defined(CFG_CRYPTO_SHA256)
TEE_Result crypto_sha256_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return mbed_hash_alloc_ctx(ctx, MBEDTLS_MD_SHA256);
}
#endif

#if defined(CFG_CRYPTO_SHA384)
TEE_Result crypto_sha384_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return mbed_hash_alloc_ctx(ctx, MBEDTLS_MD_SHA384);
}
#endif

#if defined(CFG_CRYPTO_SHA512)
TEE_Result crypto_sha512_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return mbed_hash_alloc_ctx(ctx, MBEDTLS_MD_SHA512);
}
#endif

#if defined(CFG_CRYPTO_SHA256)
TEE_Result hash_sha256_check(const uint8_t *hash, const uint8_t *data,
			     size_t data_size)
{
	mbedtls_sha256_context hs;
	uint8_t digest[TEE_SHA256_HASH_SIZE] = { 0 };

	memset(&hs, 0, sizeof(hs));
	mbedtls_sha256_init(&hs);
	mbedtls_sha256_starts(&hs, 0);
	mbedtls_sha256_update(&hs, data, data_size);
	mbedtls_sha256_finish(&hs, digest);
	mbedtls_sha256_free(&hs);

	if (consttime_memcmp(digest, hash, sizeof(digest)))
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}
#endif

#if defined(MBEDTLS_SHA1_PROCESS_ALT)
int mbedtls_internal_sha1_process(mbedtls_sha1_context *ctx,
				  const unsigned char data[64])
{
	MBEDTLS_INTERNAL_VALIDATE_RET(ctx != NULL,
				      MBEDTLS_ERR_SHA1_BAD_INPUT_DATA);
	MBEDTLS_INTERNAL_VALIDATE_RET((const unsigned char *)data != NULL,
				      MBEDTLS_ERR_SHA1_BAD_INPUT_DATA);

	crypto_accel_sha1_compress(ctx->state, data, 1);

	return 0;
}
#endif /*MBEDTLS_SHA1_PROCESS_ALT*/

#if defined(MBEDTLS_SHA256_PROCESS_ALT)
int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx,
				    const unsigned char data[64])
{
	MBEDTLS_INTERNAL_VALIDATE_RET(ctx != NULL,
				      MBEDTLS_ERR_SHA256_BAD_INPUT_DATA);
	MBEDTLS_INTERNAL_VALIDATE_RET((const unsigned char *)data != NULL,
				      MBEDTLS_ERR_SHA256_BAD_INPUT_DATA);

	crypto_accel_sha256_compress(ctx->state, data, 1);

	return 0;
}
#endif /*MBEDTLS_SHA256_PROCESS_ALT*/

#if defined(MBEDTLS_SHA512_PROCESS_ALT)
int mbedtls_internal_sha512_process(mbedtls_sha512_context *ctx,
				    const unsigned char data[64])
{
	MBEDTLS_INTERNAL_VALIDATE_RET(ctx != NULL,
				      MBEDTLS_ERR_SHA512_BAD_INPUT_DATA);
	MBEDTLS_INTERNAL_VALIDATE_RET((const unsigned char *)data != NULL,
				      MBEDTLS_ERR_SHA512_BAD_INPUT_DATA);

	crypto_accel_sha512_compress(ctx->state, data, 1);

	return 0;
}
#endif /*MBEDTLS_SHA512_PROCESS_ALT*/
