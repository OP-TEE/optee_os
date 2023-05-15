// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto_accel.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <mbedtls/aes.h>
#include <mbedtls/platform_util.h>
#include <string.h>

TEE_Result crypto_aes_expand_enc_key(const void *key, size_t key_len,
				     void *enc_key, size_t enc_keylen,
				     unsigned int *rounds)
{
#if defined(MBEDTLS_AES_ALT)
	return crypto_accel_aes_expand_keys(key, key_len, enc_key, NULL,
					    enc_keylen, rounds);
#else
	mbedtls_aes_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	mbedtls_aes_init(&ctx);
	if (mbedtls_aes_setkey_enc(&ctx, key, key_len * 8) != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (enc_keylen > sizeof(ctx.buf))
		return TEE_ERROR_BAD_PARAMETERS;
	memcpy(enc_key, ctx.buf, enc_keylen);
	*rounds = ctx.nr;
	mbedtls_aes_free(&ctx);
	return TEE_SUCCESS;
#endif
}

void crypto_aes_enc_block(const void *enc_key, size_t enc_keylen __maybe_unused,
			  unsigned int rounds, const void *src, void *dst)
{
#if defined(MBEDTLS_AES_ALT)
	crypto_accel_aes_ecb_enc(dst, src, enc_key, rounds, 1);
#else
	mbedtls_aes_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	mbedtls_aes_init(&ctx);
	if (enc_keylen > sizeof(ctx.buf))
		panic();
	memcpy(ctx.buf, enc_key, enc_keylen);
	ctx.rk = ctx.buf;
	ctx.nr = rounds;
	mbedtls_aes_encrypt(&ctx, src, dst);
	mbedtls_aes_free(&ctx);
#endif
}

#if defined(MBEDTLS_AES_ALT)
void mbedtls_aes_init(mbedtls_aes_context *ctx)
{
	assert(ctx);
	memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
	if (ctx)
		mbedtls_platform_zeroize(ctx, sizeof(*ctx));
}

int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
			   unsigned int keybits)
{
	assert(ctx && key);

	if (keybits != 128 && keybits != 192 && keybits != 256)
		return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

	if (crypto_accel_aes_expand_keys(key, keybits / 8, ctx->key, NULL,
					 sizeof(ctx->key), &ctx->round_count))
		return MBEDTLS_ERR_AES_BAD_INPUT_DATA;

	return 0;
}

int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
			   unsigned int keybits)
{
	uint32_t enc_key[sizeof(ctx->key)] = { 0 };

	assert(ctx && key);

	if (keybits != 128 && keybits != 192 && keybits != 256)
		return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

	if (crypto_accel_aes_expand_keys(key, keybits / 8, enc_key, ctx->key,
					 sizeof(ctx->key), &ctx->round_count))
		return MBEDTLS_ERR_AES_BAD_INPUT_DATA;

	return 0;
}
#endif /*MBEDTLS_AES_ALT*/
