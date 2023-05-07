// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2023. All rights reserved.
 *
 * SM4 optimization for ARMv8
 */

#include "sm4.h"
#include <assert.h>
#include <string.h>
#include <crypto/crypto_accel.h>

void sm4_setkey_enc(struct sm4_context *ctx, const uint8_t key[16])
{
	ctx->mode = SM4_ENCRYPT;
	crypto_accel_sm4_setkey_enc(ctx->sk, key);
}

void sm4_setkey_dec(struct sm4_context *ctx, const uint8_t key[16])
{
	ctx->mode = SM4_DECRYPT;
	crypto_accel_sm4_setkey_dec(ctx->sk, key);
}

void sm4_crypt_ecb(struct sm4_context *ctx, size_t length, const uint8_t *input,
		   uint8_t *output)
{
	assert(!(length % 16));

	crypto_accel_sm4_ecb_enc(output, input, ctx->sk, length);
}

void sm4_crypt_cbc(struct sm4_context *ctx, size_t length, uint8_t iv[16],
		   const uint8_t *input, uint8_t *output)
{
	assert(!(length % 16));

	if (ctx->mode == SM4_ENCRYPT)
		crypto_accel_sm4_cbc_enc(output, input, ctx->sk, length, iv);
	else
		/* SM4_DECRYPT */
		crypto_accel_sm4_cbc_dec(output, input, ctx->sk, length, iv);
}

void sm4_crypt_ctr(struct sm4_context *ctx, size_t length, uint8_t ctr[16],
		   const uint8_t *input, uint8_t *output)
{
	assert(!(length % 16));

	crypto_accel_sm4_ctr_enc(output, input, ctx->sk, length, ctr);
}

void sm4_crypt_xts(struct sm4_context *ctx, struct sm4_context *ctx_ek,
		   struct sm4_context *ctx_dk __unused, size_t len, uint8_t *iv,
		   const uint8_t *input, uint8_t *output)
{
	assert(len >= 16);

	if (ctx->mode == SM4_ENCRYPT)
		crypto_accel_sm4_xts_enc(output, input, ctx->sk, ctx_ek->sk,
					 len, iv);
	else
		crypto_accel_sm4_xts_dec(output, input, ctx->sk, ctx_ek->sk,
					 len, iv);
}
