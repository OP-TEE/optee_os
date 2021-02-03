// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Linaro Limited
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto_accel.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <mbedtls/aes.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

#include "mbed_helpers.h"

struct mbed_aes_ecb_ctx {
	struct crypto_cipher_ctx ctx;
	int mbed_mode;
	mbedtls_aes_context aes_ctx;
};

static const struct crypto_cipher_ops mbed_aes_ecb_ops;

static struct mbed_aes_ecb_ctx *to_aes_ecb_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &mbed_aes_ecb_ops);

	return container_of(ctx, struct mbed_aes_ecb_ctx, ctx);
}

static TEE_Result mbed_aes_ecb_init(struct crypto_cipher_ctx *ctx,
				    TEE_OperationMode mode, const uint8_t *key1,
				    size_t key1_len,
				    const uint8_t *key2 __unused,
				    size_t key2_len __unused,
				    const uint8_t *iv __unused,
				    size_t iv_len  __unused)
{
	struct mbed_aes_ecb_ctx *c = to_aes_ecb_ctx(ctx);
	int mbed_res = 0;

	mbedtls_aes_init(&c->aes_ctx);

	if (mode == TEE_MODE_ENCRYPT) {
		c->mbed_mode = MBEDTLS_AES_ENCRYPT;
		mbed_res = mbedtls_aes_setkey_enc(&c->aes_ctx, key1,
						  key1_len * 8);
	} else {
		c->mbed_mode = MBEDTLS_AES_DECRYPT;
		mbed_res = mbedtls_aes_setkey_dec(&c->aes_ctx, key1,
						  key1_len * 8);
	}

	if (mbed_res)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_aes_ecb_update(struct crypto_cipher_ctx *ctx,
				      bool last_block __unused,
				      const uint8_t *data, size_t len,
				      uint8_t *dst)
{
	struct mbed_aes_ecb_ctx *c = to_aes_ecb_ctx(ctx);
	size_t block_size = TEE_AES_BLOCK_SIZE;
	size_t offs = 0;

	if (len % block_size)
		return TEE_ERROR_BAD_PARAMETERS;

	for (offs = 0; offs < len; offs += block_size) {
		if (mbedtls_aes_crypt_ecb(&c->aes_ctx, c->mbed_mode,
					  data + offs, dst + offs))
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static void mbed_aes_ecb_final(struct crypto_cipher_ctx *ctx)
{
	mbedtls_aes_free(&to_aes_ecb_ctx(ctx)->aes_ctx);
}

static void mbed_aes_ecb_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_aes_ecb_ctx(ctx));
}

static void mbed_aes_ecb_copy_state(struct crypto_cipher_ctx *dst_ctx,
				    struct crypto_cipher_ctx *src_ctx)
{
	struct mbed_aes_ecb_ctx *src = to_aes_ecb_ctx(src_ctx);
	struct mbed_aes_ecb_ctx *dst = to_aes_ecb_ctx(dst_ctx);

	dst->mbed_mode = src->mbed_mode;
	mbed_copy_mbedtls_aes_context(&dst->aes_ctx, &src->aes_ctx);
}

static const struct crypto_cipher_ops mbed_aes_ecb_ops = {
	.init = mbed_aes_ecb_init,
	.update = mbed_aes_ecb_update,
	.final = mbed_aes_ecb_final,
	.free_ctx = mbed_aes_ecb_free_ctx,
	.copy_state = mbed_aes_ecb_copy_state,
};

TEE_Result crypto_aes_ecb_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct mbed_aes_ecb_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &mbed_aes_ecb_ops;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}

#if defined(MBEDTLS_AES_ALT)
int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx, int mode,
			  const unsigned char input[16],
			  unsigned char output[16])

{
	if (mode == MBEDTLS_AES_ENCRYPT)
		crypto_accel_aes_ecb_enc(output, input, ctx->key,
					 ctx->round_count, 1);
	else
		crypto_accel_aes_ecb_dec(output, input, ctx->key,
					 ctx->round_count, 1);

	return 0;
}
#endif /*MBEDTLS_AES_ALT*/
