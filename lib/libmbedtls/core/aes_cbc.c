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

struct mbed_aes_cbc_ctx {
	struct crypto_cipher_ctx ctx;
	int mbed_mode;
	mbedtls_aes_context aes_ctx;
	unsigned char iv[TEE_AES_BLOCK_SIZE];
};

static const struct crypto_cipher_ops mbed_aes_cbc_ops;

static struct mbed_aes_cbc_ctx *to_aes_cbc_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &mbed_aes_cbc_ops);

	return container_of(ctx, struct mbed_aes_cbc_ctx, ctx);
}

static TEE_Result mbed_aes_cbc_init(struct crypto_cipher_ctx *ctx,
				    TEE_OperationMode mode, const uint8_t *key1,
				    size_t key1_len,
				    const uint8_t *key2 __unused,
				    size_t key2_len __unused,
				    const uint8_t *iv, size_t iv_len)
{
	struct mbed_aes_cbc_ctx *c = to_aes_cbc_ctx(ctx);
	int mbed_res = 0;

	if (iv_len != sizeof(c->iv))
		return TEE_ERROR_BAD_PARAMETERS;
	memcpy(c->iv, iv, sizeof(c->iv));

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

static TEE_Result mbed_aes_cbc_update(struct crypto_cipher_ctx *ctx,
				      bool last_block __unused,
				      const uint8_t *data, size_t len,
				      uint8_t *dst)
{
	struct mbed_aes_cbc_ctx *c = to_aes_cbc_ctx(ctx);

	if (mbedtls_aes_crypt_cbc(&c->aes_ctx, c->mbed_mode, len, c->iv,
				  data, dst))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static void mbed_aes_cbc_final(struct crypto_cipher_ctx *ctx)
{
	mbedtls_aes_free(&to_aes_cbc_ctx(ctx)->aes_ctx);
}

static void mbed_aes_cbc_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_aes_cbc_ctx(ctx));
}

static void mbed_aes_cbc_copy_state(struct crypto_cipher_ctx *dst_ctx,
				    struct crypto_cipher_ctx *src_ctx)
{
	struct mbed_aes_cbc_ctx *src = to_aes_cbc_ctx(src_ctx);
	struct mbed_aes_cbc_ctx *dst = to_aes_cbc_ctx(dst_ctx);

	memcpy(dst->iv, src->iv, sizeof(dst->iv));
	dst->mbed_mode = src->mbed_mode;
	mbed_copy_mbedtls_aes_context(&dst->aes_ctx, &src->aes_ctx);
}

static const struct crypto_cipher_ops mbed_aes_cbc_ops = {
	.init = mbed_aes_cbc_init,
	.update = mbed_aes_cbc_update,
	.final = mbed_aes_cbc_final,
	.free_ctx = mbed_aes_cbc_free_ctx,
	.copy_state = mbed_aes_cbc_copy_state,
};

TEE_Result crypto_aes_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct mbed_aes_cbc_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &mbed_aes_cbc_ops;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}

#if defined(MBEDTLS_AES_ALT)
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx, int mode, size_t length,
			  unsigned char iv[16], const unsigned char *input,
			  unsigned char *output)
{
	if (length % 16)
		return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;

	if (mode == MBEDTLS_AES_ENCRYPT)
		crypto_accel_aes_cbc_enc(output, input, ctx->key,
					 ctx->round_count, length / 16, iv);
	else
		crypto_accel_aes_cbc_dec(output, input, ctx->key,
					 ctx->round_count, length / 16, iv);

	return 0;
}
#endif /*MBEDTLS_AES_ALT*/
