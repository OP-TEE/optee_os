// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <mbedtls/aes.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

struct mbed_aes_ctr_ctx {
	struct crypto_cipher_ctx ctx;
	mbedtls_aes_context aes_ctx;
	size_t nc_off;
	unsigned char counter[TEE_AES_BLOCK_SIZE];
	unsigned char block[TEE_AES_BLOCK_SIZE];
};

static const struct crypto_cipher_ops mbed_aes_ctr_ops;

static struct mbed_aes_ctr_ctx *to_aes_ctr_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &mbed_aes_ctr_ops);

	return container_of(ctx, struct mbed_aes_ctr_ctx, ctx);
}

static TEE_Result mbed_aes_ctr_init(struct crypto_cipher_ctx *ctx,
				    TEE_OperationMode mode __unused,
				    const uint8_t *key1, size_t key1_len,
				    const uint8_t *key2 __unused,
				    size_t key2_len __unused,
				    const uint8_t *iv, size_t iv_len)
{
	struct mbed_aes_ctr_ctx *c = to_aes_ctr_ctx(ctx);

	if (iv_len != sizeof(c->counter))
		return TEE_ERROR_BAD_PARAMETERS;
	memcpy(c->counter, iv, sizeof(c->counter));

	mbedtls_aes_init(&c->aes_ctx);
	c->nc_off = 0;

	if (mbedtls_aes_setkey_enc(&c->aes_ctx, key1, key1_len * 8))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_aes_ctr_update(struct crypto_cipher_ctx *ctx,
				      bool last_block __unused,
				      const uint8_t *data, size_t len,
				      uint8_t *dst)
{
	struct mbed_aes_ctr_ctx *c = to_aes_ctr_ctx(ctx);

	if (mbedtls_aes_crypt_ctr(&c->aes_ctx, len, &c->nc_off, c->counter,
				   c->block, data, dst))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static void mbed_aes_ctr_final(struct crypto_cipher_ctx *ctx)
{
	struct mbed_aes_ctr_ctx *c = to_aes_ctr_ctx(ctx);

	mbedtls_aes_free(&c->aes_ctx);
	memset(c->block, 0, sizeof(c->block));
}

static void mbed_aes_ctr_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_aes_ctr_ctx(ctx));
}

static void mbed_aes_ctr_copy_state(struct crypto_cipher_ctx *dst_ctx,
				    struct crypto_cipher_ctx *src_ctx)
{
	struct mbed_aes_ctr_ctx *src = to_aes_ctr_ctx(src_ctx);
	struct mbed_aes_ctr_ctx *dst = to_aes_ctr_ctx(dst_ctx);

	memcpy(dst->counter, src->counter, sizeof(dst->counter));
	memcpy(dst->block, src->block, sizeof(dst->block));
	dst->nc_off = src->nc_off;
	dst->aes_ctx = src->aes_ctx;
}

static const struct crypto_cipher_ops mbed_aes_ctr_ops = {
	.init = mbed_aes_ctr_init,
	.update = mbed_aes_ctr_update,
	.final = mbed_aes_ctr_final,
	.free_ctx = mbed_aes_ctr_free_ctx,
	.copy_state = mbed_aes_ctr_copy_state,
};

TEE_Result crypto_aes_ctr_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct mbed_aes_ctr_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &mbed_aes_ctr_ops;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}
