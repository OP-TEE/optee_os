// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 * Copyright (C) 2021, SumUp Services GmbH
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

struct mbed_cmac_ctx {
	struct crypto_mac_ctx mac_ctx;
	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_cipher_id_t cipher_id;
};

static const struct crypto_mac_ops mbed_cmac_ops;

static struct mbed_cmac_ctx *to_cmac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx);
	assert(ctx->ops == &mbed_cmac_ops);

	return container_of(ctx, struct mbed_cmac_ctx, mac_ctx);
}

static TEE_Result mbed_cmac_init(struct crypto_mac_ctx *ctx,
				 const uint8_t *key, size_t len)
{
	struct mbed_cmac_ctx *c = to_cmac_ctx(ctx);
	const mbedtls_cipher_info_t *cipher_info = NULL;

	cipher_info = mbedtls_cipher_info_from_values(c->cipher_id,
						      len * 8,
						      MBEDTLS_MODE_ECB);
	if (!cipher_info)
		return TEE_ERROR_NOT_SUPPORTED;

	if (mbedtls_cipher_setup_info(&c->cipher_ctx, cipher_info))
		return TEE_ERROR_BAD_STATE;

	if (mbedtls_cipher_cmac_reset(&c->cipher_ctx))
		return TEE_ERROR_BAD_STATE;

	if (mbedtls_cipher_cmac_starts(&c->cipher_ctx, key, len * 8))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_cmac_update(struct crypto_mac_ctx *ctx,
				   const uint8_t *data, size_t len)
{
	struct mbed_cmac_ctx *c = to_cmac_ctx(ctx);

	if (mbedtls_cipher_cmac_update(&c->cipher_ctx, data, len))
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_cmac_final(struct crypto_mac_ctx *ctx,
				  uint8_t *digest, size_t len)
{
	struct mbed_cmac_ctx *c = to_cmac_ctx(ctx);
	size_t block_size = TEE_AES_BLOCK_SIZE;
	uint8_t block_digest[TEE_AES_BLOCK_SIZE] = { };
	uint8_t *tmp_digest = NULL;

	COMPILE_TIME_ASSERT(TEE_AES_BLOCK_SIZE >= TEE_DES_BLOCK_SIZE);

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (c->cipher_id == MBEDTLS_CIPHER_ID_3DES)
		block_size = TEE_DES_BLOCK_SIZE;

	if (len < block_size)
		tmp_digest = block_digest; /* use a tempory buffer */
	else
		tmp_digest = digest;

	if (mbedtls_cipher_cmac_finish(&c->cipher_ctx, tmp_digest))
		return TEE_ERROR_BAD_STATE;

	if (len < block_size)
		memcpy(digest, tmp_digest, len);

	return TEE_SUCCESS;
}

static void mbed_cmac_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct mbed_cmac_ctx *c = to_cmac_ctx(ctx);

	mbedtls_cipher_free(&c->cipher_ctx);
	free(c);
}

static void mbed_cmac_copy_state(struct crypto_mac_ctx *dst_ctx,
				 struct crypto_mac_ctx *src_ctx)
{
	struct mbed_cmac_ctx *src = to_cmac_ctx(src_ctx);
	struct mbed_cmac_ctx *dst = to_cmac_ctx(dst_ctx);

	if (mbedtls_cipher_clone(&dst->cipher_ctx, &src->cipher_ctx))
		panic();
}

static const struct crypto_mac_ops mbed_cmac_ops = {
	.init = mbed_cmac_init,
	.update = mbed_cmac_update,
	.final = mbed_cmac_final,
	.free_ctx = mbed_cmac_free_ctx,
	.copy_state = mbed_cmac_copy_state,
};

static TEE_Result crypto_cmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret,
					const mbedtls_cipher_id_t cipher_id,
					int key_bitlen)
{
	int mbed_res = 0;
	struct mbed_cmac_ctx *c = NULL;
	const mbedtls_cipher_info_t *cipher_info = NULL;

	/*
	 * Use a default key length for getting 'cipher_info' to do the
	 * setup. The 'cipher_info' will need to be re-assigned with final
	 * key length obtained in mbed_cmac_init() above.
	 *
	 * This is safe since 'mbedtls_cipher_base_t' (used for cipher
	 * context) uses the same fixed allocation all key lengths.
	 */
	cipher_info = mbedtls_cipher_info_from_values(cipher_id, key_bitlen,
						      MBEDTLS_MODE_ECB);
	if (!cipher_info)
		return TEE_ERROR_NOT_SUPPORTED;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->cipher_id = cipher_id;
	c->mac_ctx.ops = &mbed_cmac_ops;

	mbedtls_cipher_init(&c->cipher_ctx);
	mbed_res = mbedtls_cipher_setup(&c->cipher_ctx, cipher_info);
	if (mbed_res) {
		free(c);
		if (mbed_res == MBEDTLS_ERR_CIPHER_ALLOC_FAILED)
			return TEE_ERROR_OUT_OF_MEMORY;
		return TEE_ERROR_NOT_SUPPORTED;
	}
	mbed_res = mbedtls_cipher_cmac_setup(&c->cipher_ctx);
	if (mbed_res) {
		free(c);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	*ctx_ret = &c->mac_ctx;

	return TEE_SUCCESS;
}

TEE_Result crypto_des3_cmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret)
{
	return crypto_cmac_alloc_ctx(ctx_ret, MBEDTLS_CIPHER_ID_3DES, 192);
}

TEE_Result crypto_aes_cmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret)
{
	return crypto_cmac_alloc_ctx(ctx_ret, MBEDTLS_CIPHER_ID_AES, 128);
}
