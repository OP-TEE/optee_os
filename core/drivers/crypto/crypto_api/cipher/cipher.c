// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Crypto Cipher interface implementation to enable HW driver.
 */
#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <util.h>

static const struct crypto_cipher_ops cipher_ops;

/*
 * Returns the reference to the driver context
 *
 * @ctx    Reference the API context pointer
 */
static struct crypto_cipher *to_cipher_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &cipher_ops);

	return container_of(ctx, struct crypto_cipher, cipher_ctx);
}

/*
 * Free cipher context
 *
 * @ctx    Reference the API context pointer
 */
static void cipher_free_ctx(struct crypto_cipher_ctx *ctx)
{
	struct crypto_cipher *cipher = to_cipher_ctx(ctx);

	if (cipher->op && cipher->op->free_ctx)
		cipher->op->free_ctx(cipher->ctx);

	free(cipher);
}

/*
 * Copy cipher context
 *
 * @dst_ctx  [out] Reference the API context pointer destination
 * @src_ctx  Reference the API context pointer source
 */
static void cipher_copy_state(struct crypto_cipher_ctx *dst_ctx,
			      struct crypto_cipher_ctx *src_ctx)
{
	struct crypto_cipher *cipher_src = to_cipher_ctx(src_ctx);
	struct crypto_cipher *cipher_dst = to_cipher_ctx(dst_ctx);

	if (cipher_src->op && cipher_src->op->copy_state)
		cipher_src->op->copy_state(cipher_dst->ctx, cipher_src->ctx);
}

/*
 * Initialization of the cipher operation
 *
 * @ctx      Reference the API context pointer
 * @mode     Operation mode
 * @key1     First Key
 * @key1_len Length of the first key
 * @key2     Second Key
 * @key2_len Length of the second key
 * @iv       Initial Vector
 * @iv_len   Length of the IV
 */
static TEE_Result cipher_init(struct crypto_cipher_ctx *ctx,
			      TEE_OperationMode mode, const uint8_t *key1,
			      size_t key1_len, const uint8_t *key2,
			      size_t key2_len, const uint8_t *iv, size_t iv_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_cipher *cipher = to_cipher_ctx(ctx);

	if ((!key1 && key1_len) || (!key2 && key2_len) || (!iv && iv_len)) {
		CRYPTO_TRACE("One of the key is not correct");
		CRYPTO_TRACE("key1 @%p-%zu bytes", key1, key1_len);
		CRYPTO_TRACE("key2 @%p-%zu bytes", key1, key1_len);
		CRYPTO_TRACE("iv   @%p-%zu bytes", iv, iv_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cipher->op && cipher->op->init) {
		struct drvcrypt_cipher_init dinit = {
			.ctx = cipher->ctx,
			.encrypt = (mode == TEE_MODE_ENCRYPT),
			.key1.data = (uint8_t *)key1,
			.key1.length = key1_len,
			.key2.data = (uint8_t *)key2,
			.key2.length = key2_len,
			.iv.data = (uint8_t *)iv,
			.iv.length = iv_len,
		};

		ret = cipher->op->init(&dinit);
	}

	CRYPTO_TRACE("cipher ret 0x%" PRIX32, ret);
	return ret;
}

/*
 * Update of the cipher operation
 *
 * @ctx        Reference the API context pointer
 * @last_block True if last block to handle
 * @data       Data to encrypt/decrypt
 * @len        Length of the input data and output result
 * @dst        [out] Output data of the operation
 */
static TEE_Result cipher_update(struct crypto_cipher_ctx *ctx, bool last_block,
				const uint8_t *data, size_t len, uint8_t *dst)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_cipher *cipher = to_cipher_ctx(ctx);

	if (!dst) {
		CRYPTO_TRACE("Destination buffer error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!data && len) {
		CRYPTO_TRACE("Bad data data @%p-%zu bytes", data, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cipher->op && cipher->op->update) {
		struct drvcrypt_cipher_update dupdate = {
			.ctx = cipher->ctx,
			.last = last_block,
			.src.data = (uint8_t *)data,
			.src.length = len,
			.dst.data = dst,
			.dst.length = len,
		};

		ret = cipher->op->update(&dupdate);
	}

	CRYPTO_TRACE("cipher ret 0x%" PRIX32, ret);
	return ret;
}

/*
 * Finalize the cipher operation
 *
 * @ctx   Reference the API context pointer
 */
static void cipher_final(struct crypto_cipher_ctx *ctx)
{
	struct crypto_cipher *cipher = to_cipher_ctx(ctx);

	if (cipher->op && cipher->op->final)
		cipher->op->final(cipher->ctx);
}

static const struct crypto_cipher_ops cipher_ops = {
	.init = cipher_init,
	.update = cipher_update,
	.final = cipher_final,
	.free_ctx = cipher_free_ctx,
	.copy_state = cipher_copy_state,
};

TEE_Result drvcrypt_cipher_alloc_ctx(struct crypto_cipher_ctx **ctx,
				     uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_cipher *cipher = NULL;

	CRYPTO_TRACE("Cipher alloc_ctx algo 0x%" PRIX32, algo);

	assert(ctx);

	cipher = calloc(1, sizeof(*cipher));
	if (!cipher)
		return TEE_ERROR_OUT_OF_MEMORY;

	cipher->op = drvcrypt_get_ops(CRYPTO_CIPHER);
	if (cipher->op && cipher->op->alloc_ctx)
		ret = cipher->op->alloc_ctx(&cipher->ctx, algo);

	if (ret != TEE_SUCCESS) {
		free(cipher);
	} else {
		cipher->cipher_ctx.ops = &cipher_ops;
		*ctx = &cipher->cipher_ctx;
	}

	CRYPTO_TRACE("Cipher alloc_ctx ret 0x%" PRIX32, ret);

	return ret;
}
