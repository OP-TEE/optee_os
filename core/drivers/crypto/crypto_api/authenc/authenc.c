// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 *
 * Crypto authenc interface implementation to enable HW driver.
 */
#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <utee_defines.h>
#include <util.h>

static const struct crypto_authenc_ops authenc_ops;

/*
 * Returns the reference to the driver context
 *
 * @ctx    Reference the API context pointer
 */
static struct crypto_authenc *to_authenc_ctx(struct crypto_authenc_ctx *ctx)
{
	assert(ctx && ctx->ops == &authenc_ops);

	return container_of(ctx, struct crypto_authenc, authenc_ctx);
}

/*
 * Free authenc context
 *
 * @ctx    Reference the API context pointer
 */
static void authenc_free_ctx(struct crypto_authenc_ctx *ctx)
{
	struct crypto_authenc *authenc = to_authenc_ctx(ctx);

	if (authenc->op && authenc->op->free_ctx)
		authenc->op->free_ctx(authenc->ctx);

	free(authenc);
}

/*
 * Copy authenc context
 *
 * @dst_ctx  [out] Reference the API context pointer destination
 * @src_ctx  Reference the API context pointer source
 */
static void authenc_copy_state(struct crypto_authenc_ctx *dst_ctx,
			       struct crypto_authenc_ctx *src_ctx)
{
	struct crypto_authenc *authenc_src = to_authenc_ctx(src_ctx);
	struct crypto_authenc *authenc_dst = to_authenc_ctx(dst_ctx);

	if (authenc_src->op && authenc_src->op->copy_state)
		authenc_src->op->copy_state(authenc_dst->ctx, authenc_src->ctx);
}

/*
 * Initialization of the authenc operation
 *
 * @ctx         Reference the API context pointer
 * @mode        Operation mode
 * @key         Key
 * @key_len     Length of the key
 * @nonce       Nonce
 * @nonce_len   Length of the nonce
 * @tag_len     Length of the requested tag
 * @aad_len     Length of the associated authenticated data
 * @payload_len Length of payload
 */
static TEE_Result authenc_init(struct crypto_authenc_ctx *ctx,
			       TEE_OperationMode mode, const uint8_t *key,
			       size_t key_len, const uint8_t *nonce,
			       size_t nonce_len, size_t tag_len, size_t aad_len,
			       size_t payload_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_authenc *authenc = to_authenc_ctx(ctx);

	if ((!key && key_len) || (!nonce && nonce_len)) {
		CRYPTO_TRACE("One of the key is not correct");
		CRYPTO_TRACE("key   @%p-%zu bytes", key, key_len);
		CRYPTO_TRACE("nonce @%p-%zu bytes", nonce, nonce_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op && authenc->op->init) {
		struct drvcrypt_authenc_init dinit = {
			.ctx = authenc->ctx,
			.encrypt = (mode == TEE_MODE_ENCRYPT),
			.key.data = (uint8_t *)key,
			.key.length = key_len,
			.nonce.data = (uint8_t *)nonce,
			.nonce.length = nonce_len,
			.tag_len = tag_len,
			.aad_len = aad_len,
			.payload_len = payload_len,
		};

		ret = authenc->op->init(&dinit);
	}

	CRYPTO_TRACE("authenc ret 0x%" PRIx32, ret);
	return ret;
}

/*
 * Update Additional Authenticated Data part of the authenc operation
 *
 * @ctx        Reference the API context pointer
 * @data       Data to authenticate without encrypt/decrypt (AAD)
 * @len        AAD length in bytes
 */
static TEE_Result authenc_update_aad(struct crypto_authenc_ctx *ctx,
				     const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_authenc *authenc = to_authenc_ctx(ctx);

	if (!data && len) {
		CRYPTO_TRACE("Bad data @%p-%zu bytes", data, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op && authenc->op->update_aad) {
		struct drvcrypt_authenc_update_aad dupdate = {
			.ctx = authenc->ctx,
			.aad.data = (uint8_t *)data,
			.aad.length = len,
		};

		ret = authenc->op->update_aad(&dupdate);
	}

	CRYPTO_TRACE("authenc ret 0x%" PRIx32, ret);
	return ret;
}

/*
 * Update payload part of the authenc operation
 *
 * @ctx        Reference the API context pointer
 * @data       Data to authenticate and encrypt/decrypt
 * @len        Length of the input data and output result
 * @dst        [out] Output data of the operation
 */
static TEE_Result authenc_update_payload(struct crypto_authenc_ctx *ctx,
					 TEE_OperationMode mode,
					 const uint8_t *data,
					 size_t len, uint8_t *dst)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_authenc *authenc = to_authenc_ctx(ctx);

	if (!dst) {
		CRYPTO_TRACE("Destination buffer error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!data && len) {
		CRYPTO_TRACE("Bad data @%p-%zu bytes", data, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op && authenc->op->update_payload) {
		struct drvcrypt_authenc_update_payload dupdate = {
			.ctx = authenc->ctx,
			.encrypt = (mode == TEE_MODE_ENCRYPT),
			.src.data = (uint8_t *)data,
			.src.length = len,
			.dst.data = dst,
			.dst.length = len,
		};

		ret = authenc->op->update_payload(&dupdate);
	}

	CRYPTO_TRACE("authenc ret 0x%" PRIx32, ret);
	return ret;
}

/*
 * Last block for the authenc encrypt and get tag operation
 *
 * @ctx     Reference the API context pointer
 * @data    Data to authenticate and encrypt (can be NULL)
 * @len     Length of the input data and output result (can be 0)
 * @dst     [out] Output data of the operation
 * @tag     [out] Output tag of the operation
 * @tag_len [in/out] in: size of the dst_tag buffer
 *                  out: size of the computed tag
 */
static TEE_Result authenc_enc_final(struct crypto_authenc_ctx *ctx,
				    const uint8_t *data, size_t len,
				    uint8_t *dst, uint8_t *tag,
				    size_t *tag_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_authenc *authenc = to_authenc_ctx(ctx);

	if (!dst && len) {
		CRYPTO_TRACE("Bad output @%p-%zu bytes", dst, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!data && len) {
		CRYPTO_TRACE("Bad input @%p-%zu bytes", data, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op && authenc->op->enc_final) {
		struct drvcrypt_authenc_final dfinal = {
			.ctx = authenc->ctx,
			.src.data = (uint8_t *)data,
			.src.length = len,
			.dst.data = dst,
			.dst.length = len,
			.tag.data = tag,
			.tag.length = *tag_len
		};

		ret = authenc->op->enc_final(&dfinal);
		if (ret == TEE_SUCCESS)
			*tag_len = dfinal.tag.length;
	}

	CRYPTO_TRACE("authenc ret 0x%" PRIx32, ret);
	return ret;
}

/*
 * Last block for the authenc decrypt and check tag operation
 *
 * @ctx         Reference the API context pointer
 * @src_data    Data to authenticate and encrypt (can be NULL)
 * @len         Length of the input data and output result (can be 0)
 * @dst         [out] Output data of the operation
 * @tag         Tag to check at end of operation
 * @tag_len     Length of @tag
 */
static TEE_Result authenc_dec_final(struct crypto_authenc_ctx *ctx,
				    const uint8_t *data, size_t len,
				    uint8_t *dst, const uint8_t *tag,
				    size_t tag_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_authenc *authenc = to_authenc_ctx(ctx);

	if (!dst && len) {
		CRYPTO_TRACE("Bad output @%p-%zu bytes", dst, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!data && len) {
		CRYPTO_TRACE("Bad data @%p-%zu bytes", data, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op && authenc->op->dec_final) {
		struct drvcrypt_authenc_final dfinal = {
			.ctx = authenc->ctx,
			.src.data = (uint8_t *)data,
			.src.length = len,
			.dst.data = dst,
			.dst.length = len,
			.tag.data = (uint8_t *)tag,
			.tag.length = tag_len
		};

		ret = authenc->op->dec_final(&dfinal);
	}

	CRYPTO_TRACE("authenc ret 0x%" PRIx32, ret);
	return ret;
}

/*
 * Finalize the authenc operation
 *
 * @ctx   Reference the API context pointer
 */
static void authenc_final(struct crypto_authenc_ctx *ctx)
{
	struct crypto_authenc *authenc = to_authenc_ctx(ctx);

	if (authenc->op && authenc->op->final)
		authenc->op->final(authenc->ctx);
}

static const struct crypto_authenc_ops authenc_ops = {
	.init = authenc_init,
	.update_aad = authenc_update_aad,
	.update_payload = authenc_update_payload,
	.enc_final = authenc_enc_final,
	.dec_final = authenc_dec_final,
	.final = authenc_final,
	.free_ctx = authenc_free_ctx,
	.copy_state = authenc_copy_state,
};

TEE_Result drvcrypt_authenc_alloc_ctx(struct crypto_authenc_ctx **ctx,
				      uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_authenc *authenc = NULL;

	CRYPTO_TRACE("authenc alloc_ctx algo 0x%" PRIx32, algo);

	assert(ctx);

	authenc = calloc(1, sizeof(*authenc));
	if (!authenc)
		return TEE_ERROR_OUT_OF_MEMORY;

	authenc->op = drvcrypt_get_ops(CRYPTO_AUTHENC);
	if (authenc->op && authenc->op->alloc_ctx)
		ret = authenc->op->alloc_ctx(&authenc->ctx, algo);

	if (ret != TEE_SUCCESS) {
		free(authenc);
	} else {
		authenc->authenc_ctx.ops = &authenc_ops;
		*ctx = &authenc->authenc_ctx;
	}

	CRYPTO_TRACE("authenc alloc_ctx ret 0x%" PRIx32, ret);
	return ret;
}
