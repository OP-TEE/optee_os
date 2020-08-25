// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <se050.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

struct se05x_des_cbc_ctx {
	struct crypto_cipher_ctx ctx;
	sss_se05x_symmetric_t des_ctx;
	sss_se05x_object_t key_obj;
	uint8_t *cnt;
	unsigned char iv[TEE_DES_BLOCK_SIZE];
	TEE_OperationMode mode;
};

static const struct crypto_cipher_ops se05x_des_cbc_ops;

static struct se05x_des_cbc_ctx *to_des_cbc_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &se05x_des_cbc_ops);

	return container_of(ctx, struct se05x_des_cbc_ctx, ctx);
}

static TEE_Result se05x_des_cbc_init(struct crypto_cipher_ctx *ctx,
				     TEE_OperationMode mode,
				     const uint8_t *key1,
				     size_t key1_len,
				     const uint8_t *key2 __unused,
				     size_t key2_len __unused,
				     const uint8_t *iv __unused,
				     size_t iv_len  __unused)
{
	struct se05x_des_cbc_ctx *c = to_des_cbc_ctx(ctx);
	sss_status_t st = kStatus_SSS_Success;
	uint32_t oid = 0;

	if (c->key_obj.keyId)
		goto init;

	if (iv_len != sizeof(c->iv))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(c->iv, iv, sizeof(c->iv));
	c->mode = mode;

	st = sss_se05x_key_object_init(&c->key_obj, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	/* DES */
	st = sss_se05x_key_object_allocate_handle(&c->key_obj, oid,
						  kSSS_KeyPart_Default,
						  kSSS_CipherType_DES, 0,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_store_set_key(se050_kstore, &c->key_obj,
					 key1, key1_len,
					 (key1_len * 8), NULL, 0);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_symmetric_context_init(&c->des_ctx, se050_session,
					      &c->key_obj,
					      kAlgorithm_SSS_DES_CBC,
					      mode == TEE_MODE_ENCRYPT ?
					      kMode_SSS_Encrypt :
					      kMode_SSS_Decrypt);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;
init:
	st = sss_se05x_cipher_init(&c->des_ctx, NULL, 0);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result des_crypt_cbc(sss_se05x_symmetric_t *ctx,
				TEE_OperationMode mode, size_t length,
				unsigned char iv[8],
				const unsigned char *input,
				unsigned char *output)
{
	unsigned char temp[8] = { 0 };
	sss_status_t st = kStatus_SSS_Success;
	size_t dst_len = 0;
	int i = 0;

	if (length % 8)
		return TEE_ERROR_BAD_PARAMETERS;

	if (mode == TEE_MODE_ENCRYPT) {
		while (length > 0) {
			dst_len = 8;
			for (i = 0; i < 8; i++)
				output[i] = (unsigned char)(input[i] ^ iv[i]);

			st = se050_cipher_update_nocache(ctx, output, 8,
							 output, &dst_len);
			if (st != kStatus_SSS_Success)
				return TEE_ERROR_GENERIC;

			memcpy(iv, output, 8);
			input  += 8;
			output += 8;
			length -= 8;
		}
	} else {
		while (length > 0) {
			dst_len = 8;
			memcpy(temp, input, 8);

			st = se050_cipher_update_nocache(ctx, input, 8,
							 output, &dst_len);
			if (st != kStatus_SSS_Success)
				return TEE_ERROR_GENERIC;

			for (i = 0; i < 8; i++)
				output[i] = (unsigned char)(output[i] ^ iv[i]);

			memcpy(iv, temp, 8);
			input  += 8;
			output += 8;
			length -= 8;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result se05x_des_cbc_update(struct crypto_cipher_ctx *ctx,
				       bool last_block __unused,
				       const uint8_t *data, size_t len,
				       uint8_t *dst)
{
	struct se05x_des_cbc_ctx *c = to_des_cbc_ctx(ctx);

	return des_crypt_cbc(&c->des_ctx, c->mode, len, c->iv, data, dst);
}

static void se05x_des_cbc_final(struct crypto_cipher_ctx *ctx)
{
	struct se05x_des_cbc_ctx *c = to_des_cbc_ctx(ctx);
	int val = se050_refcount_final_ctx(c->cnt);

	if (!val)
		return;

	if (c->key_obj.keyId)
		sss_se05x_key_store_erase_key(se050_kstore, &c->key_obj);

	sss_se05x_symmetric_context_free(&c->des_ctx);
}

static void se05x_des_cbc_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_des_cbc_ctx(ctx));
}

static void se05x_des_cbc_copy_state(struct crypto_cipher_ctx *dst_ctx,
				     struct crypto_cipher_ctx *src_ctx)
{
	struct se05x_des_cbc_ctx *src = to_des_cbc_ctx(src_ctx);
	struct se05x_des_cbc_ctx *dst = to_des_cbc_ctx(dst_ctx);

	se050_refcount_init_ctx(&src->cnt);
	memcpy(dst, src, sizeof(*dst));
}

static const struct crypto_cipher_ops se05x_des_cbc_ops = {
	.init = se05x_des_cbc_init,
	.update = se05x_des_cbc_update,
	.final = se05x_des_cbc_final,
	.free_ctx = se05x_des_cbc_free_ctx,
	.copy_state = se05x_des_cbc_copy_state,
};

TEE_Result crypto_des_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct se05x_des_cbc_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &se05x_des_cbc_ops;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}
