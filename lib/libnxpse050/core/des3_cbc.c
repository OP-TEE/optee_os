// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <crypto/crypto_impl.h>
#include <se050.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

struct se05x_des3_cbc_ctx {
	struct crypto_cipher_ctx ctx;
	sss_se05x_symmetric_t des_ctx;
	sss_se05x_object_t key_obj;
	uint8_t *cnt;
};

static const struct crypto_cipher_ops se05x_des3_cbc_ops;

static struct se05x_des3_cbc_ctx *to_des3_cbc_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &se05x_des3_cbc_ops);

	return container_of(ctx, struct se05x_des3_cbc_ctx, ctx);
}

static TEE_Result se05x_des3_cbc_init(struct crypto_cipher_ctx *ctx,
				      TEE_OperationMode mode,
				      const uint8_t *key1,
				      size_t key1_len,
				      const uint8_t *key2 __unused,
				      size_t key2_len __unused,
				      const uint8_t *iv __unused,
				      size_t iv_len  __unused)
{
	struct se05x_des3_cbc_ctx *c = to_des3_cbc_ctx(ctx);
	sss_status_t st = kStatus_SSS_Success;
	uint32_t oid = 0;

	if (key1_len != 16 && key1_len != 24)
		return TEE_ERROR_BAD_PARAMETERS;
	if (iv_len != 8)
		return TEE_ERROR_BAD_PARAMETERS;

	if (c->key_obj.keyId)
		goto init;

	st = sss_se05x_key_object_init(&c->key_obj, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	/* DES */
	st = sss_se05x_key_object_allocate_handle(&c->key_obj, oid,
						  kSSS_KeyPart_Default,
						  kSSS_CipherType_DES,
						  0,
						 kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_store_set_key(se050_kstore, &c->key_obj, key1,
					 key1_len, (key1_len * 8), NULL, 0);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	/* DES3-CBC */
	st = sss_se05x_symmetric_context_init(&c->des_ctx, se050_session,
					      &c->key_obj,
					      kAlgorithm_SSS_DES3_CBC,
					      mode == TEE_MODE_ENCRYPT ?
					      kMode_SSS_Encrypt :
					      kMode_SSS_Decrypt);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

init:
	st = sss_se05x_cipher_init(&c->des_ctx, (uint8_t *)iv, iv_len);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result se05x_des3_cbc_update(struct crypto_cipher_ctx *ctx,
					bool last_block __unused,
					const uint8_t *data, size_t len,
					uint8_t *dst)
{
	struct se05x_des3_cbc_ctx *c = to_des3_cbc_ctx(ctx);
	size_t dst_len = len;
	sss_status_t st = kStatus_SSS_Success;

	st = sss_se05x_cipher_update(&c->des_ctx, data, len, dst, &dst_len);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static void se05x_des3_cbc_final(struct crypto_cipher_ctx *ctx)
{
	struct se05x_des3_cbc_ctx *c = to_des3_cbc_ctx(ctx);
	int val = 0;

	val = se050_refcount_final_ctx(c->cnt);
	if (!val)
		return;

	if (c->key_obj.keyId)
		sss_se05x_key_store_erase_key(se050_kstore, &c->key_obj);

	sss_se05x_symmetric_context_free(&c->des_ctx);
}

static void se05x_des3_cbc_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_des3_cbc_ctx(ctx));
}

static void se05x_des3_cbc_copy_state(struct crypto_cipher_ctx *dst_ctx,
				      struct crypto_cipher_ctx *src_ctx)
{
	struct se05x_des3_cbc_ctx *src = to_des3_cbc_ctx(src_ctx);
	struct se05x_des3_cbc_ctx *dst = to_des3_cbc_ctx(dst_ctx);

	se050_recount_init_ctx(&src->cnt);
	memcpy(dst, src, sizeof(*dst));
}

static const struct crypto_cipher_ops se05x_des3_cbc_ops = {
	.init = se05x_des3_cbc_init,
	.update = se05x_des3_cbc_update,
	.final = se05x_des3_cbc_final,
	.free_ctx = se05x_des3_cbc_free_ctx,
	.copy_state = se05x_des3_cbc_copy_state,
};

TEE_Result crypto_des3_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct se05x_des3_cbc_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &se05x_des3_cbc_ops;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}
