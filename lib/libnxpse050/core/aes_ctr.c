// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <crypto/crypto_impl.h>
#include <se050.h>
#include <string.h>
#include <utee_defines.h>
#include <util.h>

struct se050_aes_ctr_ctx {
	struct crypto_cipher_ctx ctx;
	sss_se05x_symmetric_t aes_ctx;
	sss_se05x_object_t key_obj;
	uint8_t *cnt;
	int nc_off;
	unsigned char counter[TEE_AES_BLOCK_SIZE];
	unsigned char block[TEE_AES_BLOCK_SIZE];
};

static const struct crypto_cipher_ops se050_aes_ctr_ops;

static struct se050_aes_ctr_ctx *to_aes_ctr_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &se050_aes_ctr_ops);

	return container_of(ctx, struct se050_aes_ctr_ctx, ctx);
}

static TEE_Result se050_aes_ctr_init(struct crypto_cipher_ctx *ctx,
				     TEE_OperationMode mode __unused,
				     const uint8_t *key1,
				     size_t key1_len,
				     const uint8_t *key2 __unused,
				     size_t key2_len __unused,
				     const uint8_t *iv, size_t iv_len __unused)
{
	struct se050_aes_ctr_ctx *c = to_aes_ctr_ctx(ctx);
	sss_status_t st = kStatus_SSS_Success;
	uint32_t oid = 0;

	if (c->key_obj.keyId)
		goto init;

	memcpy(c->counter, iv, sizeof(c->counter));

	st = sss_se05x_key_object_init(&c->key_obj, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	/* AES */
	st = sss_se05x_key_object_allocate_handle(&c->key_obj, oid,
						  kSSS_KeyPart_Default,
						  kSSS_CipherType_AES, 0,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_store_set_key(se050_kstore, &c->key_obj,
					 key1, key1_len,
					 (key1_len * 8), NULL, 0);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	/* AES-CTR: implement OP-TEE API workaround via ECB */
	st = sss_se05x_symmetric_context_init(&c->aes_ctx, se050_session,
					      &c->key_obj,
					      kAlgorithm_SSS_AES_ECB,
					      kMode_SSS_Encrypt);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;
init:
	st = sss_se05x_cipher_init(&c->aes_ctx, (uint8_t *)NULL, 0);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result se050_aes_ctr_update(struct crypto_cipher_ctx *ctx,
				       bool last_block __unused,
				       const uint8_t *data, size_t len,
				       uint8_t *dst)
{
	struct se050_aes_ctr_ctx *c = to_aes_ctr_ctx(ctx);
	size_t dst_len = len;
	sss_status_t st = kStatus_SSS_Success;
	int i = 0, n = 0, j = 0;

	n = c->nc_off;

	/*
	 * work around to cope with the current imposibility of not returning
	 * the expected amount of data back to the caller
	 */
	while (len--) {
		dst_len = sizeof(c->counter);
		if (n == 0) {
			st = sss_se05x_cipher_update(&c->aes_ctx,
						     c->counter, 16,
						     c->block, &dst_len);
			if (st != kStatus_SSS_Success)
				return TEE_ERROR_BAD_STATE;

			for (i = 16; i > 0; i--)
				if (++c->counter[i - 1] != 0)
					break;
		}
		j = *data++;
		*dst++ = (unsigned char)(j ^ c->block[n]);
		n = (n + 1) & 0x0F;
	}

	c->nc_off = n;

	return TEE_SUCCESS;
}

static void se050_aes_ctr_final(struct crypto_cipher_ctx *ctx)
{
	struct se050_aes_ctr_ctx *c = to_aes_ctr_ctx(ctx);
	int val;

	val = se050_refcount_final_ctx(c->cnt);
	if (!val) {
		memset(c->block, 0, sizeof(c->block));
		return;
	}

	if (c->key_obj.keyId)
		sss_se05x_key_store_erase_key(se050_kstore, &c->key_obj);

	sss_se05x_symmetric_context_free(&c->aes_ctx);
}

static void se050_aes_ctr_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_aes_ctr_ctx(ctx));
}

static void se050_aes_ctr_copy_state(struct crypto_cipher_ctx *dst_ctx,
				     struct crypto_cipher_ctx *src_ctx)
{
	struct se050_aes_ctr_ctx *src = to_aes_ctr_ctx(src_ctx);
	struct se050_aes_ctr_ctx *dst = to_aes_ctr_ctx(dst_ctx);

	se050_refcount_init_ctx(&src->cnt);
	memcpy(dst, src, sizeof(*dst));
}

static const struct crypto_cipher_ops se050_aes_ctr_ops = {
	.init = se050_aes_ctr_init,
	.update = se050_aes_ctr_update,
	.final = se050_aes_ctr_final,
	.free_ctx = se050_aes_ctr_free_ctx,
	.copy_state = se050_aes_ctr_copy_state,
};

TEE_Result crypto_aes_ctr_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct se050_aes_ctr_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &se050_aes_ctr_ops;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}
