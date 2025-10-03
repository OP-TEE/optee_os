// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Marvell
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <crypto/internal_aes-gcm.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <initcall.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <util.h>

#include "mrvl_ehsm_cryp.h"

struct mrvl_cipher_ctx {
	struct crypto_cipher_ctx a_ctx;
	struct mrvl_cryp_context cryp_ctx;
	enum mrvl_cryp_algo_mode algo;
};

static struct mrvl_cipher_ctx *to_mrvl_cipher_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx);

	return container_of(ctx, struct mrvl_cipher_ctx, a_ctx);
}

static TEE_Result mrvl_cipher_initialize(struct drvcrypt_cipher_init *dinit)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_cipher_ctx *c = to_mrvl_cipher_ctx(dinit->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;

	mrvl_ehsm_cryp_lock();

	// if already initialized free the previous content and context
	if (ctx->initialized) {
		free(ctx->iv_data);
		free(ctx->key);
		if (ctx->key2)
			free(ctx->key2);

		if (ctx->context_id != 0) {
			ret = mrvl_ehsm_aes_context_release(ctx->context_id);
			if (ret != TEE_SUCCESS)
				goto out;
		}
	}

	ctx->iv_len = dinit->iv.length;
	ctx->iv_data = mem_alloc(ctx->iv_len);
	if (!ctx->iv_data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(ctx->iv_data, dinit->iv.data, ctx->iv_len);

	ctx->op_enc_dec = dinit->encrypt;

	ctx->key_len = dinit->key1.length;
	ctx->key = mem_alloc(ctx->key_len);
	if (!ctx->key) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_key_err;
	}
	memcpy(ctx->key, dinit->key1.data, ctx->key_len);

	if (dinit->key2.length) {
		ctx->key2_len = dinit->key2.length;
		ctx->key2 = mem_alloc(ctx->key2_len);
		if (!ctx->key2) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out_key2_err;
		}
		memcpy(ctx->key2, dinit->key2.data, ctx->key2_len);
	}

	ret = mrvl_ehsm_aes_init(c->algo, ctx->op_enc_dec, (void *)ctx->key,
				 ctx->key_len, (void *)ctx->key2, ctx->key2_len,
				 ctx->iv_data, 0);
	if (ret != TEE_SUCCESS)
		goto out_init_err;

	ret = mrvl_ehsm_aes_context_store(&ctx->context_id);
	if (ret != TEE_SUCCESS)
		goto out_init_err;

	ctx->is_new = true;
	ctx->initialized = true;

	goto out;

out_init_err:
	if (ctx->key2)
		free(ctx->key2);
out_key2_err:
	free(ctx->key);
out_key_err:
	free(ctx->iv_data);
out:
	mrvl_ehsm_cryp_unlock();
	return ret;
}

static TEE_Result mrvl_cipher_update(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_cipher_ctx *c = to_mrvl_cipher_ctx(dupdate->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;
	size_t payload_len = dupdate->src.length;
	size_t dstdata_len = dupdate->dst.length;
	uint8_t *payload_buf = NULL;
	uint8_t *dstdata_buf = NULL;

	mrvl_ehsm_cryp_lock();

	ret = mrvl_ehsm_aes_context_load(ctx->context_id);
	if (ret != TEE_SUCCESS)
		return ret;

	payload_buf = mem_alloc(payload_len);
	if (!payload_buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	dstdata_buf = mem_alloc(dstdata_len);
	if (!dstdata_buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto dstdata_buf_err;
	}

	memcpy(payload_buf, dupdate->src.data, payload_len);

	ret = mrvl_ehsm_aes_update_payload(payload_buf, payload_len,
					   dstdata_buf, dstdata_len,
					   ctx->is_new, dupdate->last);

	if (ret == TEE_SUCCESS)
		memcpy(dupdate->dst.data, dstdata_buf, dstdata_len);

	ctx->is_new = false;

	free(dstdata_buf);
dstdata_buf_err:
	free(payload_buf);
out:
	mrvl_ehsm_cryp_unlock();
	return ret;
}

static void mrvl_cipher_final(void *ctx __unused)
{
}

static void mrvl_cipher_free(void *ctx)
{
	struct mrvl_cipher_ctx *c = to_mrvl_cipher_ctx(ctx);
	struct mrvl_cryp_context *cryp_ctx = &c->cryp_ctx;

	mrvl_ehsm_cryp_lock();
	mrvl_ehsm_aes_context_release(cryp_ctx->context_id);
	mrvl_ehsm_cryp_unlock();

	mrvl_ehsm_aes_cryp_release();

	free(cryp_ctx->iv_data);
	free(cryp_ctx->key);

	if (cryp_ctx->key2)
		free(cryp_ctx->key2);

	free(c);
}

static void mrvl_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct mrvl_cipher_ctx *src = to_mrvl_cipher_ctx(src_ctx);
	struct mrvl_cipher_ctx *dst = to_mrvl_cipher_ctx(dst_ctx);

	memcpy(dst, src, sizeof(*dst));
}

static TEE_Result alloc_ctx(void **ctx, enum mrvl_cryp_algo_mode algo)
{
	struct mrvl_cipher_ctx *c = NULL;

	if (!mrvl_ehsm_aes_cryp_allowed()) {
		DMSG("%s ehsm aes is busy, algo: %x\n", __func__, algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		mrvl_ehsm_aes_cryp_release();
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	c->algo = algo;
	*ctx = &c->a_ctx;

	return TEE_SUCCESS;
}

/*
 * Allocate the SW authenc data context
 *
 * @ctx   [out] Caller context variable
 * @algo  Algorithm ID of the context
 */
static TEE_Result mrvl_cipher_allocate(void **ctx, uint32_t algo)
{
	/*
	 * Convert TEE_ALGO id to internal id
	 */
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		return alloc_ctx(ctx, MRVL_CRYP_MODE_AES_ECB);
	case TEE_ALG_AES_CBC_NOPAD:
		return alloc_ctx(ctx, MRVL_CRYP_MODE_AES_CBC);
	case TEE_ALG_AES_CTR:
		return alloc_ctx(ctx, MRVL_CRYP_MODE_AES_CTR);
	case TEE_ALG_AES_XTS:
		return alloc_ctx(ctx, MRVL_CRYP_MODE_AES_XTS);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/*
 * Registration of the Cipher Driver
 */
static struct drvcrypt_cipher mrvl_cipher = {
	.alloc_ctx = &mrvl_cipher_allocate,
	.update =  &mrvl_cipher_update,
	.free_ctx = &mrvl_cipher_free,
	.init = &mrvl_cipher_initialize,
	.final = &mrvl_cipher_final,
	.copy_state = &mrvl_cipher_copy_state,
};

static TEE_Result mrvl_register_cipher(void)
{
	return drvcrypt_register_cipher(&mrvl_cipher);
}

early_init(mrvl_register_cipher);
