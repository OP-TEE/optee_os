// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Marvell
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <crypto/internal_aes-gcm.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <initcall.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <util.h>

#include "mrvl_ehsm_cryp.h"

struct mrvl_ae_ctx {
	struct crypto_authenc_ctx a_ctx;
	struct mrvl_cryp_context cryp_ctx;
};

static struct mrvl_ae_ctx *to_mrvl_ae_ctx(struct crypto_authenc_ctx *ctx)
{
	assert(ctx);

	return container_of(ctx, struct mrvl_ae_ctx, a_ctx);
}

static TEE_Result mrvl_ae_initialize(struct drvcrypt_authenc_init *dinit)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(dinit->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;

	mrvl_ehsm_cryp_lock();

	ctx->iv_len = dinit->nonce.length;
	ctx->iv_data = mem_alloc(ctx->iv_len);
	if (!ctx->iv_data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(ctx->iv_data, dinit->nonce.data, ctx->iv_len);

	ctx->aad_len = dinit->aad_len;
	ctx->aad_cur_idx = 0;
	ctx->aad_data = mem_alloc(ctx->aad_len);
	if (!ctx->aad_data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_aad_err;
	}

	ctx->op_enc_dec = dinit->encrypt;
	ctx->tag_len = dinit->tag_len;

	ctx->key_len = dinit->key.length;
	ctx->key = mem_alloc(ctx->key_len);
	if (!ctx->key) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_key_err;
	}
	memcpy(ctx->key, dinit->key.data, ctx->key_len);

	ret = mrvl_ehsm_aes_gcm_init(ctx->op_enc_dec, (void *)ctx->key,
				     ctx->key_len, ctx->aad_len,
				     ctx->tag_len, ctx->iv_len,
				     ctx->iv_data, 0);
	if (ret != TEE_SUCCESS)
		goto out_init_err;

	ret = mrvl_ehsm_aes_context_store(&ctx->context_id);
	if (ret != TEE_SUCCESS)
		goto out_init_err;

	ctx->is_new = true;

	goto out;

out_init_err:
	free(ctx->key);
out_key_err:
	free(ctx->aad_data);
out_aad_err:
	free(ctx->iv_data);
out:
	mrvl_ehsm_cryp_unlock();
	return ret;
}

static TEE_Result
mrvl_ae_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(dupdate->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;

	if ((dupdate->aad.length + ctx->aad_cur_idx) <= ctx->aad_len) {
		memcpy(ctx->aad_data + ctx->aad_cur_idx, dupdate->aad.data,
		       dupdate->aad.length);
		ctx->aad_cur_idx += dupdate->aad.length;
	} else {
		ret = TEE_ERROR_BAD_PARAMETERS;
	}

	return ret;
}

static TEE_Result
mrvl_ae_update_payload(struct drvcrypt_authenc_update_payload *dupdate)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(dupdate->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;
	uint8_t *payload_buf = NULL;
	uint8_t *encdata_buf = NULL;
	size_t payload_buf_len = 0;
	size_t encdata_buf_len = 0;
	uint32_t context_id = 0;
	size_t iv = 0;

#if defined(PLATFORM_FLAVOR_cn10ka) || defined(PLATFORM_FLAVOR_cn10kb) || \
	defined(PLATFORM_FLAVOR_cnf10ka) || defined(PLATFORM_FLAVOR_cnf10kb)
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif
	mrvl_ehsm_cryp_lock();

	ret = mrvl_ehsm_aes_context_load(ctx->context_id);
	if (ret != TEE_SUCCESS)
		return ret;

	if (ctx->is_new) {
		/* IV is not 12-byte, load IV part of AES operation payload */
		if (ctx->iv_len != 12)
			iv = ctx->iv_len;
		else
			iv = 0;

		payload_buf_len = iv + ctx->aad_len + dupdate->src.length;

		payload_buf = mem_alloc(payload_buf_len);
		if (!payload_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		encdata_buf_len = iv + ctx->aad_len + dupdate->dst.length;

		encdata_buf = mem_alloc(encdata_buf_len);
		if (!encdata_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out_enc_buf_err;
		}

		if (ctx->iv_len != 12)
			memcpy(payload_buf, ctx->iv_data, iv);

		memcpy(payload_buf + iv, ctx->aad_data, ctx->aad_cur_idx);
		memcpy(payload_buf + iv + ctx->aad_cur_idx, dupdate->src.data,
		       dupdate->src.length);

		ret = mrvl_ehsm_aes_gcm_update_payload(payload_buf,
						       dupdate->src.length,
						       encdata_buf,
						       dupdate->dst.length,
						       ctx->is_new);

		if (ret == TEE_SUCCESS)
			memcpy(dupdate->dst.data, encdata_buf + iv +
			       ctx->aad_cur_idx, dupdate->dst.length);

		ctx->is_new = false;

		context_id = ctx->context_id;
		ret = mrvl_ehsm_aes_context_store(&ctx->context_id);
		if (ret != TEE_SUCCESS)
			goto out_ctx_err;

		ret = mrvl_ehsm_aes_context_release(context_id);
		if (ret != TEE_SUCCESS)
			goto out_ctx_err;

	} else {
		payload_buf = mem_alloc(dupdate->src.length);
		if (!payload_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		encdata_buf = mem_alloc(dupdate->dst.length);
		if (!encdata_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out_enc_buf_err;
		}

		memcpy(payload_buf, dupdate->src.data, dupdate->src.length);

		ret = mrvl_ehsm_aes_gcm_update_payload(payload_buf,
						       dupdate->src.length,
						       encdata_buf,
						       dupdate->dst.length,
						       ctx->is_new);

		if (ret == TEE_SUCCESS)
			memcpy(dupdate->dst.data, encdata_buf,
			       dupdate->dst.length);
	}

out_ctx_err:
	free(encdata_buf);
out_enc_buf_err:
	free(payload_buf);
out:
	mrvl_ehsm_cryp_unlock();
	return ret;
}

static TEE_Result mrvl_ae_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(dfinal->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;
	uint8_t *payload_buf = NULL;
	uint8_t	*encdata_buf = NULL;
	size_t payload_buf_len = 0;
	size_t encdata_buf_len = 0;
	size_t iv = 0;

	mrvl_ehsm_cryp_lock();

	ret = mrvl_ehsm_aes_context_load(ctx->context_id);
	if (ret != TEE_SUCCESS)
		return ret;

	if (ctx->is_new) {
		/* IV is not 12-byte, load IV part of AES operation payload */
		if (ctx->iv_len != 12)
			iv = ctx->iv_len;
		else
			iv = 0;

		payload_buf_len = iv + ctx->aad_len + dfinal->src.length;

		payload_buf = mem_alloc(payload_buf_len);
		if (!payload_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		encdata_buf_len = iv + ctx->aad_len + dfinal->dst.length +
				  dfinal->tag.length;

		encdata_buf = mem_alloc(encdata_buf_len);
		if (!encdata_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out_enc_buf_err;
		}

		if (ctx->iv_len != 12)
			memcpy(payload_buf, ctx->iv_data, iv);

		memcpy(payload_buf + iv, ctx->aad_data, ctx->aad_cur_idx);
		memcpy(payload_buf + iv + ctx->aad_cur_idx, dfinal->src.data,
		       dfinal->src.length);

		ret = mrvl_ehsm_aes_gcm_final(payload_buf, dfinal->src.length,
					      encdata_buf, dfinal->dst.length,
					      ctx->is_new);

		if (ret == TEE_SUCCESS) {
			memcpy(dfinal->dst.data, encdata_buf + iv +
			       ctx->aad_cur_idx, dfinal->dst.length);
			memcpy(dfinal->tag.data, encdata_buf + iv +
			       ctx->aad_cur_idx + dfinal->dst.length,
			       dfinal->tag.length);
		}

	} else {
		payload_buf_len = dfinal->src.length;

		payload_buf = mem_alloc(payload_buf_len);
		if (!payload_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		encdata_buf_len = dfinal->dst.length + dfinal->tag.length;

		encdata_buf = mem_alloc(encdata_buf_len);
		if (!encdata_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out_enc_buf_err;
		}

		memcpy(payload_buf, dfinal->src.data, dfinal->src.length);

		ret = mrvl_ehsm_aes_gcm_final(payload_buf, dfinal->src.length,
					      encdata_buf, dfinal->dst.length,
					      ctx->is_new);

		if (ret == TEE_SUCCESS) {
			memcpy(dfinal->dst.data, encdata_buf,
			       dfinal->dst.length);
			memcpy(dfinal->tag.data, encdata_buf +
			       dfinal->dst.length, dfinal->tag.length);
		}
	}

	free(encdata_buf);
out_enc_buf_err:
	free(payload_buf);
out:
	mrvl_ehsm_cryp_unlock();
	return ret;
}

static TEE_Result mrvl_ae_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(dfinal->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;
	uint8_t *encdata_buf = NULL;
	uint8_t *decdata_buf = NULL;
	size_t buf_len = 0;
	size_t iv = 0;

	mrvl_ehsm_cryp_lock();

	ret = mrvl_ehsm_aes_context_load(ctx->context_id);
	if (ret != TEE_SUCCESS)
		return ret;

	if (ctx->is_new) {
		if (ctx->iv_len != 12)
			iv = ctx->iv_len;
		else
			iv = 0;

		buf_len = iv + ctx->aad_len + dfinal->src.length +
			  dfinal->tag.length;

		encdata_buf = mem_alloc(buf_len);
		if (!encdata_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		decdata_buf = mem_alloc(buf_len);
		if (!decdata_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out_dec_buf_err;
		}

		if (ctx->iv_len != 12)
			memcpy(encdata_buf, ctx->iv_data, iv);

		memcpy(encdata_buf + iv, ctx->aad_data, ctx->aad_cur_idx);
		memcpy(encdata_buf + iv + ctx->aad_cur_idx, dfinal->src.data,
		       dfinal->src.length);
		memcpy(encdata_buf + iv + ctx->aad_cur_idx + dfinal->src.length,
		       dfinal->tag.data, dfinal->tag.length);

		ret = mrvl_ehsm_aes_gcm_final(encdata_buf, dfinal->src.length,
					      decdata_buf, dfinal->dst.length,
					      ctx->is_new);

		if (ret == TEE_SUCCESS)
			memcpy(dfinal->dst.data, decdata_buf + iv +
			       ctx->aad_cur_idx, dfinal->dst.length);

	} else {
		buf_len = dfinal->src.length + dfinal->tag.length;

		encdata_buf = mem_alloc(buf_len);
		if (!encdata_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		decdata_buf = mem_alloc(buf_len);
		if (!decdata_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out_dec_buf_err;
		}

		memcpy(encdata_buf, dfinal->src.data, dfinal->src.length);
		memcpy(encdata_buf + dfinal->src.length, dfinal->tag.data,
		       dfinal->tag.length);

		ret = mrvl_ehsm_aes_gcm_final(encdata_buf, dfinal->src.length,
					      decdata_buf, dfinal->dst.length,
					      ctx->is_new);

		if (ret == TEE_SUCCESS)
			memcpy(dfinal->dst.data, decdata_buf,
			       dfinal->dst.length);
	}

	free(decdata_buf);
out_dec_buf_err:
	free(encdata_buf);
out:
	mrvl_ehsm_cryp_unlock();
	return ret;
}

static void mrvl_ae_final(void *ctx __unused)
{
}

static void mrvl_ae_free(void *ctx)
{
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(ctx);
	struct mrvl_cryp_context *cryp_ctx = &c->cryp_ctx;

	mrvl_ehsm_cryp_lock();
	mrvl_ehsm_aes_context_release(cryp_ctx->context_id);
	mrvl_ehsm_cryp_unlock();

	mrvl_ehsm_aes_cryp_release();

	free(cryp_ctx->iv_data);
	free(cryp_ctx->aad_data);
	free(cryp_ctx->key);
	free(c);
}

static void mrvl_ae_copy_state(void *dst_ctx, void *src_ctx)
{
	struct mrvl_ae_ctx *src = to_mrvl_ae_ctx(src_ctx);
	struct mrvl_ae_ctx *dst = to_mrvl_ae_ctx(dst_ctx);

	memcpy(dst, src, sizeof(*dst));
}

/*
 * Allocate the SW authenc data context
 *
 * @ctx   [out] Caller context variable
 * @algo  Algorithm ID of the context
 */
static TEE_Result mrvl_ae_allocate(void **ctx, uint32_t algo)
{
	struct mrvl_ae_ctx *c = NULL;

	if (algo != TEE_ALG_AES_GCM)
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (!mrvl_ehsm_aes_cryp_allowed()) {
		DMSG("%s ehsm aes busy, algo: %x\n", __func__, algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		mrvl_ehsm_aes_cryp_release();
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	*ctx = &c->a_ctx;

	return TEE_SUCCESS;
}

/*
 * Registration of the Authenc Driver
 */
static struct drvcrypt_authenc mrvl_gcm = {
	.alloc_ctx = &mrvl_ae_allocate,
	.update_aad = &mrvl_ae_update_aad,
	.update_payload =  &mrvl_ae_update_payload,
	.enc_final = &mrvl_ae_enc_final,
	.dec_final = &mrvl_ae_dec_final,
	.free_ctx = &mrvl_ae_free,
	.init = &mrvl_ae_initialize,
	.final = &mrvl_ae_final,
	.copy_state = &mrvl_ae_copy_state,
};

static TEE_Result mrvl_register_authenc(void)
{
	return drvcrypt_register_authenc(&mrvl_gcm);
}

early_init(mrvl_register_authenc);
