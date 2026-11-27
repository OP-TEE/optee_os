// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Marvell
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

	ctx->gcm_hold_len = 0;
	memzero_explicit(ctx->gcm_hold, sizeof(ctx->gcm_hold));

	/* if already initialized free the previous content and context */
	if (ctx->initialized) {
		mrvl_ehsm_mem_free(ctx->iv_data);
		mrvl_ehsm_mem_free(ctx->key);
		mrvl_ehsm_mem_free(ctx->aad_data);
		ctx->iv_data = NULL;
		ctx->key = NULL;
		ctx->aad_data = NULL;

		if (ctx->context_id != 0) {
			ret = mrvl_ehsm_aes_context_release(ctx->context_id);
			ctx->context_id = 0;
			if (ret != TEE_SUCCESS)
				goto out;
		}
	}

	ctx->iv_len = dinit->nonce.length;
	ctx->iv_data = mrvl_ehsm_mem_alloc(ctx->iv_len);
	if (!ctx->iv_data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(ctx->iv_data, dinit->nonce.data, ctx->iv_len);

	ctx->aad_len = dinit->aad_len;
	ctx->aad_cur_idx = 0;
	ctx->aad_data = mrvl_ehsm_mem_alloc(ctx->aad_len);
	if (!ctx->aad_data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ctx->op_enc_dec = dinit->encrypt;
	ctx->tag_len = dinit->tag_len;

	ctx->key_len = dinit->key.length;
	ctx->key = mrvl_ehsm_mem_alloc(ctx->key_len);
	if (!ctx->key) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(ctx->key, dinit->key.data, ctx->key_len);

	ret = mrvl_ehsm_aes_gcm_init(ctx->op_enc_dec, (void *)ctx->key,
				     ctx->key_len, ctx->aad_len,
				     ctx->tag_len, ctx->iv_len,
				     ctx->iv_data, 0);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = mrvl_ehsm_aes_context_store(&ctx->context_id);
	if (ret != TEE_SUCCESS)
		goto out;

	ctx->is_new = true;
	ctx->initialized = true;

out:
	if (ret != TEE_SUCCESS) {
		mrvl_ehsm_mem_free(ctx->key);
		mrvl_ehsm_mem_free(ctx->aad_data);
		mrvl_ehsm_mem_free(ctx->iv_data);
		ctx->key = NULL;
		ctx->aad_data = NULL;
		ctx->iv_data = NULL;
	}

	mrvl_ehsm_cryp_unlock();

	return ret;
}

static TEE_Result
mrvl_ae_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(dupdate->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;

	if (!ctx->aad_data)
		return TEE_ERROR_BAD_STATE;

	if ((dupdate->aad.length + ctx->aad_cur_idx) <= ctx->aad_len) {
		memcpy(ctx->aad_data + ctx->aad_cur_idx, dupdate->aad.data,
		       dupdate->aad.length);
		ctx->aad_cur_idx += dupdate->aad.length;
	} else {
		ret = TEE_ERROR_BAD_PARAMETERS;
	}

	return ret;
}

static TEE_Result mrvl_ae_hw_pass(struct mrvl_cryp_context *ctx,
				  const uint8_t *head, size_t head_len,
				  const uint8_t *src, size_t src_len,
				  uint8_t *dst, const uint8_t *tag_in,
				  uint8_t *tag_out, size_t tag_len,
				  bool last, bool commit)
{
	TEE_Result ret = TEE_SUCCESS;
	uint8_t *in_buf = NULL;
	uint8_t *out_buf = NULL;
	size_t len = head_len + src_len;
	size_t iv = 0;
	size_t pre = 0;
	size_t off = 0;
	size_t extra = (tag_in || tag_out) ? tag_len : 0;
	size_t buf_len = 0;
	uint32_t old_id = 0;

	if (ctx->is_new) {
		if (ctx->iv_len != 12)
			iv = ctx->iv_len;
		pre = iv + ctx->aad_len;
		off = iv + ctx->aad_cur_idx;
	}

	buf_len = pre + len + extra;
	in_buf = mrvl_ehsm_mem_alloc(buf_len);
	out_buf = mrvl_ehsm_mem_alloc(buf_len);
	if (!in_buf || !out_buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (iv)
		memcpy(in_buf, ctx->iv_data, iv);
	if (ctx->is_new && ctx->aad_cur_idx)
		memcpy(in_buf + iv, ctx->aad_data, ctx->aad_cur_idx);
	if (head_len)
		memcpy(in_buf + off, head, head_len);
	if (src_len)
		memcpy(in_buf + off + head_len, src, src_len);
	if (tag_in)
		memcpy(in_buf + off + len, tag_in, tag_len);

	if (last)
		ret = mrvl_ehsm_aes_gcm_final(in_buf, len, out_buf, len,
					      ctx->is_new);
	else
		ret = mrvl_ehsm_aes_gcm_update_payload(in_buf, len, out_buf,
						       len, ctx->is_new);
	if (ret != TEE_SUCCESS)
		goto out;

	if (src_len)
		memcpy(dst, out_buf + off + head_len, src_len);
	if (tag_out)
		memcpy(tag_out, out_buf + off + len, tag_len);

	if (commit) {
		old_id = ctx->context_id;
		ctx->context_id = 0;
		ctx->is_new = false;
		ret = mrvl_ehsm_aes_context_release(old_id);
		if (ret != TEE_SUCCESS)
			goto out;
		ret = mrvl_ehsm_aes_context_store(&ctx->context_id);
	}
out:
	if (in_buf)
		memzero_explicit(in_buf, buf_len);
	if (out_buf)
		memzero_explicit(out_buf, buf_len);
	mrvl_ehsm_mem_free(in_buf);
	mrvl_ehsm_mem_free(out_buf);

	return ret;
}

static TEE_Result
mrvl_ae_update_payload(struct drvcrypt_authenc_update_payload *dupdate)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(dupdate->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;
	const uint8_t *src = dupdate->src.data;
	size_t n = dupdate->src.length;
	size_t hold = ctx->gcm_hold_len;
	size_t total = hold + n;
	size_t nblk = 0;
	size_t rem = 0;
	size_t skip = 0;
	uint8_t pad[TEE_AES_BLOCK_SIZE] = { };
	uint8_t trial[TEE_AES_BLOCK_SIZE] = { };

	if (IS_ENABLED(CFG_MARVELL_EHSM_CN10K))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (!ctx->iv_data || !ctx->aad_data || !ctx->context_id)
		return TEE_ERROR_BAD_STATE;

	if (!n)
		return TEE_SUCCESS;

	nblk = ROUNDDOWN(total - 1, TEE_AES_BLOCK_SIZE);
	rem = total - nblk;

	mrvl_ehsm_cryp_lock();

	ret = mrvl_ehsm_aes_context_load(ctx->context_id);
	if (ret != TEE_SUCCESS)
		goto out;

	if (nblk) {
		memcpy(pad, src + (nblk - hold), rem);
		ret = mrvl_ae_hw_pass(ctx, ctx->gcm_hold, hold, src,
				      nblk - hold, dupdate->dst.data,
				      NULL, NULL, 0, false, true);
		if (ret != TEE_SUCCESS)
			goto out;
		ret = mrvl_ehsm_aes_context_load(ctx->context_id);
		if (ret != TEE_SUCCESS)
			goto out;
	} else {
		memcpy(pad, ctx->gcm_hold, hold);
		memcpy(pad + hold, src, n);
		skip = hold;
	}

	memcpy(ctx->gcm_hold, pad, rem);
	ctx->gcm_hold_len = rem;

	ret = mrvl_ae_hw_pass(ctx, NULL, 0, pad, TEE_AES_BLOCK_SIZE, trial,
			      NULL, NULL, 0, false, false);
	if (ret != TEE_SUCCESS)
		goto out;

	memcpy(dupdate->dst.data + (nblk ? nblk - hold : 0), trial + skip,
	       rem - skip);
out:
	memzero_explicit(pad, sizeof(pad));
	memzero_explicit(trial, sizeof(trial));

	mrvl_ehsm_cryp_unlock();

	return ret;
}

static TEE_Result mrvl_ae_final_common(struct drvcrypt_authenc_final *dfinal,
				       bool enc)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(dfinal->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;
	size_t hold = ctx->gcm_hold_len;

	if (!ctx->iv_data || !ctx->aad_data ||
	    (!IS_ENABLED(CFG_MARVELL_EHSM_CN10K) && !ctx->context_id))
		return TEE_ERROR_BAD_STATE;

	if (enc) {
		if (dfinal->tag.length < ctx->tag_len)
			return TEE_ERROR_SHORT_BUFFER;
		dfinal->tag.length = ctx->tag_len;
	} else if (dfinal->tag.length != ctx->tag_len) {
		return TEE_ERROR_MAC_INVALID;
	}

	mrvl_ehsm_cryp_lock();

	ret = mrvl_ehsm_aes_context_load(ctx->context_id);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = mrvl_ae_hw_pass(ctx, ctx->gcm_hold, hold,
			      dfinal->src.data, dfinal->src.length,
			      dfinal->dst.data,
			      enc ? NULL : dfinal->tag.data,
			      enc ? dfinal->tag.data : NULL,
			      ctx->tag_len, true, false);
out:
	memzero_explicit(ctx->gcm_hold, sizeof(ctx->gcm_hold));
	ctx->gcm_hold_len = 0;

	mrvl_ehsm_cryp_unlock();

	return ret;
}

static TEE_Result mrvl_ae_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	return mrvl_ae_final_common(dfinal, true);
}

static TEE_Result mrvl_ae_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	return mrvl_ae_final_common(dfinal, false);
}

static void mrvl_ae_final(void *ctx __unused)
{
}

static void mrvl_ae_free(void *ctx)
{
	struct mrvl_ae_ctx *c = to_mrvl_ae_ctx(ctx);
	struct mrvl_cryp_context *cryp_ctx = &c->cryp_ctx;

	mrvl_ehsm_cryp_lock();
	if (cryp_ctx->context_id)
		mrvl_ehsm_aes_context_release(cryp_ctx->context_id);
	mrvl_ehsm_cryp_unlock();

	mrvl_ehsm_aes_cryp_put();

	mrvl_ehsm_mem_free(cryp_ctx->iv_data);
	mrvl_ehsm_mem_free(cryp_ctx->aad_data);
	mrvl_ehsm_mem_free(cryp_ctx->key);

	memzero_explicit(cryp_ctx->gcm_hold, sizeof(cryp_ctx->gcm_hold));

	free(c);
}

static void mrvl_ae_copy_state(void *dst_ctx, void *src_ctx)
{
	struct mrvl_ae_ctx *src = to_mrvl_ae_ctx(src_ctx);
	struct mrvl_ae_ctx *dst = to_mrvl_ae_ctx(dst_ctx);
	struct mrvl_cryp_context *s = &src->cryp_ctx;
	struct mrvl_cryp_context *d = &dst->cryp_ctx;

	mrvl_ehsm_cryp_lock();

	if (d->context_id)
		mrvl_ehsm_aes_context_release(d->context_id);
	mrvl_ehsm_mem_free(d->key);
	mrvl_ehsm_mem_free(d->iv_data);
	mrvl_ehsm_mem_free(d->aad_data);

	*d = *s;
	d->key = NULL;
	d->iv_data = NULL;
	d->aad_data = NULL;
	d->context_id = 0;

	if (s->key) {
		d->key = mrvl_ehsm_mem_alloc(s->key_len);
		if (d->key)
			memcpy(d->key, s->key, s->key_len);
	}

	if (s->iv_data) {
		d->iv_data = mrvl_ehsm_mem_alloc(s->iv_len);
		if (d->iv_data)
			memcpy(d->iv_data, s->iv_data, s->iv_len);
	}

	if (s->aad_data) {
		d->aad_data = mrvl_ehsm_mem_alloc(s->aad_len);
		if (d->aad_data && s->aad_cur_idx)
			memcpy(d->aad_data, s->aad_data, s->aad_cur_idx);
	}

	if (s->context_id &&
	    mrvl_ehsm_aes_context_load(s->context_id) == TEE_SUCCESS)
		mrvl_ehsm_aes_context_store(&d->context_id);

	mrvl_ehsm_cryp_unlock();
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

	if (!mrvl_ehsm_aes_cryp_get()) {
		DMSG("ehsm aes busy, algo: %x", algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		mrvl_ehsm_aes_cryp_put();
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
