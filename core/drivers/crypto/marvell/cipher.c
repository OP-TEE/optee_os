// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Marvell
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

	ctx->ks_tail_len = 0;
	memzero_explicit(ctx->ks_tail, sizeof(ctx->ks_tail));

	/* if already initialized free the previous content and context */
	if (ctx->initialized) {
		mrvl_ehsm_mem_free(ctx->iv_data);
		mrvl_ehsm_mem_free(ctx->key);
		mrvl_ehsm_mem_free(ctx->key2);
		ctx->iv_data = NULL;
		ctx->key = NULL;
		ctx->key2 = NULL;

		if (ctx->context_id != 0) {
			ret = mrvl_ehsm_aes_context_release(ctx->context_id);
			ctx->context_id = 0;
			if (ret != TEE_SUCCESS)
				goto out;
		}
	}

	ctx->iv_len = dinit->iv.length;
	ctx->iv_data = mrvl_ehsm_mem_alloc(ctx->iv_len);
	if (!ctx->iv_data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(ctx->iv_data, dinit->iv.data, ctx->iv_len);

	ctx->op_enc_dec = dinit->encrypt;

	ctx->key_len = dinit->key1.length;
	ctx->key = mrvl_ehsm_mem_alloc(ctx->key_len);
	if (!ctx->key) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(ctx->key, dinit->key1.data, ctx->key_len);

	if (dinit->key2.length) {
		ctx->key2_len = dinit->key2.length;
		ctx->key2 = mrvl_ehsm_mem_alloc(ctx->key2_len);
		if (!ctx->key2) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		memcpy(ctx->key2, dinit->key2.data, ctx->key2_len);
	}

	ret = mrvl_ehsm_aes_init(c->algo, ctx->op_enc_dec, (void *)ctx->key,
				 ctx->key_len, (void *)ctx->key2, ctx->key2_len,
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
		mrvl_ehsm_mem_free(ctx->key2);
		mrvl_ehsm_mem_free(ctx->key);
		mrvl_ehsm_mem_free(ctx->iv_data);
		ctx->key2 = NULL;
		ctx->key = NULL;
		ctx->iv_data = NULL;
	}

	mrvl_ehsm_cryp_unlock();

	return ret;
}

static void xor_bytes(uint8_t *dst, const uint8_t *a, const uint8_t *b,
		      size_t n)
{
	size_t i = 0;

	for (i = 0; i < n; i++)
		dst[i] = a[i] ^ b[i];
}

static TEE_Result
mrvl_cipher_update_block(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_cipher_ctx *c = to_mrvl_cipher_ctx(dupdate->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;
	size_t payload_len = dupdate->src.length;
	size_t dstdata_len = dupdate->dst.length;
	uint8_t *payload_buf = NULL;
	uint8_t *dstdata_buf = NULL;
	uint32_t context_id = 0;

	mrvl_ehsm_cryp_lock();

	ret = mrvl_ehsm_aes_context_load(ctx->context_id);
	if (ret != TEE_SUCCESS)
		goto out;

	payload_buf = mrvl_ehsm_mem_alloc(payload_len);
	if (!payload_buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	dstdata_buf = mrvl_ehsm_mem_alloc(dstdata_len);
	if (!dstdata_buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memcpy(payload_buf, dupdate->src.data, payload_len);

	if (dupdate->last)
		ret = mrvl_ehsm_aes_final(payload_buf, payload_len,
					  dstdata_buf, dstdata_len,
					  ctx->is_new);
	else
		ret = mrvl_ehsm_aes_update_payload(payload_buf, payload_len,
						   dstdata_buf, dstdata_len,
						   ctx->is_new);

	if (ret != TEE_SUCCESS)
		goto out;

	memcpy(dupdate->dst.data, dstdata_buf, dstdata_len);

	context_id = ctx->context_id;
	ctx->context_id = 0;
	ret = mrvl_ehsm_aes_context_release(context_id);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = mrvl_ehsm_aes_context_store(&ctx->context_id);
	if (ret != TEE_SUCCESS)
		goto out;

	ctx->is_new = false;

out:
	mrvl_ehsm_mem_free(dstdata_buf);
	mrvl_ehsm_mem_free(payload_buf);

	mrvl_ehsm_cryp_unlock();

	return ret;
}

static TEE_Result
mrvl_cipher_update_ctr(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_SUCCESS;
	struct mrvl_cipher_ctx *c = to_mrvl_cipher_ctx(dupdate->ctx);
	struct mrvl_cryp_context *ctx = &c->cryp_ctx;
	const uint8_t *src = dupdate->src.data;
	uint8_t *dst = dupdate->dst.data;
	size_t len = MIN(dupdate->src.length, dupdate->dst.length);
	size_t blk = TEE_AES_BLOCK_SIZE;
	size_t off = 0;
	size_t full = 0;
	size_t tail = 0;
	uint32_t context_id = 0;
	uint8_t *in_buf = NULL;
	uint8_t *out_buf = NULL;

	mrvl_ehsm_cryp_lock();

	ret = mrvl_ehsm_aes_context_load(ctx->context_id);
	if (ret != TEE_SUCCESS)
		goto out;

	if (ctx->ks_tail_len) {
		size_t k = MIN(ctx->ks_tail_len, len);

		xor_bytes(dst, src, ctx->ks_tail, k);
		memmove(ctx->ks_tail, ctx->ks_tail + k, ctx->ks_tail_len - k);
		ctx->ks_tail_len -= k;
		off = k;
	}

	full = (len - off) & ~(blk - 1);
	tail = (len - off) - full;

	if (full) {
		in_buf = mrvl_ehsm_mem_alloc(full);
		out_buf = mrvl_ehsm_mem_alloc(full);
		if (!in_buf || !out_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		memcpy(in_buf, src + off, full);

		if (dupdate->last && !tail)
			ret = mrvl_ehsm_aes_final(in_buf, full, out_buf, full,
						  ctx->is_new);
		else
			ret = mrvl_ehsm_aes_update_payload(in_buf, full,
							   out_buf, full,
							   ctx->is_new);
		if (ret != TEE_SUCCESS)
			goto out;

		memcpy(dst + off, out_buf, full);
		ctx->is_new = false;
		off += full;

		mrvl_ehsm_mem_free(in_buf);
		mrvl_ehsm_mem_free(out_buf);
		in_buf = NULL;
		out_buf = NULL;
	}

	if (tail) {
		in_buf = mrvl_ehsm_mem_alloc(blk);
		out_buf = mrvl_ehsm_mem_alloc(blk);
		if (!in_buf || !out_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (dupdate->last) {
			memcpy(in_buf, src + off, tail);
			ret = mrvl_ehsm_aes_final(in_buf, tail, out_buf,
						  tail, ctx->is_new);
			if (ret != TEE_SUCCESS)
				goto out;
			memcpy(dst + off, out_buf, tail);
		} else {
			memset(in_buf, 0, blk);
			memcpy(in_buf, src + off, tail);
			ret = mrvl_ehsm_aes_update_payload(in_buf, blk, out_buf,
							   blk, ctx->is_new);
			if (ret != TEE_SUCCESS)
				goto out;
			memcpy(dst + off, out_buf, tail);
			memcpy(ctx->ks_tail, out_buf + tail, blk - tail);
			ctx->ks_tail_len = blk - tail;
		}
		ctx->is_new = false;
	}

	context_id = ctx->context_id;
	ctx->context_id = 0;
	ret = mrvl_ehsm_aes_context_release(context_id);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = mrvl_ehsm_aes_context_store(&ctx->context_id);

out:
	mrvl_ehsm_mem_free(in_buf);
	mrvl_ehsm_mem_free(out_buf);

	mrvl_ehsm_cryp_unlock();

	return ret;
}

static TEE_Result mrvl_cipher_update(struct drvcrypt_cipher_update *dupdate)
{
	struct mrvl_cipher_ctx *c = to_mrvl_cipher_ctx(dupdate->ctx);

	if (c->algo == MRVL_CRYP_MODE_AES_CTR)
		return mrvl_cipher_update_ctr(dupdate);

	return mrvl_cipher_update_block(dupdate);
}

static void mrvl_cipher_final(void *ctx __unused)
{
}

static void mrvl_cipher_free(void *ctx)
{
	struct mrvl_cipher_ctx *c = to_mrvl_cipher_ctx(ctx);
	struct mrvl_cryp_context *cryp_ctx = &c->cryp_ctx;

	mrvl_ehsm_cryp_lock();
	if (cryp_ctx->context_id)
		mrvl_ehsm_aes_context_release(cryp_ctx->context_id);
	mrvl_ehsm_cryp_unlock();

	mrvl_ehsm_aes_cryp_put();

	mrvl_ehsm_mem_free(cryp_ctx->iv_data);
	mrvl_ehsm_mem_free(cryp_ctx->key);
	mrvl_ehsm_mem_free(cryp_ctx->key2);

	memzero_explicit(cryp_ctx->ks_tail, sizeof(cryp_ctx->ks_tail));

	free(c);
}

static void mrvl_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct mrvl_cipher_ctx *src = to_mrvl_cipher_ctx(src_ctx);
	struct mrvl_cipher_ctx *dst = to_mrvl_cipher_ctx(dst_ctx);
	struct mrvl_cryp_context *s = &src->cryp_ctx;
	struct mrvl_cryp_context *d = &dst->cryp_ctx;

	mrvl_ehsm_cryp_lock();

	if (d->context_id)
		mrvl_ehsm_aes_context_release(d->context_id);
	mrvl_ehsm_mem_free(d->key);
	mrvl_ehsm_mem_free(d->key2);
	mrvl_ehsm_mem_free(d->iv_data);

	dst->algo = src->algo;
	*d = *s;
	d->key = NULL;
	d->key2 = NULL;
	d->iv_data = NULL;
	d->context_id = 0;

	if (s->key) {
		d->key = mrvl_ehsm_mem_alloc(s->key_len);
		if (d->key)
			memcpy(d->key, s->key, s->key_len);
	}

	if (s->key2) {
		d->key2 = mrvl_ehsm_mem_alloc(s->key2_len);
		if (d->key2)
			memcpy(d->key2, s->key2, s->key2_len);
	}

	if (s->iv_data) {
		d->iv_data = mrvl_ehsm_mem_alloc(s->iv_len);
		if (d->iv_data)
			memcpy(d->iv_data, s->iv_data, s->iv_len);
	}

	if (s->context_id &&
	    mrvl_ehsm_aes_context_load(s->context_id) == TEE_SUCCESS)
		mrvl_ehsm_aes_context_store(&d->context_id);

	mrvl_ehsm_cryp_unlock();
}

static TEE_Result alloc_ctx(void **ctx, enum mrvl_cryp_algo_mode algo)
{
	struct mrvl_cipher_ctx *c = NULL;

	if (!mrvl_ehsm_aes_cryp_get()) {
		DMSG("ehsm aes is busy, algo: %x", algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		mrvl_ehsm_aes_cryp_put();
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
