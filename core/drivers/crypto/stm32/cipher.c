// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <util.h>

#include "common.h"
#include "stm32_cryp.h"
#include "stm32_saes.h"

#define DES3_KEY_SIZE		24

struct cryp_ctx {
	struct stm32_cryp_context ctx;
	enum stm32_cryp_algo_mode algo;
};

struct saes_ctx {
	struct stm32_saes_context ctx;
	enum stm32_saes_chaining_mode algo;
	/* Fallback to software implementation on 192bit AES key */
	bool use_fallback;
	struct crypto_cipher_ctx *fallback_ctx;
};

/*
 * Internal peripheral context
 * SAES and CRYP are registered under the same ID in the crypto framework.
 * Therefore, only one of them can be registered.
 */

union ip_ctx {
	struct saes_ctx saes;
	struct cryp_ctx cryp;
};

/* Internal Peripheral cipher ops*/
struct ip_cipher_ops {
	TEE_Result (*init)(union ip_ctx *ctx, bool is_decrypt,
			   const uint8_t *key, size_t key_len,
			   const uint8_t *iv, size_t iv_len);
	TEE_Result (*update)(union ip_ctx *ctx, bool last_block, uint8_t *src,
			     uint8_t *dst, size_t len);
	void (*final)(union ip_ctx *ctx);
	void (*copy_state)(union ip_ctx *dst_ctx, union ip_ctx *src_ctx);
};

struct stm32_cipher_ctx {
	struct crypto_cipher_ctx c_ctx;
	union ip_ctx ip_ctx;
	const struct ip_cipher_ops *ops;
};

static TEE_Result cryp_init(union ip_ctx *ip_ctx, bool is_decrypt,
			    const uint8_t *key, size_t key_len,
			    const uint8_t *iv, size_t iv_len)
{
	uint8_t temp_key[DES3_KEY_SIZE] = { };

	if (!IS_ENABLED(CFG_STM32_CRYP))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (key_len == 16 &&
	    (ip_ctx->cryp.algo == STM32_CRYP_MODE_TDES_ECB ||
	     ip_ctx->cryp.algo == STM32_CRYP_MODE_TDES_CBC)) {
		/* Manage DES2: i.e. K=K1.K2.K1 */
		memcpy(temp_key, key, key_len);
		memcpy(temp_key + key_len, key, key_len / 2);
		key_len = DES3_KEY_SIZE;
		key = temp_key;
	}

	return stm32_cryp_init(&ip_ctx->cryp.ctx, is_decrypt, ip_ctx->cryp.algo,
			       key, key_len, iv, iv_len);
}

static TEE_Result cryp_update(union ip_ctx *ip_ctx, bool last_block,
			      uint8_t *src, uint8_t *dst, size_t len)
{
	if (!IS_ENABLED(CFG_STM32_CRYP))
		return TEE_ERROR_NOT_IMPLEMENTED;

	return stm32_cryp_update(&ip_ctx->cryp.ctx, last_block, src, dst, len);
}

static void cryp_copy_state(union ip_ctx *dst_ip_ctx, union ip_ctx *src_ip_ctx)
{
	assert(IS_ENABLED(CFG_STM32_CRYP));

	memcpy(&dst_ip_ctx->cryp, &src_ip_ctx->cryp, sizeof(dst_ip_ctx->cryp));
}

static const struct ip_cipher_ops cryp_ops = {
	.init = cryp_init,
	.update = cryp_update,
	.copy_state = cryp_copy_state,
};

static TEE_Result saes_init(union ip_ctx *ip_ctx, bool is_decrypt,
			    const uint8_t *key, size_t key_len,
			    const uint8_t *iv, size_t iv_len)
{
	enum stm32_saes_key_selection key_sel = STM32_SAES_KEY_SOFT;

	if (!IS_ENABLED(CFG_STM32_SAES))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (key_len == AES_KEYSIZE_192) {
		struct crypto_cipher_ctx *ctx = ip_ctx->saes.fallback_ctx;
		TEE_OperationMode mode = TEE_MODE_ILLEGAL_VALUE;
		TEE_Result res = TEE_ERROR_GENERIC;

		if (!IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK)) {
			EMSG("STM32 SAES does not support 192bit keys");

			return TEE_ERROR_NOT_IMPLEMENTED;
		}

		if (is_decrypt)
			mode = TEE_MODE_DECRYPT;
		else
			mode = TEE_MODE_ENCRYPT;

		res = ctx->ops->init(ctx, mode, key, key_len, NULL, 0, iv,
				     iv_len);
		if (res)
			return res;

		ip_ctx->saes.use_fallback = true;

		return TEE_SUCCESS;
	}

	ip_ctx->saes.use_fallback = false;

	return stm32_saes_init(&ip_ctx->saes.ctx, is_decrypt, ip_ctx->saes.algo,
			       key_sel, key, key_len, iv, iv_len);
}

static TEE_Result saes_update(union ip_ctx *ip_ctx, bool last_block,
			      uint8_t *src, uint8_t *dst, size_t len)
{
	if (!IS_ENABLED(CFG_STM32_SAES))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (ip_ctx->saes.use_fallback) {
		struct crypto_cipher_ctx *ctx = ip_ctx->saes.fallback_ctx;

		assert(IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK));

		return ctx->ops->update(ctx, last_block, src, len, dst);
	}

	return stm32_saes_update(&ip_ctx->saes.ctx, last_block, src, dst, len);
}

static void saes_final(union ip_ctx *ip_ctx)
{
	struct crypto_cipher_ctx *ctx = ip_ctx->saes.fallback_ctx;

	assert(IS_ENABLED(CFG_STM32_SAES));

	if (ip_ctx->saes.use_fallback) {
		assert(IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK));
		ctx->ops->final(ctx);
	}
}

static void saes_copy_state(union ip_ctx *dst_ip_ctx, union ip_ctx *src_ip_ctx)
{
	struct saes_ctx *src_ctx = &src_ip_ctx->saes;
	struct crypto_cipher_ctx *fb_ctx = src_ctx->fallback_ctx;

	assert(IS_ENABLED(CFG_STM32_SAES));

	memcpy(&dst_ip_ctx->saes.ctx, &src_ctx->ctx, sizeof(src_ctx->ctx));

	dst_ip_ctx->saes.algo = src_ctx->algo;
	dst_ip_ctx->saes.use_fallback = src_ctx->use_fallback;

	if (src_ctx->use_fallback) {
		assert(IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK));
		fb_ctx->ops->copy_state(dst_ip_ctx->saes.fallback_ctx, fb_ctx);
	}
}

static const struct ip_cipher_ops saes_ops = {
	.init = saes_init,
	.update = saes_update,
	.final = saes_final,
	.copy_state = saes_copy_state,
};

static struct stm32_cipher_ctx *
to_stm32_cipher_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx);

	return container_of(ctx, struct stm32_cipher_ctx, c_ctx);
}

static TEE_Result stm32_cipher_initialize(struct drvcrypt_cipher_init *dinit)
{
	struct stm32_cipher_ctx *c = to_stm32_cipher_ctx(dinit->ctx);

	return c->ops->init(&c->ip_ctx, !dinit->encrypt, dinit->key1.data,
			    dinit->key1.length, dinit->iv.data,
			    dinit->iv.length);
}

static TEE_Result stm32_cipher_update(struct drvcrypt_cipher_update *dupdate)
{
	struct stm32_cipher_ctx *c = to_stm32_cipher_ctx(dupdate->ctx);
	size_t len = MIN(dupdate->src.length, dupdate->dst.length);

	return c->ops->update(&c->ip_ctx, dupdate->last, dupdate->src.data,
			      dupdate->dst.data, len);
}

static void stm32_cipher_final(void *ctx __unused)
{
	struct stm32_cipher_ctx *c = to_stm32_cipher_ctx(ctx);

	if (c->ops->final)
		c->ops->final(&c->ip_ctx);
}

static void stm32_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct stm32_cipher_ctx *src_c = to_stm32_cipher_ctx(src_ctx);
	struct stm32_cipher_ctx *dst_c = to_stm32_cipher_ctx(dst_ctx);

	src_c->ops->copy_state(&dst_c->ip_ctx, &src_c->ip_ctx);
}

static TEE_Result alloc_cryp_ctx(void **ctx, enum stm32_cryp_algo_mode algo)
{
	struct stm32_cipher_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	FMSG("Using CRYP %d", algo);
	c->ip_ctx.cryp.algo = algo;
	c->ops = &cryp_ops;
	*ctx = &c->c_ctx;

	return TEE_SUCCESS;
}

static TEE_Result stm32_cryp_cipher_allocate(void **ctx, uint32_t algo)
{
	/*
	 * Convert TEE_ALGO id to internal id
	 */
	switch (algo) {
	case TEE_ALG_DES_ECB_NOPAD:
		return alloc_cryp_ctx(ctx, STM32_CRYP_MODE_DES_ECB);
	case TEE_ALG_DES_CBC_NOPAD:
		return alloc_cryp_ctx(ctx, STM32_CRYP_MODE_DES_CBC);
	case TEE_ALG_DES3_ECB_NOPAD:
		return alloc_cryp_ctx(ctx, STM32_CRYP_MODE_TDES_ECB);
	case TEE_ALG_DES3_CBC_NOPAD:
		return alloc_cryp_ctx(ctx, STM32_CRYP_MODE_TDES_CBC);
	case TEE_ALG_AES_ECB_NOPAD:
		return alloc_cryp_ctx(ctx, STM32_CRYP_MODE_AES_ECB);
	case TEE_ALG_AES_CBC_NOPAD:
		return alloc_cryp_ctx(ctx, STM32_CRYP_MODE_AES_CBC);
	case TEE_ALG_AES_CTR:
		return alloc_cryp_ctx(ctx, STM32_CRYP_MODE_AES_CTR);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static void stm32_cryp_cipher_free(void *ctx)
{
	struct stm32_cipher_ctx *c = to_stm32_cipher_ctx(ctx);

	free(c);
}

static TEE_Result stm32_saes_cipher_allocate(void **ctx, uint32_t algo)
{
	enum stm32_saes_chaining_mode saes_algo = STM32_SAES_MODE_ECB;
	struct crypto_cipher_ctx *fallback_ctx = NULL;
	struct stm32_cipher_ctx *saes_ctx = NULL;
	TEE_Result res = TEE_SUCCESS;

	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		saes_algo = STM32_SAES_MODE_ECB;
		if (IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK))
			res = crypto_aes_ecb_alloc_ctx(&fallback_ctx);
		break;
	case TEE_ALG_AES_CBC_NOPAD:
		saes_algo = STM32_SAES_MODE_CBC;
		if (IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK))
			res = crypto_aes_cbc_alloc_ctx(&fallback_ctx);
		break;
	case TEE_ALG_AES_CTR:
		saes_algo = STM32_SAES_MODE_CTR;
		if (IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK))
			res = crypto_aes_ctr_alloc_ctx(&fallback_ctx);
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
	if (res)
		return res;

	saes_ctx = calloc(1, sizeof(*saes_ctx));
	if (!saes_ctx) {
		if (IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK))
			fallback_ctx->ops->free_ctx(fallback_ctx);

		return TEE_ERROR_OUT_OF_MEMORY;
	}

	FMSG("Using SAES %d", saes_algo);
	saes_ctx->ip_ctx.saes.algo = saes_algo;
	saes_ctx->ops = &saes_ops;
	saes_ctx->ip_ctx.saes.fallback_ctx = fallback_ctx;
	*ctx = &saes_ctx->c_ctx;

	return TEE_SUCCESS;
}

static void stm32_saes_cipher_free(void *ctx)
{
	struct stm32_cipher_ctx *c = to_stm32_cipher_ctx(ctx);

	if (IS_ENABLED(CFG_STM32_SAES_SW_FALLBACK)) {
		struct crypto_cipher_ctx *fb_ctx = c->ip_ctx.saes.fallback_ctx;

		fb_ctx->ops->free_ctx(fb_ctx);
	}

	free(c);
}

static struct drvcrypt_cipher driver_cipher_cryp = {
	.alloc_ctx = stm32_cryp_cipher_allocate,
	.free_ctx = stm32_cryp_cipher_free,
	.init = stm32_cipher_initialize,
	.update = stm32_cipher_update,
	.final = stm32_cipher_final,
	.copy_state = stm32_cipher_copy_state,
};

static struct drvcrypt_cipher driver_cipher_saes = {
	.alloc_ctx = stm32_saes_cipher_allocate,
	.free_ctx = stm32_saes_cipher_free,
	.init = stm32_cipher_initialize,
	.update = stm32_cipher_update,
	.final = stm32_cipher_final,
	.copy_state = stm32_cipher_copy_state,
};

TEE_Result stm32_register_cipher(enum stm32_cipher_ip_id cipher_ip)
{
	if (cipher_ip == SAES_IP)
		return drvcrypt_register_cipher(&driver_cipher_saes);
	else if (cipher_ip == CRYP_IP)
		return drvcrypt_register_cipher(&driver_cipher_cryp);
	else
		return TEE_ERROR_BAD_PARAMETERS;
}
