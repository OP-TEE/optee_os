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

static TEE_Result saes_init(union ip_ctx *ip_ctx, bool is_decrypt,
			    const uint8_t *key, size_t key_len,
			    const uint8_t *iv, size_t iv_len)
{
	enum stm32_saes_key_selection key_sel = STM32_SAES_KEY_SOFT;

	if (!IS_ENABLED(CFG_STM32_SAES))
		return TEE_ERROR_NOT_IMPLEMENTED;

	return stm32_saes_init(&ip_ctx->saes.ctx, is_decrypt, ip_ctx->saes.algo,
			       key_sel, key, key_len, iv, iv_len);
}

static TEE_Result saes_update(union ip_ctx *ip_ctx, bool last_block,
			      uint8_t *src, uint8_t *dst, size_t len)
{
	if (!IS_ENABLED(CFG_STM32_SAES))
		return TEE_ERROR_NOT_IMPLEMENTED;

	return stm32_saes_update(&ip_ctx->saes.ctx, last_block, src, dst, len);
}

const struct ip_cipher_ops cryp_ops = {
	.init = cryp_init,
	.update = cryp_update,
};

const struct ip_cipher_ops saes_ops = {
	.init = saes_init,
	.update = saes_update,
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
}

static void stm32_cipher_free(void *ctx)
{
	struct stm32_cipher_ctx *c = to_stm32_cipher_ctx(ctx);

	free(c);
}

static void stm32_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct stm32_cipher_ctx *src = to_stm32_cipher_ctx(src_ctx);
	struct stm32_cipher_ctx *dst = to_stm32_cipher_ctx(dst_ctx);

	memcpy(dst, src, sizeof(*dst));
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

static TEE_Result alloc_saes_ctx(void **ctx, enum stm32_saes_chaining_mode algo)
{
	struct stm32_cipher_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	FMSG("Using SAES %d", algo);
	c->ip_ctx.saes.algo = algo;
	c->ops = &saes_ops;
	*ctx = &c->c_ctx;

	return TEE_SUCCESS;
}

/*
 * Allocate the SW cipher data context for CRYP peripheral.
 *
 * @ctx   [out] Caller context variable
 * @algo  Algorithm ID of the context
 */
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

/*
 * Allocate the SW cipher data context for SAES peripheral.
 *
 * @ctx   [out] Caller context variable
 * @algo  Algorithm ID of the context
 */
static TEE_Result stm32_saes_cipher_allocate(void **ctx, uint32_t algo)
{
	/*
	 * Convert TEE_ALGO id to internal id
	 */
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		return alloc_saes_ctx(ctx, STM32_SAES_MODE_ECB);
	case TEE_ALG_AES_CBC_NOPAD:
		return alloc_saes_ctx(ctx, STM32_SAES_MODE_CBC);
	case TEE_ALG_AES_CTR:
		return alloc_saes_ctx(ctx, STM32_SAES_MODE_CTR);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static struct drvcrypt_cipher driver_cipher_cryp = {
	.alloc_ctx = &stm32_cryp_cipher_allocate,
	.free_ctx = &stm32_cipher_free,
	.init = &stm32_cipher_initialize,
	.update = &stm32_cipher_update,
	.final = &stm32_cipher_final,
	.copy_state = &stm32_cipher_copy_state,
};

static struct drvcrypt_cipher driver_cipher_saes = {
	.alloc_ctx = &stm32_saes_cipher_allocate,
	.free_ctx = &stm32_cipher_free,
	.init = &stm32_cipher_initialize,
	.update = &stm32_cipher_update,
	.final = &stm32_cipher_final,
	.copy_state = &stm32_cipher_copy_state,
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
