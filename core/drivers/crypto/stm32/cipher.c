// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <kernel/dt.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <util.h>

#include "common.h"
#include "stm32_cryp.h"

#define DES3_KEY_SIZE		24

struct stm32_cipher_ctx {
	struct crypto_cipher_ctx c_ctx;
	struct stm32_cryp_context cryp;
	enum stm32_cryp_algo_mode algo;
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
	uint8_t temp_key[DES3_KEY_SIZE] = { 0 };
	uint8_t *key = NULL;
	size_t key_size = 0;

	if (dinit->key1.length == 16 &&
	    (c->algo == STM32_CRYP_MODE_TDES_ECB ||
	     c->algo == STM32_CRYP_MODE_TDES_CBC)) {
		/* Manage DES2: ie K=K1.K2.K1 */
		memcpy(temp_key, dinit->key1.data, dinit->key1.length);
		memcpy(temp_key + dinit->key1.length, dinit->key1.data,
		       dinit->key1.length / 2);
		key_size = DES3_KEY_SIZE;
		key = temp_key;
	} else {
		key_size =  dinit->key1.length;
		key = dinit->key1.data;
	}

	return stm32_cryp_init(&c->cryp, !dinit->encrypt, c->algo,
			       key, key_size, dinit->iv.data,
			       dinit->iv.length);
}

static TEE_Result stm32_cipher_update(struct drvcrypt_cipher_update *dupdate)
{
	struct stm32_cipher_ctx *c = to_stm32_cipher_ctx(dupdate->ctx);
	size_t len = MIN(dupdate->src.length, dupdate->dst.length);

	return stm32_cryp_update(&c->cryp, dupdate->last,
				 dupdate->src.data, dupdate->dst.data,
				 len);
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

static TEE_Result alloc_ctx(void **ctx, enum stm32_cryp_algo_mode algo)
{
	struct stm32_cipher_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->algo = algo;
	*ctx = &c->c_ctx;

	return TEE_SUCCESS;
}

/*
 * Allocate the SW cipher data context.
 *
 * @ctx   [out] Caller context variable
 * @algo  Algorithm ID of the context
 */
static TEE_Result stm32_cipher_allocate(void **ctx, uint32_t algo)
{
	/*
	 * Convert TEE_ALGO id to internal id
	 */
	switch (algo) {
	case TEE_ALG_DES_ECB_NOPAD:
		return alloc_ctx(ctx, STM32_CRYP_MODE_DES_ECB);
	case TEE_ALG_DES_CBC_NOPAD:
		return alloc_ctx(ctx, STM32_CRYP_MODE_DES_CBC);
	case TEE_ALG_DES3_ECB_NOPAD:
		return alloc_ctx(ctx, STM32_CRYP_MODE_TDES_ECB);
	case TEE_ALG_DES3_CBC_NOPAD:
		return alloc_ctx(ctx, STM32_CRYP_MODE_TDES_CBC);
	case TEE_ALG_AES_ECB_NOPAD:
		return alloc_ctx(ctx, STM32_CRYP_MODE_AES_ECB);
	case TEE_ALG_AES_CBC_NOPAD:
		return alloc_ctx(ctx, STM32_CRYP_MODE_AES_CBC);
	case TEE_ALG_AES_CTR:
		return alloc_ctx(ctx, STM32_CRYP_MODE_AES_CTR);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx = &stm32_cipher_allocate,
	.free_ctx = &stm32_cipher_free,
	.init = &stm32_cipher_initialize,
	.update = &stm32_cipher_update,
	.final = &stm32_cipher_final,
	.copy_state = &stm32_cipher_copy_state,
};

TEE_Result stm32_register_cipher(void)
{
	return drvcrypt_register_cipher(&driver_cipher);
}
