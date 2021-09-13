// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2025, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <crypto/crypto_impl.h>
#include <crypto/crypto.h>
#include <drvcrypt_mac.h>
#include <drvcrypt.h>
#include <kernel/dt.h>
#include <string.h>

#include "common.h"
#include "stm32_hash.h"

static const struct crypto_mac_ops hmac_ops;

struct stm32_hmac_ctx {
	struct crypto_mac_ctx mac_ctx;
	struct stm32_hash_context hash;
	uint8_t *key;
	size_t key_len;
};

static struct stm32_hmac_ctx *to_stm32_hmac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &hmac_ops);

	return container_of(ctx, struct stm32_hmac_ctx, mac_ctx);
}

/*
 * Initialization of the hmac operation
 *
 * @ctx   Operation software context
 */
static TEE_Result do_hmac_init(struct crypto_mac_ctx *ctx, const uint8_t *key,
			       size_t len)
{
	struct stm32_hmac_ctx *c = to_stm32_hmac_ctx(ctx);

	/*
	 * If hmac_init() is called again,
	 * we won't need the previously saved key.
	 */
	if (c->key)
		free(c->key);

	c->key = malloc(len);
	if (!c->key) {
		c->key_len = 0;
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	memcpy(c->key, key, len);
	c->key_len = len;

	return stm32_hash_init(&c->hash, c->key, c->key_len);
}

/*
 * Update the hmac operation
 *
 * @ctx   Operation software context
 * @data  Data to hmac
 * @len   Data length
 */
static TEE_Result do_hmac_update(struct crypto_mac_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	struct stm32_hmac_ctx *c = to_stm32_hmac_ctx(ctx);

	return stm32_hash_update(&c->hash, data, len);
}

/*
 * Finalize the hmac operation
 *
 * @ctx     Operation software context
 * @digest  [out] hmac digest buffer
 * @len     Digest buffer length
 */
static TEE_Result do_hmac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				size_t len)
{
	struct stm32_hmac_ctx *c = to_stm32_hmac_ctx(ctx);
	TEE_Result res = TEE_SUCCESS;
	uint8_t *full_digest = NULL;
	bool alloc = false;

	if (len < stm32_hash_digest_size(&c->hash)) {
		full_digest = malloc(stm32_hash_digest_size(&c->hash));
		if (!full_digest)
			return TEE_ERROR_OUT_OF_MEMORY;
		alloc = true;
	} else {
		full_digest = digest;
	}

	res = stm32_hash_final(&c->hash, full_digest, c->key, c->key_len);

	if (alloc) {
		memcpy(digest, full_digest, len);
		free(full_digest);
	}

	return res;
}

/*
 * Free the SW hmac context
 *
 * @ctx    [in/out] Caller context variable
 */
static void do_hmac_free(struct crypto_mac_ctx *ctx)
{
	struct stm32_hmac_ctx *c = to_stm32_hmac_ctx(ctx);

	free(c->key);
	stm32_hash_free(&c->hash);
	free(c);
}

/*
 * Copy Software hmacing Context
 *
 * @dst_ctx  [out] Reference the context destination
 * @src_ctx  Reference the context source
 */
static void do_hmac_copy_state(struct crypto_mac_ctx *dst_ctx,
			       struct crypto_mac_ctx *src_ctx)
{
	struct stm32_hmac_ctx *src = to_stm32_hmac_ctx(src_ctx);
	struct stm32_hmac_ctx *dst = to_stm32_hmac_ctx(dst_ctx);

	memcpy(&dst->mac_ctx, &src->mac_ctx, sizeof(dst->mac_ctx));
	stm32_hash_deep_copy(&dst->hash, &src->hash);

	dst->key_len = src->key_len;

	if (src->key)
		dst->key = malloc(dst->key_len);

	if (dst->key && src->key)
		memcpy(dst->key, src->key, dst->key_len);
	else
		dst->key_len = 0;
}

/*
 * Registration of the hmac Driver
 */
static const struct crypto_mac_ops hmac_ops = {
	.init = do_hmac_init,
	.update = do_hmac_update,
	.final = do_hmac_final,
	.free_ctx = do_hmac_free,
	.copy_state = do_hmac_copy_state,
};

/*
 * Allocate the internal hmacing data context
 *
 * @ctx    [out] Caller context variable
 * @algo   OP_TEE Algorithm ID
 */
static TEE_Result stm32_hmac_allocate(struct crypto_mac_ctx **ctx,
				      uint32_t algo)
{
	TEE_Result res = TEE_SUCCESS;
	enum stm32_hash_algo stm32_algo;
	struct stm32_hmac_ctx *c = NULL;

	switch (TEE_ALG_GET_MAIN_ALG(algo)) {
	case TEE_MAIN_ALGO_MD5:
		stm32_algo = STM32_HASH_MD5;
		break;
	case TEE_MAIN_ALGO_SHA1:
		stm32_algo = STM32_HASH_SHA1;
		break;
	case TEE_MAIN_ALGO_SHA224:
		stm32_algo = STM32_HASH_SHA224;
		break;
	case TEE_MAIN_ALGO_SHA256:
		stm32_algo = STM32_HASH_SHA256;
		break;
	case TEE_MAIN_ALGO_SHA384:
		stm32_algo = STM32_HASH_SHA384;
		break;
	case TEE_MAIN_ALGO_SHA512:
		stm32_algo = STM32_HASH_SHA512;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Allocate internal stm32_hash.
	 */
	res = stm32_hash_alloc(&c->hash, STM32_HMAC_MODE, stm32_algo);
	if (res) {
		free(c);
		return res;
	}

	FMSG("Using HMAC %d", stm32_algo);
	c->mac_ctx.ops = &hmac_ops;
	*ctx = &c->mac_ctx;

	return TEE_SUCCESS;
}

TEE_Result stm32_register_hmac(void)
{
	return drvcrypt_register_hmac(&stm32_hmac_allocate);
}
