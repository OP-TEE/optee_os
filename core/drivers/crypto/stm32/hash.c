// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2025, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <crypto/crypto_impl.h>
#include <crypto/crypto.h>
#include <drvcrypt_hash.h>
#include <drvcrypt.h>
#include <kernel/dt.h>
#include <string.h>

#include "common.h"
#include "stm32_hash.h"

static const struct crypto_hash_ops hash_ops;

struct stm32_hash_ctx {
	struct crypto_hash_ctx ch_ctx;
	struct stm32_hash_context hash;
};

static struct stm32_hash_ctx *to_stm32_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &hash_ops);

	return container_of(ctx, struct stm32_hash_ctx, ch_ctx);
}

/*
 * Initialization of the Hash operation
 *
 * @ctx   Operation software context
 */
static TEE_Result do_hash_init(struct crypto_hash_ctx *ctx)
{
	struct stm32_hash_ctx *c = to_stm32_hash_ctx(ctx);

	return stm32_hash_init(&c->hash, NULL, 0);
}

/*
 * Update the Hash operation
 *
 * @ctx   Operation software context
 * @data  Data to hash
 * @len   Data length
 */
static TEE_Result do_hash_update(struct crypto_hash_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	struct stm32_hash_ctx *c = to_stm32_hash_ctx(ctx);

	return stm32_hash_update(&c->hash, data, len);
}

/*
 * Finalize the Hash operation
 *
 * @ctx     Operation software context
 * @digest  [out] Hash digest buffer
 * @len     Digest buffer length
 */
static TEE_Result do_hash_final(struct crypto_hash_ctx *ctx, uint8_t *digest,
				size_t len)
{
	struct stm32_hash_ctx *c = to_stm32_hash_ctx(ctx);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t block_digest[STM32_HASH_MAX_DIGEST_SIZE] = { 0 };
	uint8_t *tmp_digest = digest;

	if (len < stm32_hash_digest_size(&c->hash))
		tmp_digest = block_digest;

	res = stm32_hash_final(&c->hash, tmp_digest, NULL, 0);

	if (res == TEE_SUCCESS && len < stm32_hash_digest_size(&c->hash))
		memcpy(digest, tmp_digest, len);

	return res;
}

/*
 * Free the SW hashing data context
 *
 * @ctx    [in/out] Caller context variable
 */
static void do_hash_free(struct crypto_hash_ctx *ctx)
{
	struct stm32_hash_ctx *c = to_stm32_hash_ctx(ctx);

	stm32_hash_free(&c->hash);
	free(c);
}

/*
 * Copy Software Hashing Context
 *
 * @dst_ctx  [out] Reference the context destination
 * @src_ctx  Reference the context source
 */
static void do_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
			       struct crypto_hash_ctx *src_ctx)
{
	struct stm32_hash_ctx *src = to_stm32_hash_ctx(src_ctx);
	struct stm32_hash_ctx *dst = to_stm32_hash_ctx(dst_ctx);

	memcpy(&dst->ch_ctx, &src->ch_ctx, sizeof(dst->ch_ctx));
	stm32_hash_deep_copy(&dst->hash, &src->hash);
}

/*
 * Registration of the hash Driver
 */
static const struct crypto_hash_ops hash_ops = {
	.init = do_hash_init,
	.update = do_hash_update,
	.final = do_hash_final,
	.free_ctx = do_hash_free,
	.copy_state = do_hash_copy_state,
};

/*
 * Allocate the internal hashing data context
 *
 * @ctx    [out] Caller context variable
 * @algo   OP_TEE Algorithm ID
 */
static TEE_Result stm32_hash_allocate(struct crypto_hash_ctx **ctx,
				      uint32_t algo)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stm32_hash_ctx *c = NULL;
	enum stm32_hash_algo stm32_algo = STM32_HASH_SHA256;

	/* Convert TEE Algo id to stm32 hash id */
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

	res = stm32_hash_alloc(&c->hash, STM32_HASH_MODE, stm32_algo);
	if (res) {
		free(c);
		return res;
	}

	FMSG("Using HASH %"PRIu32, stm32_algo);
	c->ch_ctx.ops = &hash_ops;
	*ctx = &c->ch_ctx;

	return TEE_SUCCESS;
}

TEE_Result stm32_register_hash(void)
{
	return drvcrypt_register_hash(&stm32_hash_allocate);
}
