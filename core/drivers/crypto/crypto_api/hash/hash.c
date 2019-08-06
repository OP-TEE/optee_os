// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Crypto Hash interface implementation to enable HW driver.
 */
#include <assert.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <malloc.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

/*
 * Format the HASH context to keep the reference to the
 * operation driver
 */
struct crypto_hash {
	struct crypto_hash_ctx hash_ctx; /* Crypto Hash API context */
	void *ctx;                       /* Hash Context */
	struct drvcrypt_hash *op;        /* Reference to the operation */
};

static const struct crypto_hash_ops hash_ops;

/*
 * Returns the reference to the driver context
 *
 * @ctx  API Context
 */
static struct crypto_hash *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &hash_ops);

	return container_of(ctx, struct crypto_hash, hash_ctx);
}

/*
 * Checks and returns reference to the driver operations
 *
 * @algo  Algorithm
 * @id    [out] Hash Algorithm internal ID
 */
static struct drvcrypt_hash *do_check_algo(uint32_t algo, uint8_t *id)
{
	struct drvcrypt_hash *hash = NULL;
	uint8_t algo_op = 0;
	uint8_t algo_id = 0;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	if (algo_op == TEE_OPERATION_DIGEST &&
	    (algo_id >= TEE_MAIN_ALGO_MD5 &&
	     algo_id <= TEE_MAIN_ALGO_SHA512)) {
		hash = drvcrypt_getmod(CRYPTO_HASH);

		/* Verify that the HASH HW implements this algorithm */
		if (id)
			*id = algo_id;
	}

	CRYPTO_TRACE("Check Hash algo %d ret 0x%" PRIxPTR, algo_id,
		     (uintptr_t)hash);

	return hash;
}

/*
 * Free the Software Hashing Context function of the algorithm
 *
 * @ctx    Reference the API context
 */
static void hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	/* Check the parameters */
	if (hash->op && hash->op->free_ctx)
		hash->op->free_ctx(hash->ctx);

	free(hash);
}

/*
 * Copy Software Hashing Context
 *
 * @src_ctx  Reference the API context source
 * @dst_ctx  [out] Reference the API context destination
 */
static void hash_copy_state(struct crypto_hash_ctx *dst_ctx,
			    struct crypto_hash_ctx *src_ctx)
{
	struct crypto_hash *hash_src = to_hash_ctx(src_ctx);
	struct crypto_hash *hash_dst = to_hash_ctx(dst_ctx);

	if (hash_src->op && hash_src->op->copy_state)
		hash_src->op->copy_state(hash_dst->ctx, hash_src->ctx);
}

/*
 * Initialization of the Hash operation
 *
 * @ctx   Reference the API context
 */
static TEE_Result hash_init(struct crypto_hash_ctx *ctx)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_hash *hash = to_hash_ctx(ctx);

	if (hash->op && hash->op->init)
		ret = hash->op->init(hash->ctx);

	CRYPTO_TRACE("hash ret 0x%" PRIX32, ret);

	return ret;
}

/*
 * Update the Hash operation
 *
 * @ctx   Reference the API context
 * @data  Data to hash
 * @len   Data length
 */
static TEE_Result hash_update(struct crypto_hash_ctx *ctx, const uint8_t *data,
			      size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_hash *hash = to_hash_ctx(ctx);

	/* Check the parameters */
	if (!data && len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->op && hash->op->update)
		ret = hash->op->update(hash->ctx, data, len);

	CRYPTO_TRACE("hash ret 0x%" PRIX32, ret);
	return ret;
}

/*
 * Finalize the Hash operation
 *
 * @ctx     Reference the API context
 * @len     Digest buffer length
 * @digest  [out] Hash digest buffer
 */
static TEE_Result hash_final(struct crypto_hash_ctx *ctx, uint8_t *digest,
			     size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_hash *hash = to_hash_ctx(ctx);

	/* Check the parameters */
	if (!digest || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->op && hash->op->final)
		ret = hash->op->final(hash->ctx, digest, len);

	CRYPTO_TRACE("hash ret 0x%" PRIX32, ret);
	return ret;
}

static const struct crypto_hash_ops hash_ops = {
	.init = hash_init,
	.update = hash_update,
	.final = hash_final,
	.free_ctx = hash_free_ctx,
	.copy_state = hash_copy_state,
};

/*
 * Allocates the Software Hashing Context function of the algorithm
 * and if the HW handles it. Else return on error and let the
 * global cryptographic core module to call SW library enabled.
 *
 * @ctx    Reference the context pointer
 * @algo   Algorithm
 * @ctx    [out] Reference the context pointer
 */
TEE_Result drvcrypt_hash_alloc_ctx(struct crypto_hash_ctx **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_hash *hash = NULL;
	uint8_t hash_id = 0;

	CRYPTO_TRACE("hash alloc_ctx algo 0x%" PRIX32, algo);

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	hash = calloc(1, sizeof(*hash));
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	hash->op = do_check_algo(algo, &hash_id);
	if (hash->op && hash->op->alloc_ctx)
		ret = hash->op->alloc_ctx(&hash->ctx, hash_id);

	if (ret != TEE_SUCCESS) {
		free(hash);
		*ctx = NULL;
	} else {
		hash->hash_ctx.ops = &hash_ops;
		*ctx = &hash->hash_ctx;
	}

	CRYPTO_TRACE("hash alloc_ctx ret 0x%" PRIX32, ret);

	return ret;
}
