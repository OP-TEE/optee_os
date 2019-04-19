// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hash.c
 *
 * @brief   Crypto Hash interface implementation to enable HW driver.
 */

/* Global includes */
#include <assert.h>
#include <crypto/crypto_impl.h>
#include <malloc.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_hash.h>

/**
 * @brief  Format the HASH context to keep the reference to the
 *         operation driver
 */
struct crypto_hash {
	struct crypto_hash_ctx hash_ctx; ///< Crypto Hash API context

	void                 *ctx; ///< Hash Context
	struct drvcrypt_hash *op;  ///< Reference to the operation
};

const struct crypto_hash_ops hash_ops;

/**
 * @brief   Checks if input API context is correct. If not, system break.
 *          Returns the reference to the driver context
 *
 * @param[in] ctx  API Context
 *
 * @retval  Reference to the driver context
 */
static struct crypto_hash *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &hash_ops);

	return container_of(ctx, struct crypto_hash, hash_ctx);
}

/**
 * @brief   Checks and returns reference to the driver operations
 *
 * @param[in]  algo  Algorithm
 * @param[out] id    Hash Algorithm internal ID
 *
 * @retval  Reference to the driver operations
 */
static struct drvcrypt_hash *do_check_algo(uint32_t algo,
						enum drvcrypt_hash_id *id)
{
	struct drvcrypt_hash *hash = NULL;
	uint8_t algo_op;
	uint8_t algo_id;
	enum drvcrypt_hash_id hash_id;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	if ((algo_op == TEE_OPERATION_DIGEST) &&
		((algo_id >= TEE_MAIN_ALGO_MD5) &&
		 (algo_id <= TEE_MAIN_ALGO_SHA512))) {

		hash_id = algo_id - 1;

		hash = drvcrypt_getmod(CRYPTO_HASH);

		/*
		 * Verify that the HASH HW implements this algorithm
		 * else return NULL pointer to call the Hash SW Library
		 */
		if (hash) {
			if (hash->max_hash < hash_id)
				hash = NULL;
		}

		/* Verify that the HASH HW implements this algorithm */
		if (id)
			*id = hash_id;
	}

	CRYPTO_TRACE("Check Hash algo %d ret 0x%"PRIxPTR"",
		algo_id, (uintptr_t)hash);

	return hash;
}

/**
 * @brief   Free the Software Hashing Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the API context
 *
 */
static void hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	/* Check the parameters */
	if (hash) {
		if (hash->op) {
			if (hash->op->free_ctx)
				hash->op->free_ctx(hash->ctx);
		}
		free(hash);
	}
}

/**
 * @brief   Copy Software Hashing Context
 *
 * @param[in]  src_ctx  Reference the API context source
 * @param[out] dst_ctx  Reference the API context destination
 *
 */
static void hash_copy_state(struct crypto_hash_ctx *dst_ctx,
		struct crypto_hash_ctx *src_ctx)
{
	struct crypto_hash *hash_src = to_hash_ctx(src_ctx);
	struct crypto_hash *hash_dst = to_hash_ctx(dst_ctx);

	if ((!dst_ctx) || (!src_ctx))
		return;

	if (hash_src->op) {
		if (hash_src->op->cpy_state)
			hash_src->op->cpy_state(hash_dst->ctx, hash_src->ctx);
	}
}

/**
 * @brief   Initialization of the Hash operation
 *
 * @param[in] ctx   Reference the API context
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm is not implemented
 */
static TEE_Result hash_init(struct crypto_hash_ctx *ctx)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_hash *hash = to_hash_ctx(ctx);

	/* Check the parameters */
	if (!hash)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->op) {
		if (hash->op->init)
			ret = hash->op->init(hash->ctx);
	}

	CRYPTO_TRACE("hash ret 0x%"PRIX32"", ret);

	return ret;
}

/**
 * @brief   Update the Hash operation
 *
 * @param[in] ctx   Reference the API context
 * @param[in] data  Data to hash
 * @param[in] len   Data length
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm is not implemented
 */
static TEE_Result hash_update(struct crypto_hash_ctx *ctx,
		const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_hash *hash = to_hash_ctx(ctx);

	/* Check the parameters */
	if ((!hash) || ((!data) && (len != 0)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->op) {
		if (hash->op->update)
			ret = hash->op->update(hash->ctx, data, len);
	}

	CRYPTO_TRACE("hash ret 0x%"PRIX32"", ret);
	return ret;
}

/**
 * @brief   Finalize the Hash operation
 *
 * @param[in] ctx   Reference the API context
 * @param[in] len   Digest buffer length
 *
 * @param[out] digest  Hash digest buffer
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm is not implemented
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result hash_final(struct crypto_hash_ctx *ctx,
		uint8_t *digest, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_hash *hash = to_hash_ctx(ctx);

	/* Check the parameters */
	if ((!hash) || (!digest) || (!len))
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->op) {
		if (hash->op->final)
			ret = hash->op->final(hash->ctx, digest, len);
	}

	CRYPTO_TRACE("hash ret 0x%"PRIX32"", ret);
	return ret;
}

const struct crypto_hash_ops hash_ops = {
	.init       = hash_init,
	.update     = hash_update,
	.final      = hash_final,
	.free_ctx   = hash_free_ctx,
	.copy_state = hash_copy_state,
};

/**
 * @brief   Allocates the Software Hashing Context function of the algorithm
 *          and if the HW handles it. Else return on error and let the
 *          global cryptographic core module to call SW library enabled.
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result drvcrypt_hash_alloc_ctx(struct crypto_hash_ctx **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_hash *hash = NULL;
	enum drvcrypt_hash_id hash_id;

	CRYPTO_TRACE("hash alloc_ctx algo 0x%"PRIX32"", algo);

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	hash = calloc(1, sizeof(*hash));
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	hash->op = do_check_algo(algo, &hash_id);
	if (hash->op) {
		if (hash->op->alloc_ctx)
			ret = hash->op->alloc_ctx(&hash->ctx, hash_id);
	}

	if (ret != TEE_SUCCESS) {
		free(hash);
		*ctx = NULL;
	} else {
		hash->hash_ctx.ops = &hash_ops;
		*ctx = &hash->hash_ctx;
	}

	CRYPTO_TRACE("hash alloc_ctx ret 0x%"PRIX32"", ret);

	return ret;
}

