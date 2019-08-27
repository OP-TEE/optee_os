// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Crypto Hash interface implementation to enable HW driver.
 */
#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <utee_defines.h>
#include <util.h>

/*
 * Checks and returns reference to the driver operations
 *
 * @algo  Algorithm
 * @id    [out] Hash Algorithm internal ID
 */
static hw_hash_allocate do_check_algo(uint32_t algo, uint8_t *id)
{
	hw_hash_allocate hash_alloc = NULL;
	uint8_t algo_op = 0;
	uint8_t algo_id = 0;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	if (algo_op == TEE_OPERATION_DIGEST &&
	    (algo_id >= TEE_MAIN_ALGO_MD5 &&
	     algo_id <= TEE_MAIN_ALGO_SHA512)) {
		hash_alloc = drvcrypt_getmod(CRYPTO_HASH);

		/* Verify that the HASH HW implements this algorithm */
		if (id)
			*id = algo_id;
	}

	CRYPTO_TRACE("Check Hash algo %d ret 0x%" PRIxPTR, algo_id,
		     (uintptr_t)hash_alloc);

	return hash_alloc;
}

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
	hw_hash_allocate hash_alloc = NULL;
	uint8_t hash_id = 0;

	CRYPTO_TRACE("hash alloc_ctx algo 0x%" PRIX32, algo);

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	hash_alloc = do_check_algo(algo, &hash_id);
	if (hash_alloc)
		ret = hash_alloc(ctx, hash_id);

	CRYPTO_TRACE("hash alloc_ctx ret 0x%" PRIX32, ret);

	return ret;
}
