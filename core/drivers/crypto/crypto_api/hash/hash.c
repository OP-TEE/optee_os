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
 * Allocate context for hashing operation if a drvcrypt hash driver is
 * registered.
 *
 * @ctx    [in/out] Reference the context pointer
 * @algo   Algorithm
 */
TEE_Result drvcrypt_hash_alloc_ctx(struct crypto_hash_ctx **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	hw_hash_allocate hash_alloc = NULL;
	uint8_t algo_id = 0;

	CRYPTO_TRACE("hash alloc_ctx algo 0x%" PRIX32, algo);

	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Extract the main algorithm */
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	hash_alloc = drvcrypt_getmod(CRYPTO_HASH);

	if (hash_alloc)
		ret = hash_alloc(ctx, algo_id);

	CRYPTO_TRACE("hash alloc_ctx ret 0x%" PRIX32, ret);

	return ret;
}
