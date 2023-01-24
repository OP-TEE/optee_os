// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Crypto Hash interface implementation to enable HW driver.
 */
#include <assert.h>
#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <util.h>

TEE_Result drvcrypt_hash_alloc_ctx(struct crypto_hash_ctx **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	hw_hash_allocate hash_alloc = NULL;

	CRYPTO_TRACE("hash alloc_ctx algo 0x%" PRIX32, algo);

	assert(ctx);

	hash_alloc = drvcrypt_get_ops(CRYPTO_HASH);

	if (hash_alloc)
		ret = hash_alloc(ctx, algo);

	CRYPTO_TRACE("hash alloc_ctx ret 0x%" PRIX32, ret);

	return ret;
}
