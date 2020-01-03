// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Crypto MAC interface implementation to enable HW driver.
 */
#include <assert.h>
#include <drvcrypt.h>
#include <drvcrypt_mac.h>
#include <utee_defines.h>
#include <util.h>

TEE_Result drvcrypt_mac_alloc_ctx(struct crypto_mac_ctx **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	drvcrypt_mac_allocate mac_alloc = NULL;
	unsigned int algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	CRYPTO_TRACE("mac alloc_ctx algo 0x%" PRIX32, algo);

	assert(ctx);

	if (algo_id >= TEE_MAIN_ALGO_MD5 && algo_id <= TEE_MAIN_ALGO_SHA512)
		mac_alloc = drvcrypt_get_ops(CRYPTO_HMAC);
	else
		mac_alloc = drvcrypt_get_ops(CRYPTO_CMAC);

	if (mac_alloc)
		ret = mac_alloc(ctx, algo);

	CRYPTO_TRACE("mac alloc_ctx ret 0x%" PRIX32, ret);

	return ret;
}
