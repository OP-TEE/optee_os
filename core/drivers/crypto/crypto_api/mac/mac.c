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

TEE_Result drvcrypt_mac_alloc_key(struct tee_cryp_obj_key *key,
				  uint32_t key_type)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_mac *mac = NULL;

	if (!key) {
		CRYPTO_TRACE("Parameters error (key @%p)", key);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mac = drvcrypt_get_ops(CRYPTO_xMAC);
	if (mac && mac->alloc_key)
		ret = mac->alloc_key(key, key_type);

	CRYPTO_TRACE("Cipher alloc ret 0x%" PRIX32, ret);

	return ret;
}

TEE_Result drvcrypt_mac_gen_key(struct tee_cryp_obj_key *key)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_mac *mac = NULL;

	if (!key) {
		CRYPTO_TRACE("Parameters error (key @%p)", key);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mac = drvcrypt_get_ops(CRYPTO_xMAC);
	if (mac && mac->gen_key)
		ret = mac->gen_key(key);

	CRYPTO_TRACE("Cipher alloc ret 0x%" PRIX32, ret);

	return ret;
}

TEE_Result drvcrypt_mac_alloc_ctx(struct crypto_mac_ctx **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_mac *mac = NULL;
	unsigned int algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	CRYPTO_TRACE("mac alloc_ctx algo 0x%" PRIX32, algo);

	assert(ctx);

	if (algo_id >= TEE_MAIN_ALGO_MD5 && algo_id <= TEE_MAIN_ALGO_SHA512)
		mac = drvcrypt_get_ops(CRYPTO_HMAC);
	else
		mac = drvcrypt_get_ops(CRYPTO_CMAC);

	if (mac && mac->alloc_ctx)
		ret = mac->alloc_ctx(ctx, algo);

	CRYPTO_TRACE("mac alloc_ctx ret 0x%" PRIX32, ret);

	return ret;
}
