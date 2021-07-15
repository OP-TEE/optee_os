/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019-2020 NXP
 *
 * MAC interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_MAC_H__
#define __DRVCRYPT_MAC_H__

#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <tee_api_types.h>

/*
 * Crypto library MAC driver operations
 */
struct drvcrypt_mac {
	TEE_Result (*alloc_key)(struct tee_cryp_obj_secret *key,
				uint32_t key_type);
	TEE_Result (*gen_key)(struct tee_cryp_obj_secret *key);
	TEE_Result (*alloc_ctx)(struct crypto_mac_ctx **ctx, uint32_t algo);
};

/*
 * Register a HMAC processing driver in the crypto API
 *
 * @allocate - Callback for driver context allocation in the crypto layer
 */
static inline TEE_Result drvcrypt_register_hmac(struct drvcrypt_mac *ops)
{
	return drvcrypt_register(CRYPTO_HMAC, (void *)ops);
}

/*
 * Register a CMAC processing driver in the crypto API
 *
 * @allocate - Callback for driver context allocation in the crypto layer
 */
static inline TEE_Result drvcrypt_register_cmac(struct drvcrypt_mac *ops)
{
	return drvcrypt_register(CRYPTO_CMAC, (void *)ops);
}
#endif /* __DRVCRYPT_MAC_H__ */
