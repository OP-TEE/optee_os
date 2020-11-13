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
 * Crypto library HMAC driver allocation function prototype
 */
typedef TEE_Result (*drvcrypt_mac_allocate)(struct crypto_mac_ctx **ctx,
					    uint32_t algo);

/*
 * Register a HMAC processing driver in the crypto API
 *
 * @allocate - Callback for driver context allocation in the crypto layer
 */
static inline TEE_Result drvcrypt_register_hmac(drvcrypt_mac_allocate allocate)
{
	return drvcrypt_register(CRYPTO_HMAC, (void *)allocate);
}

/*
 * Register a CMAC processing driver in the crypto API
 *
 * @allocate - Callback for driver context allocation in the crypto layer
 */
static inline TEE_Result drvcrypt_register_cmac(drvcrypt_mac_allocate allocate)
{
	return drvcrypt_register(CRYPTO_CMAC, (void *)allocate);
}
#endif /* __DRVCRYPT_MAC_H__ */
