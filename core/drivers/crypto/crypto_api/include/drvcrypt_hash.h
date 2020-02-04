/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   Hash interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_HASH_H__
#define __DRVCRYPT_HASH_H__

#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <tee_api_types.h>

/*
 * Crypto Library Hash driver allocation function prototype
 */
typedef TEE_Result (*hw_hash_allocate)(struct crypto_hash_ctx **ctx,
				       uint32_t algo);

/*
 * Register a hash processing driver in the crypto API
 *
 * @allocate - Callback for driver context allocation in the crypto layer
 */
static inline TEE_Result drvcrypt_register_hash(hw_hash_allocate allocate)
{
	return drvcrypt_register(CRYPTO_HASH, (void *)allocate);
}

#endif /* __DRVCRYPT_HASH_H__ */
