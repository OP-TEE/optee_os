/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Hash interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_HASH_H__
#define __DRVCRYPT_HASH_H__

#include <crypto/crypto_impl.h>
#include <tee_api_types.h>

/*
 * Crypto Library Hash driver allocation function prototype
 */
typedef TEE_Result (*hw_hash_allocate)(struct crypto_hash_ctx **ctx,
				       uint8_t hash_id);

#endif /* __DRVCRYPT_HASH_H__ */
