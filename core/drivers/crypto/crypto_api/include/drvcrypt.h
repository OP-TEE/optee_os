/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    drvcrypt.h
 *
 * @brief   Crypto Driver exported constants and interfaces.
 */
#ifndef __DRVCRYPT_H__
#define __DRVCRYPT_H__

/* Global includes */
#include <tee_api_types.h>

#ifdef CFG_CRYPTO_DRV_DBG
#define CRYPTO_TRACE	DMSG
#else
#define CRYPTO_TRACE(...)
#endif

/**
 * @brief   Crypto Library Algorithm enumeration
 */
enum drvcrypt_algo_id {
	CRYPTO_HASH = 0,     ///< HASH driver
	CRYPTO_HMAC,         ///< HMAC driver
	CRYPTO_CIPHER,       ///< CIPHER driver
	CRYPTO_ECC,          ///< Assymetric ECC driver
	CRYPTO_MAX_ALGO      ///< Maximum number of algo supported
};

/**
 * @brief   Cryptographic buffer type
 */
struct drvcrypt_buf {
	uint8_t *data;   ///< Pointer to the data buffer
	size_t  length;  ///< Length in bytes of the data buffer
};

/**
 * @brief   Cryptographic module registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 *
 * @retval  0   Success
 * @retval (-1) Error
 */
int drvcrypt_register(enum drvcrypt_algo_id idx, void *ops);

/**
 * @brief   Cryptographic module modify registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 */
void drvcrypt_register_change(enum drvcrypt_algo_id idx, void *ops);

/**
 * @brief   Returns the address of the crypto module structure
 *
 * @param[in] idx  Crypto index in the array
 *
 * retval  address of the crypto module structure
 */
void *drvcrypt_getmod(enum drvcrypt_algo_id idx);

#endif /* __DRVCRYPT_H__ */
