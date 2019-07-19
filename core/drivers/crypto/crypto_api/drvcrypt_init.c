// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    drvcrypt_init.c
 *
 * @brief   This driver interfaces TEE Internal API by implementing
 *          all crypto_* functions. If an algorithm is not supported,
 *          the default NULL implementations are built and return
 *          TEE_ERROR_NOT_IMPLEMENTED
 */

/* Global includes */
#include <crypto/crypto.h>
#include <initcall.h>

/* Driver Crypto includes */
#include <drvcrypt.h>

/**
 * @brief   Pointers array to Cryptographic modules operation
 */
static void *crypt_algo[CRYPTO_MAX_ALGO] = {0};

/**
 * @brief   Cryptographic module registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 *
 * @retval  0   Success
 * @retval (-1) Error
 */
int drvcrypt_register(enum drvcrypt_algo_id idx, void *ops)
{
	if (crypt_algo[idx] == NULL) {
		CRYPTO_TRACE("Registering module id %d with 0x%"PRIxPTR"",
					idx, (uintptr_t)ops);
		crypt_algo[idx] = ops;
		return 0;
	}

	CRYPTO_TRACE("Fail to register module id %d with 0x%"PRIxPTR"",
				idx, (uintptr_t)ops);
	return (-1);
}

/**
 * @brief   Cryptographic module modify registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 */
void drvcrypt_register_change(enum drvcrypt_algo_id idx, void *ops)
{
	CRYPTO_TRACE("Change registered module id %d with 0x%"PRIxPTR"",
					idx, (uintptr_t)ops);
	crypt_algo[idx] = ops;
}

/**
 * @brief   Returns the address of the crypto module structure
 *
 * @param[in] idx  Crypto index in the array
 *
 * retval  address of the crypto module structure
 */
void *drvcrypt_getmod(enum drvcrypt_algo_id idx)
{
	return crypt_algo[idx];
}

