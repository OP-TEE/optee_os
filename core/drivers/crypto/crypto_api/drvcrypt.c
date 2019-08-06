// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   This driver interfaces TEE Cryptographic API crypto_*
 */
#include <crypto/crypto.h>
#include <drvcrypt.h>
#include <initcall.h>

static void *crypt_algo[CRYPTO_MAX_ALGO];

/*
 * Registers the Cryptographic's operation in the table of modules
 *
 * @algo_id  ID of the Cryptographic module
 * @ops      Operation (function/structure) to register
 */
TEE_Result drvcrypt_register(enum drvcrypt_algo_id algo_id, void *ops)
{
	if (!crypt_algo[algo_id]) {
		CRYPTO_TRACE("Registering module id %d with 0x%p", algo_id,
			     ops);
		crypt_algo[algo_id] = ops;
		return TEE_SUCCESS;
	}

	CRYPTO_TRACE("Fail to register module id %d with 0x%p", algo_id, ops);
	return TEE_ERROR_GENERIC;
}

/*
 * Modify the Cryptographic algorithm in the table of modules
 *
 * @algo_id  ID of the Cryptographic module
 * @ops      Operation (function/structure) to register
 */
void drvcrypt_register_change(enum drvcrypt_algo_id algo_id, void *ops)
{
	CRYPTO_TRACE("Change registered module id %d with 0x%p", algo_id, ops);
	crypt_algo[algo_id] = ops;
}

/*
 * Returns the Cryptographic's operation (function/structure) registered in
 * the table of modules.
 *
 * @algo_id  ID of the Cryptographic module
 */
void *drvcrypt_getmod(enum drvcrypt_algo_id algo_id)
{
	return crypt_algo[algo_id];
}
