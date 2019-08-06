/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Crypto Driver exported constants and interfaces.
 */
#ifndef __DRVCRYPT_H__
#define __DRVCRYPT_H__

#include <tee_api_types.h>
#include <trace.h>

#ifdef CFG_CRYPTO_DRIVER_DEBUG
#define CRYPTO_TRACE	DMSG
#else
#define CRYPTO_TRACE(...)
#endif

/*
 * Crypto Library Algorithm enumeration
 */
enum drvcrypt_algo_id {
	CRYPTO_HASH = 0, /* Hash driver */
	CRYPTO_MAX_ALGO  /* Maximum number of algo supported */
};

/*
 * Registers the Cryptographic's operation in the table of modules
 *
 * @algo_id  ID of the Cryptographic module
 * @ops      Operation (function/structure) to register
 */
TEE_Result drvcrypt_register(enum drvcrypt_algo_id algo_id, void *ops);

/*
 * Modify the Cryptographic algorithm in the table of modules
 *
 * @algo_id  ID of the Cryptographic module
 * @ops      Operation (function/structure) to register
 */
void drvcrypt_register_change(enum drvcrypt_algo_id algo_id, void *ops);

/*
 * Returns the Cryptographic's operation (function/structure) registered in
 * the table of modules.
 *
 * @algo_id  ID of the Cryptographic module
 */
void *drvcrypt_getmod(enum drvcrypt_algo_id algo_id);

#endif /* __DRVCRYPT_H__ */
