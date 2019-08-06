/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Crypto Driver exported constants and interfaces.
 */
#ifndef __DRVCRYPT_H__
#define __DRVCRYPT_H__

#include <tee_api_types.h>

#ifdef CFG_CRYPTO_DRIVER_DEBUG
#define CRYPTO_TRACE	DMSG
#else
#define CRYPTO_TRACE(...)
#endif

/*
 * Crypto Library Algorithm enumeration
 */
enum drvcrypt_algo_id {
	CRYPTO_HASH = 0,     /* HASH driver */
	CRYPTO_MAX_ALGO      /* Maximum number of algo supported */
};

/*
 * Cryptographic buffer type
 */
struct drvcrypt_buf {
	uint8_t *data;   /* Pointer to the data buffer */
	size_t  length;  /* Length in bytes of the data buffer */
};

/*
 * Cryptographic module registration
 *
 * @algo_id  Crypto index in the array
 * @ops      Reference to the cryptographic module
 */
TEE_Result drvcrypt_register(enum drvcrypt_algo_id algo_id, void *ops);

/*
 * Cryptographic module modify registration
 *
 * @algo_id  Crypto index in the array
 * @ops      Reference to the cryptographic module
 */
void drvcrypt_register_change(enum drvcrypt_algo_id algo_id, void *ops);

/*
 * Returns the address of the crypto module structure
 *
 * @algo_id  Crypto index in the array
 */
void *drvcrypt_getmod(enum drvcrypt_algo_id algo_id);

#endif /* __DRVCRYPT_H__ */
