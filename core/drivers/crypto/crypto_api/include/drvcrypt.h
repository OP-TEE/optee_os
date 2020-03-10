/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 *
 * Brief   Crypto Driver exported constants and interfaces.
 */
#ifndef __DRVCRYPT_H__
#define __DRVCRYPT_H__

#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

/*
 * Debug Macros function of Crypto Driver Debug Level setting
 * The CFG_CRYPTO_DRV_DBG is a bit mask 32 bits value defined
 * as followed:
 */
#define DRV_DBG_TRACE BIT32(0) /* Driver trace */
#define DRV_DBG_BUF   BIT32(1) /* Driver dump Buffer */

#if (CFG_CRYPTO_DRIVER_DEBUG & DRV_DBG_TRACE)
#define CRYPTO_TRACE DMSG
#else
#define CRYPTO_TRACE(...)
#endif
#if (CFG_CRYPTO_DRIVER_DEBUG & DRV_DBG_BUF)
#define CRYPTO_DUMPBUF(title, buf, len)                                        \
	do {                                                                   \
		__typeof__(buf) _buf = (buf);                                  \
		__typeof__(len) _len = (len);                                  \
		CRYPTO_TRACE("%s @%p: %zu", title, _buf, _len);                \
		dhex_dump(NULL, 0, 0, _buf, _len);                             \
	} while (0)
#else
#define CRYPTO_DUMPBUF(...)
#endif

/*
 * Definition of a crypto buffer type
 */
struct drvcrypt_buf {
	uint8_t *data;
	size_t length;
};

/*
 * Crypto Library Algorithm enumeration
 */
enum drvcrypt_algo_id {
	CRYPTO_HASH = 0, /* Hash driver */
	CRYPTO_HMAC,	 /* HMAC driver */
	CRYPTO_CMAC,	 /* CMAC driver */
	CRYPTO_RSA,      /* Asymmetric RSA driver */
	CRYPTO_MATH,	 /* Mathematical driver */
	CRYPTO_CIPHER,   /* Cipher driver */
	CRYPTO_ECC,      /* Asymmetric ECC driver */
	CRYPTO_DH,       /* Asymmetric DH driver */
	CRYPTO_DSA,	 /* Asymmetric DSA driver */
	CRYPTO_MAX_ALGO  /* Maximum number of algo supported */
};

/*
 * Register the Cryptographic's operation in the table of modules
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
 * Return the Cryptographic's operation (function/structure) registered in
 * the table of modules.
 *
 * @algo_id  ID of the Cryptographic module
 */
void *drvcrypt_get_ops(enum drvcrypt_algo_id algo_id);

#endif /* __DRVCRYPT_H__ */
