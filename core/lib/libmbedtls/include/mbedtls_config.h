/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018, ARM Limited
 */

#ifndef MBEDTLS_FEATURE_CONFIG_H
#define MBEDTLS_FEATURE_CONFIG_H

#define MBEDTLS_HAVE_ASM

#if defined(CFG_CRYPTO_MD5)
#define MBEDTLS_MD5_C
#endif

#if defined(CFG_CRYPTO_SHA1)
#define MBEDTLS_SHA1_C
#endif

#if defined(CFG_CRYPTO_SHA224) || defined(CFG_CRYPTO_SHA256) \
	|| defined(CFG_MBEDTLS_HMAC_PRNG)
#define MBEDTLS_SHA256_C
#endif

#if defined(CFG_CRYPTO_SHA384) || defined(CFG_CRYPTO_SHA512)
#define MBEDTLS_SHA512_C
#endif

#if defined(CFG_CRYPTO_HMAC) || defined(CFG_MBEDTLS_HMAC_PRNG)
#define MBEDTLS_MD_C
#endif

#if defined(CFG_CRYPTO_AES) || defined(CFG_MBEDTLS_CTR_PRNG)
#define MBEDTLS_AES_C
#endif

#if defined(CFG_MBEDTLS_CTR_PRNG) || defined(CFG_MBEDTLS_HMAC_PRNG)
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#endif

#if defined(CFG_MBEDTLS_CTR_PRNG)
#define MBEDTLS_CTR_DRBG_C
#endif

#if defined(CFG_MBEDTLS_HMAC_PRNG)
#define MBEDTLS_HMAC_DRBG_C
#endif

#if defined(CFG_CRYPTO_DES)
#define MBEDTLS_DES_C
#endif

#if defined(_CFG_CRYPTO_WITH_CIPHER)
#define MBEDTLS_CIPHER_C
#endif

#if defined(CFG_CRYPTO_CBC)
#define MBEDTLS_CIPHER_MODE_CBC
#endif

#if defined(CFG_CRYPTO_CTR)
#define MBEDTLS_CIPHER_MODE_CTR
#endif

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_FEATURE_CONFIG_H */
