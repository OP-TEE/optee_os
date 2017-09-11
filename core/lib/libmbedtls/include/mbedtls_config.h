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

#if defined(CFG_CRYPTO_CMAC)
#define MBEDTLS_CMAC_C
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

#if defined(_CFG_CRYPTO_WITH_ACIPHER)
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_PK_C
#define MBEDTLS_GENPRIME
#endif

#if defined(CFG_CRYPTO_RSA)
#define MBEDTLS_RSA_C
#define MBEDTLS_RSA_NO_CRT
#endif

#if defined(_CFG_CRYPTO_WITH_ASN1)
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#endif

#if defined(CFG_CRYPTO_DH)
#define MBEDTLS_DHM_C
#endif

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_FEATURE_CONFIG_H */
