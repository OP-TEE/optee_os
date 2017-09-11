/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */
#ifndef __MBEDTLS_CONFIG_KERNEL_H
#define __MBEDTLS_CONFIG_KERNEL_H

#ifdef CFG_CORE_MBEDTLS_MPI
#ifdef ARM32
#define MBEDTLS_HAVE_INT32
#endif
#ifdef ARM64
#define MBEDTLS_HAVE_INT64
#endif
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_GENPRIME
#endif

/* Test if Mbedtls is the primary crypto lib */
#ifdef CFG_CRYPTOLIB_NAME_mbedtls

#if defined(CFG_CRYPTO_MD5)
#define MBEDTLS_MD5_C
#define MBEDTLS_MD_C
#endif

#if defined(CFG_CRYPTO_SHA1)
#define MBEDTLS_SHA1_C
#define MBEDTLS_MD_C
#endif

#if defined(CFG_CRYPTO_SHA224) || defined(CFG_CRYPTO_SHA256)
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD_C
#endif

#if defined(CFG_CRYPTO_SHA384) || defined(CFG_CRYPTO_SHA512)
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C
#endif

#if defined(CFG_CRYPTO_HMAC)
#define MBEDTLS_MD_C
#endif

#if defined(CFG_CRYPTO_AES)
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
#endif

#if defined(CFG_CRYPTO_DES)
#define MBEDTLS_DES_C
#endif

#if defined(CFG_CRYPTO_CBC)
#define MBEDTLS_CIPHER_MODE_CBC
#endif

#if defined(CFG_CRYPTO_CTR)
#define MBEDTLS_CIPHER_MODE_CTR
#endif

#if defined(CFG_CRYPTO_CMAC)
#define MBEDTLS_CMAC_C
#define MBEDTLS_CIPHER_C
#endif

#if defined(CFG_CRYPTO_RSA) || defined(CFG_CRYPTO_DSA) || \
    defined(CFG_CRYPTO_DH) || defined(CFG_CRYPTO_ECC)
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_PK_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_CTR_DRBG_C
#endif

#if defined(CFG_CRYPTO_RSA)
#define MBEDTLS_RSA_C
#define MBEDTLS_RSA_NO_CRT
#endif

#if defined(CFG_CRYPTO_RSA)
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#endif

#if defined(CFG_CRYPTO_DH)
#define MBEDTLS_DHM_C
#endif

#endif /*CFG_CRYPTOLIB_NAME_mbedtls*/

#include <mbedtls/check_config.h>

#endif /* __MBEDTLS_CONFIG_KERNEL_H */
