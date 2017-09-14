/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */
#ifndef __MBEDTLS_CONFIG_KERNEL_H
#define __MBEDTLS_CONFIG_KERNEL_H

#define MBEDTLS_HAVE_ASM

#if defined(CFG_CRYPTO_MD5)
#define MBEDTLS_MD5_C
#endif

#if defined(CFG_CRYPTO_SHA1)
#define MBEDTLS_SHA1_C
#endif

#if defined(CFG_CRYPTO_SHA224) || defined(CFG_CRYPTO_SHA256)
#define MBEDTLS_SHA256_C
#endif

#if defined(CFG_CRYPTO_SHA384) || defined(CFG_CRYPTO_SHA512)
#define MBEDTLS_SHA512_C
#endif

#if defined(CFG_CRYPTO_HMAC)
#define MBEDTLS_MD_C
#endif

#if defined(CFG_CRYPTO_AES)
#define MBEDTLS_AES_C
#endif

#if defined(CFG_CRYPTO_DES)
#define MBEDTLS_DES_C
#endif

#if defined(_CFG_CRYPTO_WITH_CIPHER) || defined(CFG_CRYPTO_CMAC)
#define MBEDTLS_CIPHER_C
#endif

#if defined(CFG_CRYPTO_CBC)
#define MBEDTLS_CIPHER_MODE_CBC
#endif

#if defined(CFG_CRYPTO_CTR)
#define MBEDTLS_CIPHER_MODE_CTR
#endif

#if defined(CFG_CRYPTO_CMAC)
#define MBEDTLS_CMAC_C
#endif

#if defined(_CFG_CRYPTO_WITH_ACIPHER)
#define MBEDTLS_BIGNUM_C
#endif

#include <mbedtls/check_config.h>

#endif /* __MBEDTLS_CONFIG_KERNEL_H */
