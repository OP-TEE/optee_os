/*
 * Copyright (C) 2017, ARM Limited, All Rights Reserved
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MBEDTLS_FEATURE_CONFIG_H
#define MBEDTLS_FEATURE_CONFIG_H

#include "mbedtls/config.h"

/**
 * \def MBEDTLS_SELF_TEST
 *
 * Disable the checkup functions (*_self_test).
 */
#ifdef MBEDTLS_SELF_TEST
#undef MBEDTLS_SELF_TEST
#endif

/**
 * \def MBEDTLS_FS_IO
 *
 * Disable functions that use the filesystem.
 */
#ifdef MBEDTLS_FS_IO
#undef MBEDTLS_FS_IO
#endif

/**
 * \def MBEDTLS_RIPEMD160_C
 *
 * Disable the RIPEMD-160 hash algorithm.
 */
#ifdef MBEDTLS_RIPEMD160_C
#undef MBEDTLS_RIPEMD160_C
#endif

/**
 * \def MBEDTLS_HAVE_TIME
 *
 * Disable time functions
 */
#ifdef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME
#endif

/**
 * \def MBEDTLS_HAVE_TIME_DATE
 *
 * Disable time date
 */
#ifdef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_HAVE_TIME_DATE
#endif

/**
 * \def MBEDTLS_CMAC_C
 *
 * Enable the CMAC (Cipher-based Message Authentication Code) mode for block
 * ciphers.
 *
 * Module:  library/cmac.c
 *
 * Requires: MBEDTLS_AES_C or MBEDTLS_DES_C
 *
 */
#ifndef MBEDTLS_CMAC_C
#define MBEDTLS_CMAC_C
#endif

#define MBEDTLS_PLATFORM_PRINTF_MACRO	(void)

#define MBEDTLS_EXTERNAL_CTX_MANAGE

#ifdef MBEDTLS_CIPHER_PADDING_PKCS7
#undef MBEDTLS_CIPHER_PADDING_PKCS7
#endif

#endif /* MBEDTLS_FEATURE_CONFIG_H */
