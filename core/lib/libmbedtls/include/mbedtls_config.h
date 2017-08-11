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

#define MBEDTLS_EXTERNAL_CTX_MANAGE

 /**
  * \def MBEDTLS_ECDSA_DETERMINISTIC
  *
  * Enable deterministic ECDSA (RFC 6979).
  * Standard ECDSA is "fragile" in the sense that lack of entropy when signing
  * may result in a compromise of the long-term signing key. This is avoided by
  * the deterministic variant.
  *
  * Requires: MBEDTLS_HMAC_DRBG_C
  *
  * Comment this macro to disable deterministic ECDSA.
  */
#ifdef MBEDTLS_ECDSA_DETERMINISTIC
#undef MBEDTLS_ECDSA_DETERMINISTIC
#endif

/**
 * \def MBEDTLS_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *          library/pkparse.c
 *          library/mbedtls_x509_crl.c
 *          library/mbedtls_x509_crt.c
 *          library/mbedtls_x509_csr.c
 *
 * Requires: MBEDTLS_BASE64_C
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#ifdef MBEDTLS_PEM_PARSE_C
#undef MBEDTLS_PEM_PARSE_C
#endif

/**
 * \def MBEDTLS_RSA_NO_CRT
 *
 * Do not use the Chinese Remainder Theorem for the RSA private operation.
 *
 * Uncomment this macro to disable the use of CRT in RSA.
 *
 */
#ifndef MBEDTLS_RSA_NO_CRT
#define MBEDTLS_RSA_NO_CRT
#endif

#define MBEDTLS_PLATFORM_PRINTF_MACRO	(void)

#endif /* MBEDTLS_FEATURE_CONFIG_H */
