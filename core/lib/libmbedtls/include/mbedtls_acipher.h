/*
 * Copyright (C) 2017, ARM Limited, All Rights Reserved
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MBEDTLS_ACIPHER_H
#define MBEDTLS_ACIPHER_H
#include <stddef.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/bignum.h"

#include "mbedtls/ctr_drbg.h"

#include "mbedtls/entropy.h"

#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#endif

#if defined(MBEDTLS_DHM_C)
#include "mbedtls/dhm.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDH_C)
#include "mbedtls/ecdh.h"
#endif

#endif /* MBEDTLS_ACIPHER_H */
