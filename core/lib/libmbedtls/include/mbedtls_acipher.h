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

#if defined(MBEDTLS_DHM_C)
#include "mbedtls/dhm.h"
#endif

#endif /* MBEDTLS_ACIPHER_H */
