/*
 * Copyright (C) 2017, ARM Limited, All Rights Reserved
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __MBEDTLS_CIPHERTWO_H
#define __MBEDTLS_CIPHERTWO_H
#include <stddef.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CIPHER_C)
#include "mbedtls/cipher.h"
#include "mbedtls/cipher_internal.h"
#endif

#if defined(MBEDTLS_DES_C)
#include "mbedtls/des.h"
#endif

#if defined(MBEDTLS_AES_C)
#include "mbedtls/aes.h"
#endif

#endif /* MBEDTLS_CIPHERTWO_H */
