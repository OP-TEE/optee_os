/*
 * Copyright (C) 2017, ARM Limited, All Rights Reserved
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __MBEDTLS_MAC_H
#define __MBEDTLS_MAC_H
#include <stddef.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CMAC_C)
#include "mbedtls/cmac.h"
#endif

#endif /* MBEDTLS_MAC_H */
