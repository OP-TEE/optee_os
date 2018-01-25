/*
 * Copyright (C) 2017, ARM Limited, All Rights Reserved
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MBEDTLS_HASH_H
#define MBEDTLS_HASH_H
#include <stddef.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MD_C)
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#endif

#endif /* MBEDTLS_HASH_H */
