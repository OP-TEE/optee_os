/*
 * Copyright (C) 2017, ARM Limited, All Rights Reserved
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBMBEDTLS_H
#define LIBMBEDTLS_H
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>

#if defined(_CFG_CRYPTO_WITH_HASH)
#include "mbedtls_hash.h"
#endif

#if defined(_CFG_CRYPTO_WITH_CIPHER)
#include "mbedtls_cipher.h"
#endif

#endif /* LIBMBEDTLS_H */
