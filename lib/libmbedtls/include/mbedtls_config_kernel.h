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

#include <mbedtls/check_config.h>

#endif /* __MBEDTLS_CONFIG_KERNEL_H */
