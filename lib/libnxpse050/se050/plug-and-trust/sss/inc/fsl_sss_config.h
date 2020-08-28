/*
 * Copyright 2018,2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FSL_SSS_CONFIG_H_
#define _FSL_SSS_CONFIG_H_

/* clang-format off */
#define SSS_SESSION_MAX_CONTEXT_SIZE        ( 0 \
    + (1 * sizeof(void *)) \
    + (1 * sizeof(void *)) \
    + (8 * sizeof(void *)) \
    + 16)
#define SSS_KEY_STORE_MAX_CONTEXT_SIZE      ( 0 \
    + (1 * sizeof(void *)) \
    + (4 * sizeof(void *)) \
    + 16)
#define SSS_KEY_OBJECT_MAX_CONTEXT_SIZE     ( 0 \
    + (1 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (4 * sizeof(void *)) \
    + 16)
#define SSS_SYMMETRIC_MAX_CONTEXT_SIZE      ( 0 \
    + (2 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 16 /* Buffer in case of unaligned block cipher operations */ \
    + 4  /* Buffer length in case of unaligned block cipher operations */ \
    + 16)
#define SSS_AEAD_MAX_CONTEXT_SIZE           ( 0 \
    + (5 * sizeof(void *)) \
    + (6 * sizeof(int)) \
    + (5 * sizeof(void *)) \
    + 16)
#define SSS_DIGEST_MAX_CONTEXT_SIZE         ( 0 \
    + (1 * sizeof(void *)) \
    + (3 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 16)
#define SSS_MAC_MAX_CONTEXT_SIZE            ( 0 \
    + (2 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 32)
#define SSS_ASYMMETRIC_MAX_CONTEXT_SIZE      ( 0 \
    + (2 * sizeof(void *)) \
    + (3 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 16)
#define SSS_TUNNEL_MAX_CONTEXT_SIZE         ( 0 \
    + (1 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 16)
#define SSS_CHANNEL_MAX_CONTEXT_SIZE         ( 0 \
    + (2 * sizeof(void *)) \
    + 16)
#define SSS_DERIVE_KEY_MAX_CONTEXT_SIZE     ( 0 \
    + (2 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 16)
#define SSS_RNG_MAX_CONTEXT_SIZE            ( 0 \
    + (1 * sizeof(void *)) \
    + (2 * sizeof(void *)) \
    + 16)

#define SSS_CONNECT_MAX_CONTEXT_SIZE ( 0 \
    + (4 * sizeof(void *)) \
    + 8 \
    )

#define SSS_AUTH_MAX_CONTEXT_SIZE ( 0 \
    + (3 * sizeof(void *)) \
    + 8 \
    )

#define SSS_POLICY_COUNT_MAX (10)

/* clang-format on */

#endif /* _FSL_SSS_CONFIG_H_ */
