/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __HWKM_DERIVE_KEYS_H
#define __HWKM_DERIVE_KEYS_H

#include <tee_api_types.h>

#define HWKM_EPHEMERAL_CTX_SIZE 64U

TEE_Result derive_ephemeral_wrapping_key(const uint8_t *ephemeral_ctx,
                                         size_t ctx_len);
TEE_Result clear_ephemeral_key(void);

TEE_Result derive_l4_wrapping_key(void);
TEE_Result clear_l4_wrapping_key(void);

#endif /* __HWKM_DERIVE_KEYS_H */
