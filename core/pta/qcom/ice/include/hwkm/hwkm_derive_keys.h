/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __HWKM_DERIVE_KEYS_H
#define __HWKM_DERIVE_KEYS_H

#include <tee_api_types.h>

TEE_Result derive_l4_wrapping_key(void);
TEE_Result clear_l4_wrapping_key(void);

#endif /* __HWKM_DERIVE_KEYS_H */
