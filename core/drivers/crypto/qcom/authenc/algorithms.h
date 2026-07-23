/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#ifndef AEAD_ALGORITHMS_H
#define AEAD_ALGORITHMS_H

#include <tee_api_types.h>

#if defined(CFG_QCOM_CE_AES_GCM)
TEE_Result ce_aes_gcm_allocate(void **ctx);
#endif

#endif /* AEAD_ALGORITHMS_H */
