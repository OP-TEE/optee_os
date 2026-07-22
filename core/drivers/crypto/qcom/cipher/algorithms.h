/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#ifndef CE_ALGORITHMS_H
#define CE_ALGORITHMS_H

#include <tee_api_types.h>

#if defined(CFG_QCOM_CE_AES_ECB)
TEE_Result ce_aes_ecb_allocate(void **ctx);
#endif

#if defined(CFG_QCOM_CE_AES_CBC)
TEE_Result ce_aes_cbc_allocate(void **ctx);
#endif

#endif /* CE_ALGORITHMS_H */
