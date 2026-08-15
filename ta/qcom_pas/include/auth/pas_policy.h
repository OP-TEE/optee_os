/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __AUTH_PAS_POLICY_H
#define __AUTH_PAS_POLICY_H

#include <stdint.h>
#include <tee_api_types.h>

TEE_Result pas_policy_expected_swid(uint32_t pas_id, uint32_t *swid);

#endif /* __AUTH_PAS_POLICY_H */
