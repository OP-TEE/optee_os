/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_POLICY_PLATFORM_H
#define __PAS_POLICY_PLATFORM_H

#include <auth/pas_policy.h>
#include <pta_qcom_pas.h>

static const struct pas_policy_entry pas_policy_map[] = {
	{ DTB_ID_LMCU, SECBOOT_LPAICP_DTB_SW_TYPE },
	{ PAS_ID_LMCU, SECBOOT_LPAICP_MISSION_MODE_SW_TYPE },
	{ PAS_ID_TURING, SECBOOT_TURING_SW_TYPE },
};

#endif /* __PAS_POLICY_PLATFORM_H */
