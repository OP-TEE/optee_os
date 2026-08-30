/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_POLICY_PLATFORM_H
#define __PAS_POLICY_PLATFORM_H

#include <auth/pas_policy.h>
#include <pta_qcom_pas.h>

static const struct pas_policy_entry pas_policy_map[] = {
	{ PAS_ID_QDSP6, SECBOOT_ADSP_SW_TYPE },
	{ PAS_ID_IRIS, SECBOOT_IRIS_SW_TYPE },
	{ PAS_ID_TURING, SECBOOT_TURING_SW_TYPE },
	{ PAS_ID_TURING1, SECBOOT_TURING1_SW_TYPE },
	{ PAS_ID_CAMERA, SECBOOT_CAMERA_SW_TYPE },
	{ PAS_ID_GPDSP0, SECBOOT_GPDSP0_SW_TYPE },
	{ PAS_ID_GPDSP1, SECBOOT_GPDSP1_SW_TYPE },
};

#endif /* __PAS_POLICY_PLATFORM_H */
