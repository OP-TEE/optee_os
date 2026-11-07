/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __AUTH_PAS_POLICY_H
#define __AUTH_PAS_POLICY_H

#include <stdint.h>
#include <tee_api_types.h>

#define SECBOOT_ADSP_SW_TYPE	0x04
#define SECBOOT_IRIS_SW_TYPE	0x0E
#define SECBOOT_TURING_SW_TYPE	0x17
#define SECBOOT_CAMERA_SW_TYPE	0x34
#define SECBOOT_TURING1_SW_TYPE	0x44
#define SECBOOT_ADSP1_SW_TYPE	0xA4
#define SECBOOT_ADSP2_SW_TYPE	0xA5
#define SECBOOT_Q6_CDSP_DTB_SW_TYPE	0x52
#define SECBOOT_Q6_ADSP_DTB_SW_TYPE	0x53
#define SECBOOT_Q6_CDSP1_DTB_SW_TYPE	0x57
#define SECBOOT_GPDSP0_SW_TYPE	0x58
#define SECBOOT_Q6_ADSP1_DTB_SW_TYPE	0xA6
#define SECBOOT_Q6_ADSP2_DTB_SW_TYPE	0xA7
#define SECBOOT_CDSP2_SW_TYPE	0xA8
#define SECBOOT_CDSP3_SW_TYPE	0xA9
#define SECBOOT_Q6_CDSP2_DTB_SW_TYPE	0xAA
#define SECBOOT_Q6_CDSP3_DTB_SW_TYPE	0xAB
#define SECBOOT_GPDSP1_SW_TYPE	0x5A

struct pas_swid_entry {
	uint32_t pas_id;
	uint32_t swid;
};

TEE_Result pas_policy_expected_swid(uint32_t pas_id, uint32_t *swid);

#endif /* __AUTH_PAS_POLICY_H */
