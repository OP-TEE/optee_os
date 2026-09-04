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
#define SECBOOT_GPDSP0_SW_TYPE	0x58
#define SECBOOT_GPDSP1_SW_TYPE	0x5A

enum pas_arb_fuse_bank {
	PAS_ARB_HLOS_FUSE_BANK = 0,
	PAS_ARB_UEFI_FUSE_BANK,
	PAS_ARB_SEPARATE_FUSE_BANK,
};

struct pas_policy_entry {
	uint32_t pas_id;
	uint32_t swid;
	enum pas_arb_fuse_bank arb_bank;
};

TEE_Result pas_policy_expected_swid(uint32_t pas_id, uint32_t *swid);

TEE_Result pas_policy_expected_arb_bank(uint32_t pas_id,
					enum pas_arb_fuse_bank *bank);

#endif /* __AUTH_PAS_POLICY_H */
