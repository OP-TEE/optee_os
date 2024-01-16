/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2023, Linaro Limited
 */
#ifndef __SM_STD_SMC_H__
#define __SM_STD_SMC_H__

#include <sm/sm.h>

/* SMC function IDs for Standard Service queries */

#define ARM_STD_SVC_CALL_COUNT		0x8400ff00
#define ARM_STD_SVC_UID			0x8400ff01
/*                                      0x8400ff02 is reserved */
#define ARM_STD_SVC_VERSION		0x8400ff03

#define ARM_SMCCC_VERSION		0x80000000
#define ARM_SMCCC_ARCH_FEATURES		0x80000001
#define ARM_SMCCC_ARCH_SOC_ID		0x80000002
#define ARM_SMCCC_ARCH_WORKAROUND_1	0x80008000
#define ARM_SMCCC_ARCH_WORKAROUND_2	0x80007fff

#define ARM_SMCCC_RET_SUCCESS		0
#define ARM_SMCCC_RET_NOT_SUPPORTED	0xffffffff
#define ARM_SMCCC_RET_NOT_REQUIRED	0xfffffffe
#define ARM_SMCCC_RET_INVALID_PARAMETER	0xfffffffd

#define SMCCC_V_1_0			0x10000
#define SMCCC_V_1_1			0x10001
#define SMCCC_V_1_2			0x10002

/* ARM Standard Service Calls version numbers */
#define STD_SVC_VERSION_MAJOR		0x0
#define STD_SVC_VERSION_MINOR		0x1

/* The macros below are used to identify PSCI calls from the SMC function ID */
#define PSCI_FID_MASK			0xffe0u
#define PSCI_FID_VALUE			0u
#define is_psci_fid(_fid) \
	(((_fid) & PSCI_FID_MASK) == PSCI_FID_VALUE)

void smc_std_handler(struct thread_smc_args *args, struct sm_nsec_ctx *nsec);
#endif
