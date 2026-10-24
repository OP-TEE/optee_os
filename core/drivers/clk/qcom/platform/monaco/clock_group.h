/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef _CLOCK_GROUP_QCOM_H_
#define _CLOCK_GROUP_QCOM_H_

/*
 * PAS per-instance registers; the sequences and the subsystem register
 * layout are in hoya/clock_hoya.h.
 */

/* GCC config-NoC AHB and aggre-NoC AXI branches (within the GCC window) */
#define GCC_TURING_0_CFG_AHB_CBCR		0x41028
#define GCC_GPDSP_0_CFG_AHB_CBCR		0x16008
#define GCC_AGGRE_NOC_GPDSP_0_AXI_CBCR		0x16004

/* AOSS_CC_COMPUTESS_RESTART and AOSS_CC_GPDSP_RESTART bit */
#define AOSS_CC_SS_0_RESTART_BIT		BIT(0)

/* RPMH_PDC_SYNC_RESET bits */
#define PDC_SYNC_RESET_GPDSP0_BIT		BIT(1)
#define PDC_SYNC_RESET_COMPUTE_BIT		BIT(9)

/* TCSR master-halt and power registers (within the TCSR mutex window) */
#define TCSR_TURING_HALTREQ			0x34000
#define TCSR_TURING_HALTACK			0x34004
#define TCSR_TURING_MASTER_IDLE			0x34008
#define TCSR_TURING_PWR_ON			0x3400c
#define TCSR_GPDSP0_HALT_REQ			0x32000
#define TCSR_GPDSP0_HALT_ACK			0x32004
#define TCSR_GPDSP0_IL0_MASTER_IDLE		0x32008
#define TCSR_GPDSP0_IL1_MASTER_IDLE		0x3200c
#define TCSR_GPDSP0_PWR_ON			0x32010

/*
 * NSP soft SKU, in TCSR_SPARE_RG63_WO_1: when bit 0 is clear, bits [15:8]
 * hold the Q6 PLL L value to boot the NSP with. An L value below the
 * default boots it at 768 MHz instead.
 */
#define NSP_SOFT_SKU_DISABLE_BIT		BIT(0)
#define NSP_SOFT_SKU_Q6_PLL_L_VAL_MASK		GENMASK_32(15, 8)
#define NSP_SOFT_SKU_Q6_PLL_L_VAL_SHIFT		8
#define NSP_SOFT_SKU_Q6_PLL_L_VAL_768MHZ	0x28

#endif /* _CLOCK_GROUP_QCOM_H_ */
