/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef _CLOCK_GROUP_QCOM_H_
#define _CLOCK_GROUP_QCOM_H_

/* Turing/NSP clock-controller register offsets (within TURINGNSP_CC_OFFSET) */
#define TURINGNSP_CC_OFFSET			0x02008000
#define TURINGNSP_NSPAUX_XO_CBCR		0x40
#define TURINGNSP_VAPSS_GDSCR			0x80
#define TURINGNSP_NSPAUX_GDSCR			0x200
#define TURINGNSP_NSPNOC			0x22c
#define TURINGNSP_Q6SS_AHBS_AON			0x414
#define TURINGNSP_Q6SS_ALT_RESET_AON		0x418
#define TURINGNSP_Q6SS_ALT_RESET_CTL		0x10034

#define NSPAUX_GDSCR_RETAIN_FF_ENABLE_BIT	BIT(11)
#define Q6SS_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT	BIT(0)

/*
 * QDSP6 boot, PLL and core clock-controller blocks relative to the subsystem
 * base; the window at TURINGNSP_BOOT_OFFSET covers all three.
 */
#define TURINGNSP_BOOT_OFFSET			0x02300000
#define TURINGNSP_PROC_WINDOW_SIZE		0x50000
#define TURINGNSP_Q6_PLL_OFFSET			0x02340000
#define TURINGNSP_CORE_CC_OFFSET		0x02348000

/* Offsets within the boot block (TURINGNSP_BOOT_OFFSET) */
#define TURINGNSP_QDSP6SS_RET_CFG		0x1c
#define QDSP6SS_BOOT_CORE_START			0x400

/* Offsets within the core clock-controller block (TURINGNSP_CORE_CC_OFFSET) */
#define QDSP6SS_CORE_CMD_RCGR			0x20
#define QDSP6SS_CORE_CFG_RCGR			0x24

#define QDSP6SS_RET_CFG_RET_ARES_ENA_BIT	BIT(0)
#define QDSP6SS_RET_CFG_NRET_ARES_ENA_BIT	BIT(1)

/* Q6 core RCG: source select = Q6 PLL (SRC_SEL, bits [10:8]), divider = 1 */
#define Q6RCG_SRC_SEL				0x2
#define Q6RCG_SRC_SEL_SHIFT			8
#define Q6RCG_SRC_DIV				0x1
#define Q6RCG_CFG_VALUE				(((Q6RCG_SRC_SEL) << \
						  (Q6RCG_SRC_SEL_SHIFT)) | \
						 (Q6RCG_SRC_DIV))

/* Turing Q6 Lucid-EVO PLL settings */
#define TURINGNSP_Q6_PLL_L_VAL			0x32
#define TURINGNSP_Q6_PLL_CAL_L_VAL		0x44
#define TURINGNSP_Q6_PLL_CONFIG_CTL		0x20485699
#define TURINGNSP_Q6_PLL_CONFIG_CTL_U		0x00182261
#define TURINGNSP_Q6_PLL_CONFIG_CTL_U1		0x32AA299C
#define TURINGNSP_Q6_PLL_USER_CTL		0x00000000
#define TURINGNSP_Q6_PLL_USER_CTL_U		0x00400805

/*
 * NSP soft SKU, in TCSR_SPARE_RG63_WO_1: when bit 0 is clear, bits [15:8]
 * hold the Q6 PLL L value to boot the NSP with. An L value below
 * TURINGNSP_Q6_PLL_L_VAL boots it at 768 MHz instead.
 */
#define NSP_SOFT_SKU_POR_VALUE			0xffffffff
#define NSP_SOFT_SKU_DISABLE_BIT		BIT(0)
#define NSP_SOFT_SKU_Q6_PLL_L_VAL_MASK		GENMASK_32(15, 8)
#define NSP_SOFT_SKU_Q6_PLL_L_VAL_SHIFT		8
#define NSP_SOFT_SKU_Q6_PLL_L_VAL_768MHZ	0x28

/*
 * LPASS / ADSP sub-block offsets relative to LPASS_BASE. The subsystem window
 * is mapped by the PAS PTA (pas_platform_mem_setup).
 */
#define LPASS_PUB_OFFSET			0x00400000
#define LPASS_PLL_OFFSET			0x00440000
#define LPASS_CORE_CC_OFFSET			0x00448000
#define LPASS_AON_CC_OFFSET			0x00808000
#define LPASS_TOP_CC_OFFSET			0x01000000

/* Offset within the QDSP6 PUB block (LPASS_PUB_OFFSET) */
#define LPASS_QDSP6SS_RET_CFG			0x1c

/* Offsets within the core clock-controller block (LPASS_CORE_CC_OFFSET) */
#define LPASS_QDSP6SS_CORE_CMD_RCGR		0x0
#define LPASS_QDSP6SS_CORE_CFG_RCGR		0x4
#define LPASS_QDSP6SS_CORE_CBCR			0x20

/* Offsets within the always-on clock-controller block (LPASS_AON_CC_OFFSET) */
#define LPASS_AON_CC_Q6_AHBM_CBCR		0x101c
#define LPASS_AON_CC_Q6_AHBS_CBCR		0x1020

/* Offset within the LPASS top clock-controller block (LPASS_TOP_CC_OFFSET) */
#define LPASS_TOP_CC_LPI_Q6_AXIM_HS_CBCR	0x4000

/* GCC config-NoC LPASS access branch (offset within the GCC window) */
#define GCC_CFG_NOC_LPASS_CBCR			0x43024

/* LPASS Q6 Lucid-EVO PLL settings */
#define LPASS_Q6_PLL_L_VAL			0x2C
#define LPASS_Q6_PLL_CAL_L_VAL			0x44
#define LPASS_Q6_PLL_CONFIG_CTL			0x20485699
#define LPASS_Q6_PLL_CONFIG_CTL_U		0x00182261
#define LPASS_Q6_PLL_CONFIG_CTL_U1		0x32AA299C
#define LPASS_Q6_PLL_USER_CTL			0x00000000
#define LPASS_Q6_PLL_USER_CTL_U			0x00400805

/* GP-DSP0 (TURINGGDSP) sub-block offsets relative to TURING_GDSP_0_BASE */
#define TURINGGDSP_GDSP_CC_OFFSET		0x00808000
#define TURINGGDSP_PUB_OFFSET			0x00c00000
#define TURINGGDSP_PLL_OFFSET			0x00c40000
#define TURINGGDSP_CORE_CC_OFFSET		0x00c48000

/* Offset within the GDSP_CC block (TURINGGDSP_GDSP_CC_OFFSET) */
#define TURINGGDSP_Q6SS_AHBS_AON_CBCR		0x10

/* Offsets within the QDSP6 PUB block (TURINGGDSP_PUB_OFFSET) */
#define TURINGGDSP_QDSP6SS_DBG_CFG		0x18
#define TURINGGDSP_QDSP6SS_RET_CFG		0x1c

/* Offsets within the core clock-controller block (TURINGGDSP_CORE_CC_OFFSET) */
#define TURINGGDSP_QDSP6SS_CORE_CMD_RCGR	0x0
#define TURINGGDSP_QDSP6SS_CORE_CFG_RCGR	0x4
#define TURINGGDSP_QDSP6SS_CORE_CBCR		0x20

/* GP-DSP Q6 Lucid-EVO PLL settings */
#define GPDSP_Q6_PLL_L_VAL			0x3A
#define GPDSP_Q6_PLL_CAL_L_VAL			0x44
#define GPDSP_Q6_PLL_CONFIG_CTL			0x20485699
#define GPDSP_Q6_PLL_CONFIG_CTL_U		0x00182261
#define GPDSP_Q6_PLL_CONFIG_CTL_U1		0x32AA299C
#define GPDSP_Q6_PLL_USER_CTL			0x00000000
#define GPDSP_Q6_PLL_USER_CTL_U			0x00400805

/* GCC config-NoC AHB and aggre-NoC AXI branches (within the GCC window) */
#define GCC_TURING_0_CFG_AHB_CBCR		0x41028
#define GCC_GPDSP_0_CFG_AHB_CBCR		0x16008
#define GCC_AGGRE_NOC_GPDSP_0_AXI_CBCR		0x16004
#define CBCR_CLK_ENABLE_BIT			BIT(0)

/* AOSS_CC subsystem restarts (within the AOSS_CC window) */
#define AOSS_CC_COMPUTESS_RESTART		0x4f030
#define AOSS_CC_GPDSP_RESTART			0x4f034
#define AOSS_CC_LPASS_RESTART			0x4f01c
#define AOSS_CC_SS_0_RESTART_BIT		BIT(0)

/* RPMH PDC global sync reset (within the RPMH_PDC_GLOBAL window) */
#define RPMH_PDC_SYNC_RESET			0x1000
#define PDC_SYNC_RESET_GPDSP0_BIT		BIT(1)
#define PDC_SYNC_RESET_AUDIO_BIT		BIT(2)
#define PDC_SYNC_RESET_COMPUTE_BIT		BIT(9)

/* RPMH PDC per-block mode status, drv0 (within each PDC window) */
#define RPMH_PDC_MODE_STATUS_DRV0		0x1030
#define PDC_MODE_STATUS_SEQ_BUSY_BIT		BIT(0)

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
#define TCSR_LPASS_HALTREQ			0x22000
#define TCSR_LPASS_HALTACK			0x22004
#define TCSR_HALT_BIT				BIT(0)

#endif /* _CLOCK_GROUP_QCOM_H_ */
