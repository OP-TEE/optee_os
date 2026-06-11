/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef _CLOCK_GROUP_QCOM_H_
#define _CLOCK_GROUP_QCOM_H_

#define GCC_SEC_CTRL_CFG_RCGR			0x39038
#define GCC_SEC_CTRL_CMD_RCGR			0x39034
#define QFPROM_CLOCK_DIVIDE			0x7

#define GCC_TURING_0_CFG_AHB_CLK		0x41028
#define GCC_TURING_1_CFG_AHB_CLK		0x12028

/*
 * Turing/NSP clock-controller register offsets, identical for both NSP
 * instances; only the subsystem base differs (TURING_0_BASE / TURING_1_BASE).
 */
#define TURINGNSP_CC_OFFSET			0x02008000
#define TURINGNSP_Q6SS_ALT_RESET_AON		0x418
#define TURINGNSP_Q6SS_AHBS_AON			0x414
#define TURINGNSP_Q6SS_ALT_RESET_CTL		0x10034
#define TURINGNSP_NSPNOC			0x22c
#define TURINGNSP_VAPSS_GDSCR			0x80

/*
 * Additional Turing CC / QDSP6 PUB register offsets used by the reset sequence
 * (within the Turing CC and QDSP6 PUB blocks respectively).
 */
#define TURINGNSP_NSPAUX_XO_CBCR		0x40
#define TURINGNSP_NSPAUX_GDSCR			0x200
#define TURINGNSP_QDSP6SS_RET_CFG		0x1c

#define NSPAUX_GDSCR_RETAIN_FF_ENABLE_BIT	BIT(11)
#define Q6SS_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT	BIT(0)
#define QDSP6SS_RET_CFG_RET_ARES_ENA_BIT	BIT(0)

/*
 * Global blocks involved in the Turing reset (offsets within each window);
 * the GCC config-NoC AHB CBCRs gate the SWAY NIU socket.
 */
#define GCC_TURING_0_CFG_AHB_CBCR		0x41028
#define GCC_TURING_1_CFG_AHB_CBCR		0x12028
#define CBCR_CLK_ENABLE_BIT			BIT(0)

/* AOSS_CC compute-subsystem restart (within AOSS_CC window). */
#define AOSS_CC_COMPUTESS_RESTART		0x4f030
#define COMPUTESS_RESTART_SS_0_BIT		BIT(0)
#define COMPUTESS_RESTART_SS_1_BIT		BIT(1)

/* RPMH PDC global sync-reset (within RPMH_PDC_GLOBAL window). */
#define RPMH_PDC_SYNC_RESET			0x1000
#define PDC_SYNC_RESET_COMPUTE_BIT		BIT(9)
#define PDC_SYNC_RESET_NSP_BIT			BIT(12)

/* RPMH PDC per-block mode status, drv0 (within each PDC window). */
#define RPMH_PDC_MODE_STATUS_DRV0		0x1030
#define PDC_MODE_STATUS_SEQ_BUSY_BIT		BIT(0)

/*
 * TCSR Turing master-halt / power registers (offsets within the TCSR mutex
 * window); the CDSP1 block sits 0x18 above CDSP0.
 */
#define TCSR_TURING_HALTREQ			0x34000
#define TCSR_TURING_HALTACK			0x34004
#define TCSR_TURING_MASTER_IDLE			0x34008
#define TCSR_TURING_PWR_ON			0x3400c
#define TCSR_TURING1_HALT_REQ			0x34018
#define TCSR_TURING1_HALT_ACK			0x3401c
#define TCSR_TURING1_MASTER_IDLE		0x34020
#define TCSR_TURING1_PWR_ON			0x34028
#define TCSR_TURING_BIT				BIT(0)

/*
 * QDSP6 boot / PLL / core CC blocks relative to the subsystem base; the
 * enable-processor window at TURINGNSP_BOOT_OFFSET (0x50000) covers all three.
 */
#define TURINGNSP_BOOT_OFFSET			0x02300000
#define TURINGNSP_PROC_WINDOW_SIZE		0x50000
#define TURINGNSP_Q6_PLL_OFFSET			0x02340000
#define TURINGNSP_CORE_CC_OFFSET		0x02348000

/* Offsets within the boot block (TURINGNSP_BOOT_OFFSET). */
#define QDSP6SS_BOOT_CORE_START			0x400

/* Offsets within the core clock-controller block (TURINGNSP_CORE_CC_OFFSET). */
#define QDSP6SS_CORE_CMD_RCGR			0x20
#define QDSP6SS_CORE_CFG_RCGR			0x24

/*
 * Q6 core RCG: source select = Q6 PLL, divider = 1. CFG_RCGR holds SRC_SEL at
 * bits [10:8] and SRC_DIV at bits [4:0].
 */
#define Q6RCG_SRC_SEL				0x2
#define Q6RCG_SRC_SEL_SHIFT			8
#define Q6RCG_SRC_DIV				0x1
#define Q6RCG_CFG_VALUE				(((Q6RCG_SRC_SEL) << \
						  (Q6RCG_SRC_SEL_SHIFT)) | \
						 (Q6RCG_SRC_DIV))

/* Q6 Lucid-EVO PLL settings, identical for both NSP instances. */
#define TURINGNSP_Q6_PLL_L_VAL			0x32
#define TURINGNSP_Q6_PLL_CAL_L_VAL		0x44
#define TURINGNSP_Q6_PLL_CONFIG_CTL		0x20485699
#define TURINGNSP_Q6_PLL_CONFIG_CTL_U		0x00182261
#define TURINGNSP_Q6_PLL_CONFIG_CTL_U1		0x32AA299C
#define TURINGNSP_Q6_PLL_USER_CTL		0x00000000
#define TURINGNSP_Q6_PLL_USER_CTL_U		0x00400805

/*
 * LPASS / ADSP (QDSP6 v68/v69). All offsets are relative to LPASS_BASE; the
 * subsystem window is mapped once by the PAS PTA (pas_platform_mem_setup), so
 * the clock driver only derives sub-block bases as LPASS_BASE + offset.
 */
#define LPASS_PUB_OFFSET			0x00400000
#define LPASS_PLL_OFFSET			0x00440000
#define LPASS_CORE_CC_OFFSET			0x00448000
#define LPASS_AON_CC_OFFSET			0x00808000
#define LPASS_MCC_OFFSET			0x008d0000
#define LPASS_TOP_CC_OFFSET			0x01000000

/* Offsets within the QDSP6 PUB block (LPASS_PUB_OFFSET). */
#define LPASS_QDSP6SS_RST_EVB			0x10
#define LPASS_QDSP6SS_BOOT_CORE_START		0x400
#define LPASS_QDSP6SS_BOOT_CMD			0x404
#define LPASS_QDSP6SS_BOOT_STATUS		0x408

/* Offset within the MCC block (LPASS_MCC_OFFSET). */
#define LPASS_EFUSE_Q6SS_EVB_SEL		0xb000

/* Offsets within the core clock-controller block (LPASS_CORE_CC_OFFSET). */
#define LPASS_QDSP6SS_CORE_CMD_RCGR		0x0
#define LPASS_QDSP6SS_CORE_CFG_RCGR		0x4
#define LPASS_QDSP6SS_CORE_CBCR			0x20

/* Offsets within the always-on clock-controller block (LPASS_AON_CC_OFFSET). */
#define LPASS_AON_CC_Q6_AHBM_CBCR		0x101c
#define LPASS_AON_CC_Q6_AHBS_CBCR		0x1020

/* Offset within the LPASS top clock-controller block (LPASS_TOP_CC_OFFSET). */
#define LPASS_TOP_CC_LPI_Q6_AXIM_HS_CBCR	0x4000

/* GCC config-NoC LPASS access branch (offset within the GCC window). */
#define GCC_CFG_NOC_LPASS_CBCR			0x43024

/*
 * LPASS Q6 Lucid-EVO PLL settings, taken from the reference clock driver
 * HALclkPLLSettings.h (HAL_CLK_LPASS_AON_CC_LPASS_QDSP6SS_PLL_*). Identical to
 * the Turing Q6 PLL except for the L value.
 */
#define LPASS_Q6_PLL_L_VAL			0x2C
#define LPASS_Q6_PLL_CAL_L_VAL			0x44
#define LPASS_Q6_PLL_CONFIG_CTL			0x20485699
#define LPASS_Q6_PLL_CONFIG_CTL_U		0x00182261
#define LPASS_Q6_PLL_CONFIG_CTL_U1		0x32AA299C
#define LPASS_Q6_PLL_USER_CTL			0x00000000
#define LPASS_Q6_PLL_USER_CTL_U			0x00400805

#endif /* _CLOCK_GROUP_QCOM_H_ */
