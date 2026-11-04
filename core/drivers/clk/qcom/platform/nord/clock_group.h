/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QUPv3 clock-controller register addresses for Nord (Wildcat family).
 *
 * Unlike lemans, Nord spreads its QUP serial engines across three clock
 * controllers: the SE and NE quadrant controllers (SE_GCC / NE_GCC), each with
 * its own GPLL0 and its own vote registers, plus the central GCC for wrapper 3.
 * Each register is a full physical address, formed from its own controller base
 * exactly as the HWIO_<CTLR>_..._ADDR counterpart in the Nord HWIO header does,
 * and named after that counterpart with the HWIO_ prefix dropped. The vote
 * registers are the TZ-owned bank
 * (HWIO_<CTLR>_APCS_TZ_{CLOCK,PLL}_BRANCH_ENA_VOTE*), which is what
 * PROC_CLK_BRANCH_ENA_VOTE* resolves to in a TZ image.
 *
 * Each register a domain touches is listed here by name, CBCR and CMD_RCGR
 * alike. The CBCR-to-CMD_RCGR distance is not architectural -- it is 0x10 for
 * a Nord SE, 8 on lemans, and neither for Nord's wrapper 3 -- so nothing here
 * derives one address from another.
 */

#ifndef _NORD_CLOCK_GROUP_H_
#define _NORD_CLOCK_GROUP_H_

#include <platform_config.h>

/*
 * SE_GCC (south-east quadrant): QUPv3 wrappers 0 and 1, seven SEs each.
 * Wrapper 1 sits one 0x1000 block above wrapper 0, and within a wrapper the
 * per-SE stride is 0x13c.
 */
#define SE_GCC_QUPV3_WRAP0_M_AHB_CBCR		(SE_GCC_BASE + 0x16004)
#define SE_GCC_QUPV3_WRAP0_S_AHB_CBCR		(SE_GCC_BASE + 0x16008)
#define SE_GCC_QUPV3_WRAP0_CORE_CBCR		(SE_GCC_BASE + 0x1600c)
#define SE_GCC_QUPV3_WRAP0_CORE_2X_CBCR		(SE_GCC_BASE + 0x16020)
#define SE_GCC_QUPV3_WRAP0_S0_CBCR		(SE_GCC_BASE + 0x1615c)
#define SE_GCC_QUPV3_WRAP0_S0_CMD_RCGR		(SE_GCC_BASE + 0x1616c)
#define SE_GCC_QUPV3_WRAP0_S1_CBCR		(SE_GCC_BASE + 0x16298)
#define SE_GCC_QUPV3_WRAP0_S1_CMD_RCGR		(SE_GCC_BASE + 0x162a8)
#define SE_GCC_QUPV3_WRAP0_S2_CBCR		(SE_GCC_BASE + 0x163d4)
#define SE_GCC_QUPV3_WRAP0_S2_CMD_RCGR		(SE_GCC_BASE + 0x163e4)
#define SE_GCC_QUPV3_WRAP0_S3_CBCR		(SE_GCC_BASE + 0x16510)
#define SE_GCC_QUPV3_WRAP0_S3_CMD_RCGR		(SE_GCC_BASE + 0x16520)
#define SE_GCC_QUPV3_WRAP0_S4_CBCR		(SE_GCC_BASE + 0x1664c)
#define SE_GCC_QUPV3_WRAP0_S4_CMD_RCGR		(SE_GCC_BASE + 0x1665c)
#define SE_GCC_QUPV3_WRAP0_S5_CBCR		(SE_GCC_BASE + 0x16788)
#define SE_GCC_QUPV3_WRAP0_S5_CMD_RCGR		(SE_GCC_BASE + 0x16798)
#define SE_GCC_QUPV3_WRAP0_S6_CBCR		(SE_GCC_BASE + 0x168c4)
#define SE_GCC_QUPV3_WRAP0_S6_CMD_RCGR		(SE_GCC_BASE + 0x168d4)

#define SE_GCC_QUPV3_WRAP1_M_AHB_CBCR		(SE_GCC_BASE + 0x17004)
#define SE_GCC_QUPV3_WRAP1_S_AHB_CBCR		(SE_GCC_BASE + 0x17008)
#define SE_GCC_QUPV3_WRAP1_CORE_CBCR		(SE_GCC_BASE + 0x1700c)
#define SE_GCC_QUPV3_WRAP1_CORE_2X_CBCR		(SE_GCC_BASE + 0x17020)
#define SE_GCC_QUPV3_WRAP1_CORE_2X_CMD_RCGR	(SE_GCC_BASE + 0x17030)
#define SE_GCC_QUPV3_WRAP1_S0_CBCR		(SE_GCC_BASE + 0x1715c)
#define SE_GCC_QUPV3_WRAP1_S0_CMD_RCGR		(SE_GCC_BASE + 0x1716c)
#define SE_GCC_QUPV3_WRAP1_S1_CBCR		(SE_GCC_BASE + 0x17298)
#define SE_GCC_QUPV3_WRAP1_S1_CMD_RCGR		(SE_GCC_BASE + 0x172a8)
#define SE_GCC_QUPV3_WRAP1_S2_CBCR		(SE_GCC_BASE + 0x173d4)
#define SE_GCC_QUPV3_WRAP1_S2_CMD_RCGR		(SE_GCC_BASE + 0x173e4)
#define SE_GCC_QUPV3_WRAP1_S3_CBCR		(SE_GCC_BASE + 0x17510)
#define SE_GCC_QUPV3_WRAP1_S3_CMD_RCGR		(SE_GCC_BASE + 0x17520)
#define SE_GCC_QUPV3_WRAP1_S4_CBCR		(SE_GCC_BASE + 0x1764c)
#define SE_GCC_QUPV3_WRAP1_S4_CMD_RCGR		(SE_GCC_BASE + 0x1765c)
#define SE_GCC_QUPV3_WRAP1_S5_CBCR		(SE_GCC_BASE + 0x17788)
#define SE_GCC_QUPV3_WRAP1_S5_CMD_RCGR		(SE_GCC_BASE + 0x17798)
#define SE_GCC_QUPV3_WRAP1_S6_CBCR		(SE_GCC_BASE + 0x178c4)
#define SE_GCC_QUPV3_WRAP1_S6_CMD_RCGR		(SE_GCC_BASE + 0x178d4)

/* NE_GCC (north-east quadrant): QUPv3 wrapper 2, seven SEs. */
#define NE_GCC_QUPV3_WRAP2_M_AHB_CBCR		(NE_GCC_BASE + 0x28004)
#define NE_GCC_QUPV3_WRAP2_S_AHB_CBCR		(NE_GCC_BASE + 0x28008)
#define NE_GCC_QUPV3_WRAP2_CORE_CBCR		(NE_GCC_BASE + 0x2800c)
#define NE_GCC_QUPV3_WRAP2_CORE_2X_CBCR		(NE_GCC_BASE + 0x28020)
#define NE_GCC_QUPV3_WRAP2_S0_CBCR		(NE_GCC_BASE + 0x2815c)
#define NE_GCC_QUPV3_WRAP2_S0_CMD_RCGR		(NE_GCC_BASE + 0x2816c)
#define NE_GCC_QUPV3_WRAP2_S1_CBCR		(NE_GCC_BASE + 0x28298)
#define NE_GCC_QUPV3_WRAP2_S1_CMD_RCGR		(NE_GCC_BASE + 0x282a8)
#define NE_GCC_QUPV3_WRAP2_S2_CBCR		(NE_GCC_BASE + 0x283d4)
#define NE_GCC_QUPV3_WRAP2_S2_CMD_RCGR		(NE_GCC_BASE + 0x283e4)
#define NE_GCC_QUPV3_WRAP2_S3_CBCR		(NE_GCC_BASE + 0x28510)
#define NE_GCC_QUPV3_WRAP2_S3_CMD_RCGR		(NE_GCC_BASE + 0x28520)
#define NE_GCC_QUPV3_WRAP2_S4_CBCR		(NE_GCC_BASE + 0x2864c)
#define NE_GCC_QUPV3_WRAP2_S4_CMD_RCGR		(NE_GCC_BASE + 0x2865c)
#define NE_GCC_QUPV3_WRAP2_S5_CBCR		(NE_GCC_BASE + 0x28788)
#define NE_GCC_QUPV3_WRAP2_S5_CMD_RCGR		(NE_GCC_BASE + 0x28798)
#define NE_GCC_QUPV3_WRAP2_S6_CBCR		(NE_GCC_BASE + 0x288c4)
#define NE_GCC_QUPV3_WRAP2_S6_CMD_RCGR		(NE_GCC_BASE + 0x288d4)

/*
 * Central GCC: QUPv3 wrapper 3. Wrapper 3 has a single SE whose CBCR is fed by
 * the shared QSPI_REF RCG (downstream models gcc_qupv3_wrap3_s0_clk and
 * gcc_qupv3_wrap3_qspi_ref_clk on one clock domain), so the RCG offset is
 * QSPI_REF's and there is no separate WRAP3_S0 CMD_RCGR. Wrapper 3 also
 * carries an m_clk in place of the m_ahb_clk the other wrappers have.
 */
#define GCC_QUPV3_WRAP3_M_CBCR			(GCC_BASE + 0x13004)
#define GCC_QUPV3_WRAP3_S_AHB_CBCR		(GCC_BASE + 0x13008)
#define GCC_QUPV3_WRAP3_CORE_CBCR		(GCC_BASE + 0x1300c)
#define GCC_QUPV3_WRAP3_CORE_2X_CBCR		(GCC_BASE + 0x13020)
#define GCC_QUPV3_WRAP3_S0_CBCR			(GCC_BASE + 0x1315c)
#define GCC_QUPV3_WRAP3_QSPI_REF_CBCR		(GCC_BASE + 0x13170)
#define GCC_QUPV3_WRAP3_QSPI_REF_CMD_RCGR	(GCC_BASE + 0x13174)

/*
 * Shared branch-enable vote registers, per controller. QUP SE and wrapper
 * branches gate through one of these rather than their own CBCR CLK_ENABLE
 * bit; which register and bit a branch uses is per-target, so both are listed
 * per domain in the BSP.
 */
#define SE_GCC_CLOCK_BRANCH_ENA_VOTE		(SE_GCC_BASE + 0x2400c)
#define SE_GCC_CLOCK_BRANCH_ENA_VOTE_1		(SE_GCC_BASE + 0x24014)
#define SE_GCC_PLL_BRANCH_ENA_VOTE		(SE_GCC_BASE + 0x2401c)

#define NE_GCC_CLOCK_BRANCH_ENA_VOTE		(NE_GCC_BASE + 0x4801c)
#define NE_GCC_CLOCK_BRANCH_ENA_VOTE_1		(NE_GCC_BASE + 0x48024)
#define NE_GCC_PLL_BRANCH_ENA_VOTE		(NE_GCC_BASE + 0x4802c)

#define GCC_CLOCK_BRANCH_ENA_VOTE		(GCC_BASE + 0x8e030)
#define GCC_CLOCK_BRANCH_ENA_VOTE_2		(GCC_BASE + 0x8e040)
#define GCC_PLL_BRANCH_ENA_VOTE			(GCC_BASE + 0x8e050)

/*
 * Vote-register bit positions, named after their
 * HWIO_<CTLR>_APCS_TZ_..._BRANCH_ENA_VOTE*_..._CLK_ENA_SHFT counterparts in
 * the Nord HWIO header (_CLK_ENA dropped to fit 80 cols), so each vote_bit in
 * the BSP traces back to a named field rather than a bare integer.
 */

/* Bits within SE_GCC_CLOCK_BRANCH_ENA_VOTE. */
#define SE_QUPV3_WRAP0_M_AHB_SHFT		12
#define SE_QUPV3_WRAP0_S_AHB_SHFT		13
#define SE_QUPV3_WRAP0_CORE_SHFT		14
#define SE_QUPV3_WRAP0_CORE_2X_SHFT		15
#define SE_QUPV3_WRAP0_S0_SHFT			16
#define SE_QUPV3_WRAP0_S1_SHFT			17
#define SE_QUPV3_WRAP0_S2_SHFT			18
#define SE_QUPV3_WRAP0_S3_SHFT			19
#define SE_QUPV3_WRAP0_S4_SHFT			20
#define SE_QUPV3_WRAP0_S5_SHFT			21
#define SE_QUPV3_WRAP0_S6_SHFT			22
#define SE_QUPV3_WRAP1_M_AHB_SHFT		23
#define SE_QUPV3_WRAP1_S_AHB_SHFT		24
#define SE_QUPV3_WRAP1_CORE_SHFT		25
#define SE_QUPV3_WRAP1_CORE_2X_SHFT		26
#define SE_QUPV3_WRAP1_S0_SHFT			27
#define SE_QUPV3_WRAP1_S1_SHFT			28
#define SE_QUPV3_WRAP1_S2_SHFT			29
#define SE_QUPV3_WRAP1_S3_SHFT			30
#define SE_QUPV3_WRAP1_S4_SHFT			31

/* Bits within SE_GCC_CLOCK_BRANCH_ENA_VOTE_1 (wrapper 1 spills over). */
#define SE_QUPV3_WRAP1_S5_SHFT			0
#define SE_QUPV3_WRAP1_S6_SHFT			1

/* Bits within NE_GCC_CLOCK_BRANCH_ENA_VOTE. */
#define NE_QUPV3_WRAP2_M_AHB_SHFT		30
#define NE_QUPV3_WRAP2_S_AHB_SHFT		31

/* Bits within NE_GCC_CLOCK_BRANCH_ENA_VOTE_1. */
#define NE_QUPV3_WRAP2_CORE_SHFT		0
#define NE_QUPV3_WRAP2_CORE_2X_SHFT		1
#define NE_QUPV3_WRAP2_S0_SHFT			2
#define NE_QUPV3_WRAP2_S1_SHFT			3
#define NE_QUPV3_WRAP2_S2_SHFT			4
#define NE_QUPV3_WRAP2_S3_SHFT			5
#define NE_QUPV3_WRAP2_S4_SHFT			6
#define NE_QUPV3_WRAP2_S5_SHFT			7
#define NE_QUPV3_WRAP2_S6_SHFT			8

/* Bits within GCC_CLOCK_BRANCH_ENA_VOTE (central). */
#define QUPV3_WRAP3_M_SHFT			22
#define QUPV3_WRAP3_CORE_SHFT			23
#define QUPV3_WRAP3_CORE_2X_SHFT		24
#define QUPV3_WRAP3_S0_SHFT			25
#define QUPV3_WRAP3_QSPI_REF_SHFT		26

/* Bits within GCC_CLOCK_BRANCH_ENA_VOTE_2 (central). */
#define QUPV3_WRAP3_S_AHB_SHFT			15

/*
 * PLL branch-enable vote bits. Each quadrant controller has its own GPLL0, and
 * in every case it is bit 0 of that controller's PLL vote register. Direct
 * register write, not RPMh.
 */
#define PLL_VOTE_BIT_GPLL0			0

/*
 * Root clock generator (RCG) register layout, common across register
 * revisions v1..v4. Offsets are relative to the domain's CMD_RCGR register
 * (qcom_clk_domain.cmd_rcgr_addr).
 */
#define QCOM_RCG_CFG_REG_OFFSET			0x4
#define QCOM_RCG_M_REG_OFFSET			0x8
#define QCOM_RCG_N_REG_OFFSET			0xC
#define QCOM_RCG_D_REG_OFFSET			0x10
#define QCOM_RCG_CMD_DFSR_REG_OFFSET		0x14
#define QCOM_RCG_PERF_DFSR_REG_OFFSET		0x1C
#define QCOM_RCG_PERF_M_DFSR_REG_OFFSET		0x5C
#define QCOM_RCG_PERF_N_DFSR_REG_OFFSET		0x9C
#define QCOM_RCG_PERF_D_DFSR_REG_OFFSET		0xDC

/* CMD_RCGR fields. */
#define QCOM_RCG_CMD_CFG_UPDATE_FMSK		0x00000001

/* CFG_RCGR fields. */
#define QCOM_RCG_CFG_HW_CLK_CONTROL_FMSK	0x00100000
#define QCOM_RCG_CFG_MODE_FMSK			0x00003000
#define QCOM_RCG_CFG_MODE_SHFT			0xC
#define QCOM_RCG_CFG_SRC_SEL_FMSK		0x00000700
#define QCOM_RCG_CFG_SRC_SEL_SHFT		0x8
#define QCOM_RCG_CFG_SRC_DIV_FMSK		0x0000001F
#define QCOM_RCG_CFG_SRC_DIV_SHFT		0
#define QCOM_RCG_CFG_DUAL_EDGE_MODE_VAL		0x2

/* CMD_DFSR fields. */
#define QCOM_RCG_CMD_DFSR_HW_CLK_CONTROL_FMSK	0x00000020
#define QCOM_RCG_CMD_DFSR_DFS_EN_FMSK		0x00000001
#define QCOM_RCG_CMD_DFSR_SW_PERF_STATE_FMSK	0x00007800
#define QCOM_RCG_CMD_DFSR_SW_PERF_STATE_SHFT	11

#ifdef CFG_QCOM_PAS_PTA

#define SE_GCC_HSCNOC_NSP_0_CBCR			0x8
#define SE_GCC_NSP_0_CFG_CBCR				0xf024
#define SE_GCC_NSP_0_HSCNOC_CBCR			0xf01c
#define SE_GCC_NSP_0_COMP_NOC_CBCR			0xf014
#define SE_GCC_NSP_0_QTB_CBCR				0xb008
#define SE_GCC_TCU_NSP_0_QTB_CBCR			0x4030

#define SE_GCC_HSCNOC_NSP_1_CBCR			0x10
#define SE_GCC_NSP_1_CFG_CBCR				0x10024
#define SE_GCC_NSP_1_HSCNOC_CBCR			0x1001c
#define SE_GCC_NSP_1_COMP_NOC_CBCR			0x10014
#define SE_GCC_NSP_1_QTB_CBCR				0xc008
#define SE_GCC_TCU_NSP_1_QTB_CBCR			0x4038

#define SE_GCC_HSCNOC_NSP_2_CBCR			0x18
#define SE_GCC_NSP_2_CFG_CBCR				0x11024
#define SE_GCC_NSP_2_HSCNOC_CBCR			0x1101c
#define SE_GCC_NSP_2_COMP_NOC_CBCR			0x11014
#define SE_GCC_NSP_2_QTB_CBCR				0xd008
#define SE_GCC_TCU_NSP_2_QTB_CBCR			0x4040

#define SE_GCC_HSCNOC_NSP_3_CBCR			0x20
#define SE_GCC_NSP_3_CFG_CBCR				0x12024
#define SE_GCC_NSP_3_HSCNOC_CBCR			0x1201c
#define SE_GCC_NSP_3_COMP_NOC_CBCR			0x12014
#define SE_GCC_NSP_3_QTB_CBCR				0xe008
#define SE_GCC_TCU_NSP_3_QTB_CBCR			0x4048

#define SE_GCC_CBCR_CLK_ENABLE_BIT			BIT(0)
#define SE_GCC_CBCR_CLK_OFF_BIT				BIT(31)
#define SE_GCC_CBCR_HW_CTL_ENABLE_BIT			BIT(1)

#define CDSP_TBF_CFG_OFFSET				0x0021c000
#define CDSP_QDSP6SS_PUB_OFFSET				0x00238000
#define CDSP_QDSP6SS_PLL_OFFSET				0x00278000
#define CDSP_QDSP6SS_CORE_CC_OFFSET			0x0027c000

/* Offsets within the TBF_CFG block (CDSP_TBF_CFG_OFFSET). */
#define CDSP_TBF_CORE_CFG1				0x8
#define TBF_CORE_FORCE_CLK_HALT_BIT			BIT(1)

/* Offsets within the QDSP6 PUB block (CDSP_QDSP6SS_PUB_OFFSET). */
#define CDSP_QDSP6SS_DBG_CFG				0x18
#define CDSP_QDSP6SS_RET_CFG				0x1c
#define CDSP_QDSP6SS_BOOT_CORE_START			0x400
#define CDSP_QDSP6SS_BOOT_CMD				0x404
#define CDSP_QDSP6SS_BOOT_STATUS			0x408
#define CDSP_QDSP6SS_BOOT_AUTO_BREAK_EN			0x410
#define CDSP_QDSP6SS_BOOT_RESUME_CMD			0x414
#define CDSP_QDSP6SS_MEMECC_CFG				0x440

#define QDSP6SS_BOOT_CORE_START_START_BIT		BIT(0)
#define QDSP6SS_BOOT_STATUS_STATUS_BIT			BIT(0)
#define QDSP6SS_BOOT_STATUS_AUTO_BREAK_BIT		BIT(31)
#define QDSP6SS_MEMECC_CFG_VTCM_EXT_CTRL_EN_BIT		BIT(0)

#define CDSP_CC_ALT_RESET_CTL				0x1044
#define CDSP_CC_NSPAUX_GDSCR				0x204
#define CDSP_CC_CENG_AHBS_CBCR				0x240
#define CDSP_CC_NSPNOC_CFG_AHBS_CBCR			0x244
#define CDSP_CC_MCMW_AHBS_CBCR				0x248
#define CDSP_CC_MCSW_AHBS_CBCR				0x24c
#define CDSP_CC_NSPNOC_CBCR				0x268
#define CDSP_CC_CENG_NOC_CBCR				0x278
#define CDSP_CC_CENG_NSP_CBCR				0x298
#define CDSP_CC_MCSW_CBCR				0x29c
#define CDSP_CC_CENG_NSP_AON_CBCR			0x2b0
#define CDSP_CC_MCMW_CBCR				0x2b4
#define CDSP_CC_CENG_PROC_CBCR				0x2d0
#define CDSP_CC_Q6SS_Q6_AXIM_CBCR			0x404
#define CDSP_CC_Q6SS_AHBM_AON_CBCR			0x40c
#define CDSP_CC_Q6SS_AHBS_AON_CBCR			0x410
#define CDSP_CC_NSPAUX_XO_CBCR				0x54
#define CDSP_CC_Q6SS_AXIS_CBCR				0x408

#define CDSP_CC_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT	BIT(0)
#define NSPAUX_GDSCR_HW_CONTROL_BIT			BIT(1)
#define CDSP_CC_CBCR_CLK_ENABLE_BIT			BIT(0)

#define CDSP_QDSP0RCG_CFG_VAL				0x100201

#define CDSP_QDSP6SS_CORE_CMD_RCGR			0x20
#define CDSP_QDSP6SS_CORE_CFG_RCGR			0x24
#define CDSP_QDSP6SS_CORE_CBCR				0x40
#define CDSP_QDSP6SS_CORE_PLL_ACMU			0x2d8

#define QDSP6SS_CORE_CBCR_CLK_ENABLE_BIT		BIT(0)
#define CORE_PLL_ACMU_CMON_FREQ_INVALID_BIT		BIT(31)
#define CORE_PLL_ACMU_CMON_FREQ_VAL_MASK		0x3fff

#define TCSR_CDSP_BIT					BIT(0)

/* AOSS_CC compute-subsystem restart (within AOSS_CC window, AOSS_CC_BASE). */
#define AOSS_CC_COMPUTESS_RESTART			0x7020
#define AOSS_CC_COMPUTESS_CONFIG_RESTART		0x704c
#define COMPUTESS_RESTART_SS_0_BIT			BIT(0)

#define RPMH_PDC_AUDIO_SYNC_RESET			0x0
#define RPMH_PDC_COMPUTE_SYNC_RESET			0x6000
#define RPMH_PDC_COMPUTE1_SYNC_RESET			0x7000
#define RPMH_PDC_COMPUTE2_SYNC_RESET			0x8000
#define RPMH_PDC_COMPUTE3_SYNC_RESET			0x9000
#define PDC_SYNC_RESET_BIT				BIT(0)

#define FEATURE_CONFIG0					0x100
#define FEATURE_CONFIG0_CDSP0_BOOTIMEM_ECC_DISABLE_BIT	BIT(24)
#define FEATURE_CONFIG0_CDSP1_BOOTIMEM_ECC_DISABLE_BIT	BIT(26)
#define FEATURE_CONFIG0_CDSP2_BOOTIMEM_ECC_DISABLE_BIT	BIT(28)
#define FEATURE_CONFIG0_CDSP3_BOOTIMEM_ECC_DISABLE_BIT	BIT(30)

#endif /* CFG_QCOM_PAS_PTA */

#endif /* _NORD_CLOCK_GROUP_H_ */
