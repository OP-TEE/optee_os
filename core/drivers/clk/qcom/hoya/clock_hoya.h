/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CLOCK_HOYA_H_
#define _CLOCK_HOYA_H_

#include <drivers/clk_qcom.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

/*
 * QDSP6 subsystem clock and reset sequences shared by the hoya chips with
 * Lucid-EVO Q6 PLLs (Lemans, Monaco). Offsets are relative to the subsystem
 * or global block named in each comment; the chip supplies the bases and
 * per-instance registers.
 */

/* Turing/NSP clock controller, relative to TURINGNSP_CC_OFFSET */
#define TURINGNSP_CC_OFFSET			0x02008000
#define TURINGNSP_NSPAUX_XO_CBCR		0x40
#define TURINGNSP_VAPSS_GDSCR			0x80
#define TURINGNSP_NSPAUX_GDSCR			0x200
#define TURINGNSP_NSPNOC			0x22c
#define TURINGNSP_Q6SS_Q6_AXIM_CBCR		0x404
#define TURINGNSP_Q6SS_AXIS2_CBCR		0x40c
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

/* Turing/NSP boot block, relative to TURINGNSP_BOOT_OFFSET */
#define TURINGNSP_QDSP6SS_RET_CFG		0x1c
#define QDSP6SS_BOOT_CORE_START			0x400

/* Turing/NSP core clock controller, relative to TURINGNSP_CORE_CC_OFFSET */
#define QDSP6SS_CORE_CMD_RCGR			0x20
#define QDSP6SS_CORE_CFG_RCGR			0x24
#define TURINGNSP_QDSP6SS_CORE_CBCR		0x40

#define QDSP6SS_RET_CFG_RET_ARES_ENA_BIT	BIT(0)
#define QDSP6SS_RET_CFG_NRET_ARES_ENA_BIT	BIT(1)

/* Q6 core RCG: source select = Q6 PLL (SRC_SEL, bits [10:8]), divider = 1 */
#define Q6RCG_SRC_SEL				0x2
#define Q6RCG_SRC_SEL_SHIFT			8
#define Q6RCG_SRC_DIV				0x1
#define Q6RCG_CFG_VALUE				(((Q6RCG_SRC_SEL) << \
						  (Q6RCG_SRC_SEL_SHIFT)) | \
						 (Q6RCG_SRC_DIV))

/* LPASS / ADSP sub-blocks, relative to LPASS_BASE */
#define LPASS_PUB_OFFSET			0x00400000
#define LPASS_PLL_OFFSET			0x00440000
#define LPASS_CORE_CC_OFFSET			0x00448000
#define LPASS_AUDIO_CC_OFFSET			0x00780000
#define LPASS_AON_CC_OFFSET			0x00808000
#define LPASS_CORE_HM_CC_OFFSET			0x00d00000
#define LPASS_TOP_CC_OFFSET			0x01000000
#define LPASS_AG_NOC_SBM_OFFSET			0x0104a000

/* QDSP6 PUB block, relative to LPASS_PUB_OFFSET */
#define LPASS_QDSP6SS_RET_CFG			0x1c

/* Core clock controller, relative to LPASS_CORE_CC_OFFSET */
#define LPASS_QDSP6SS_CORE_CMD_RCGR		0x0
#define LPASS_QDSP6SS_CORE_CFG_RCGR		0x4
#define LPASS_QDSP6SS_CORE_CBCR			0x20

/* Always-on clock controller, relative to LPASS_AON_CC_OFFSET */
#define LPASS_AON_CC_Q6_AHBM_CBCR		0x101c
#define LPASS_AON_CC_Q6_AHBS_CBCR		0x1020
#define LPASS_AON_CC_AUDIO_HM_BCR		0x108c
#define LPASS_AON_CC_AUDIO_HM_GDSCR		0x1090
#define LPASS_AON_CC_CORE_HM_COLLAPSE_VOTE	0x4000
#define LPASS_AON_CC_AUDIO_ML_GDSCR		0xe090

/* Top clock controller, relative to LPASS_TOP_CC_OFFSET */
#define LPASS_TOP_CC_CORE_HM_GDSCR		0x0
#define LPASS_TOP_CC_CORE_GDSCR_DEBUG_VOTE	0x2000
#define LPASS_TOP_CC_LPI_Q6_AXIM_HS_CBCR	0x4000
#define LPASS_TOP_CC_ISLAND_MODE_STATUS		0xa004
#define LPASS_ISLAND_MODE_BIT			BIT(0)

/* LPASS_CORE_HM clock controller, relative to LPASS_CORE_HM_CC_OFFSET */
#define LPASS_CORE_HM_DIG_PLL_OPMODE		0x4
#define LPASS_CORE_HM_CORE_CMD_RCGR		0x1d000
#define LPASS_CORE_HM_CORE_CFG_RCGR		0x1d004
#define LPASS_CORE_HM_AF_NOC_QCHANNEL_CTL	0x41000
#define QCHANNEL_CTL_QREQN_BIT			BIT(0)
#define QCHANNEL_CTL_SW_OVERRIDE_EN_BIT		BIT(1)
#define QCHANNEL_CTL_QACCEPTN_BIT		BIT(4)
#define QCHANNEL_CTL_QDENY_BIT			BIT(5)
#define QCHANNEL_CTL_QACTIVE_BIT		BIT(6)

/* Audio clock controller, relative to LPASS_AUDIO_CC_OFFSET */
#define LPASS_AUDIO_CC_PLL_MODE			0x0
#define LPASS_AUDIO_CC_PLL_OPMODE		0x2c
#define LPASS_AUDIO_CC_DIG_PLL_OPMODE		0x1004
#define LPASS_AUDIO_CC_RX_MCLK_CMD_RCGR		0x24004
#define LPASS_AUDIO_CC_RX_MCLK_MODE_MUXSEL	0x240d8
#define RX_MCLK_MODE_MUXSEL_SEL_BIT		BIT(0)

/* AG NoC sideband manager, relative to LPASS_AG_NOC_SBM_OFFSET */
#define LPASS_AG_NOC_SBM_FLAGOUTCLR0_LOW	0x80
#define LPASS_AG_NOC_SBM_FLAGOUTSET0_LOW	0x88
#define LPASS_AG_NOC_SBM_SENSEIN0_LOW		0x100
#define LPASS_AG_NOC_SBM_PORT0_BIT		BIT(0)
#define LPASS_AG_NOC_SBM_PORT1_BIT		BIT(1)

#define GDSCR_SW_COLLAPSE_BIT			BIT(0)
#define GDSCR_RETAIN_FF_ENABLE_BIT		BIT(11)
#define GDSCR_PWR_ON_BIT			BIT(31)
#define GDSCR_DEBUG_VOTE_RETENTION_BIT		BIT(0)
#define BCR_BLK_ARES_BIT			BIT(0)
#define RCGR_CFG_OFFSET				0x4
#define CFG_RCGR_SRC_DIV_MASK			GENMASK_32(4, 0)
#define CFG_RCGR_SRC_SEL_MASK			GENMASK_32(10, 8)
#define PLL_MODE_OUTCTRL_BIT			BIT(0)
#define PLL_MODE_BYPASSNL_BIT			BIT(1)
#define PLL_MODE_RESET_N_BIT			BIT(2)
#define PLL_OPMODE_MASK				GENMASK_32(2, 0)
#define CBCR_CLK_ENABLE_BIT			BIT(0)

/* GP-DSP (TURINGGDSP) sub-blocks, relative to the GP-DSP base */
#define TURINGGDSP_GDSP_CC_OFFSET		0x00808000
#define TURINGGDSP_PUB_OFFSET			0x00c00000
#define TURINGGDSP_PLL_OFFSET			0x00c40000
#define TURINGGDSP_CORE_CC_OFFSET		0x00c48000
#define TURINGGDSP_SIZE				0x01000000

/* GDSP clock controller, relative to TURINGGDSP_GDSP_CC_OFFSET */
#define TURINGGDSP_Q6SS_AHBS_AON_CBCR		0x10

/* QDSP6 PUB block, relative to TURINGGDSP_PUB_OFFSET */
#define TURINGGDSP_QDSP6SS_DBG_CFG		0x18
#define TURINGGDSP_QDSP6SS_RET_CFG		0x1c

/* Core clock controller, relative to TURINGGDSP_CORE_CC_OFFSET */
#define TURINGGDSP_QDSP6SS_CORE_CMD_RCGR	0x0
#define TURINGGDSP_QDSP6SS_CORE_CFG_RCGR	0x4
#define TURINGGDSP_QDSP6SS_CORE_CBCR		0x20

/* GCC config-NoC LPASS access branch, relative to GCC_BASE */
#define GCC_CFG_NOC_LPASS_CBCR			0x43024

/* Subsystem restarts, relative to AOSS_CC_BASE */
#define AOSS_CC_LPASS_RESTART			0x4f01c
#define AOSS_CC_COMPUTESS_RESTART		0x4f030
#define AOSS_CC_GPDSP_RESTART			0x4f034
#define LPASS_RESTART_SS_BIT			BIT(0)

/* PDC sync reset, relative to RPMH_PDC_GLOBAL_BASE */
#define RPMH_PDC_SYNC_RESET			0x1000
#define PDC_SYNC_RESET_AUDIO_BIT		BIT(2)

/* Mode status, relative to each subsystem PDC */
#define RPMH_PDC_MODE_STATUS_DRV0		0x1030
#define PDC_MODE_STATUS_SEQ_BUSY_BIT		BIT(0)

/* Master halt, relative to TCSR_MUTEX_BASE */
#define TCSR_LPASS_HALTREQ			0x22000
#define TCSR_LPASS_HALTACK			0x22004
#define TCSR_HALT_BIT				BIT(0)

/*
 * struct qcom_hoya_nsp - one Turing/NSP (CDSP) instance
 * @base:		Subsystem base
 * @gcc_cfg_ahb_cbcr:	Config-NoC AHB branch (SWAY NIU socket), in GCC
 * @tcsr_haltreq:	Master halt request, in the TCSR mutex window
 * @tcsr_haltack:	Master halt acknowledge
 * @tcsr_master_idle:	Master port idle status
 * @tcsr_pwr_on:	Power status
 * @pdc_base:		Subsystem PDC, for the sequencer busy check
 * @pdc_size:		Size of the subsystem PDC window
 * @pdc_sync_reset_bit:	Bit in RPMH_PDC_SYNC_RESET
 * @restart_bit:	Bit in AOSS_CC_COMPUTESS_RESTART
 * @ret_cfg_ares:	QDSP6SS_RET_CFG bits set before the restart
 * @ret_cfg_settle_us:	Delay after the RET_CFG write, 0 for none
 */
struct qcom_hoya_nsp {
	paddr_t base;
	uint32_t gcc_cfg_ahb_cbcr;
	uint32_t tcsr_haltreq;
	uint32_t tcsr_haltack;
	uint32_t tcsr_master_idle;
	uint32_t tcsr_pwr_on;
	paddr_t pdc_base;
	size_t pdc_size;
	uint32_t pdc_sync_reset_bit;
	uint32_t restart_bit;
	uint32_t ret_cfg_ares;
	uint32_t ret_cfg_settle_us;
};

/*
 * struct qcom_hoya_gpdsp - one GP-DSP (TURINGGDSP) instance
 * @base:		Subsystem base
 * @gcc_cfg_ahb_cbcr:	Config-NoC AHB branch (SWAY NIU socket), in GCC
 * @gcc_aggre_axi_cbcr:	Aggre-NoC AXI branch, in GCC
 * @tcsr_haltreq:	Master halt request, in the TCSR mutex window
 * @tcsr_haltack:	Master halt acknowledge
 * @tcsr_il0_master_idle: IL0 master port idle status
 * @tcsr_il1_master_idle: IL1 master port idle status
 * @tcsr_pwr_on:	Power status
 * @pdc_base:		Subsystem PDC, for the sequencer busy check
 * @pdc_size:		Size of the subsystem PDC window
 * @pdc_sync_reset_bit:	Bit in RPMH_PDC_SYNC_RESET
 * @restart_bit:	Bit in AOSS_CC_GPDSP_RESTART
 * @ret_cfg_ares:	QDSP6SS_RET_CFG bits set before the restart
 */
struct qcom_hoya_gpdsp {
	paddr_t base;
	uint32_t gcc_cfg_ahb_cbcr;
	uint32_t gcc_aggre_axi_cbcr;
	uint32_t tcsr_haltreq;
	uint32_t tcsr_haltack;
	uint32_t tcsr_il0_master_idle;
	uint32_t tcsr_il1_master_idle;
	uint32_t tcsr_pwr_on;
	paddr_t pdc_base;
	size_t pdc_size;
	uint32_t pdc_sync_reset_bit;
	uint32_t restart_bit;
	uint32_t ret_cfg_ares;
};

/* Enable the NSP bus and Q6SS clocks and initialize the retention flops */
TEE_Result qcom_hoya_nsp_enable(const struct qcom_hoya_nsp *nsp);
/*
 * Lock the Q6 PLL, switch the core RCG onto it and release the core. Must
 * run after the boot FSM completes.
 */
TEE_Result
qcom_hoya_nsp_enable_processor(const struct qcom_hoya_nsp *nsp,
			       const struct qcom_lucidevo_pll_config *pll);
/* Put the NSP through a subsystem restart */
TEE_Result qcom_hoya_nsp_reset(const struct qcom_hoya_nsp *nsp);

/* Enable the GP-DSP clocks and lock its Q6 PLL, before the boot FSM */
TEE_Result qcom_hoya_gpdsp_setup(const struct qcom_hoya_gpdsp *gpdsp,
				 const struct qcom_lucidevo_pll_config *pll);
/* Put the GP-DSP through a subsystem restart */
TEE_Result qcom_hoya_gpdsp_reset(const struct qcom_hoya_gpdsp *gpdsp);

/* Enable the LPASS clocks and lock its Q6 PLL, before the boot FSM */
TEE_Result qcom_hoya_lpass_setup(const struct qcom_lucidevo_pll_config *pll);
/*
 * Quiesce LPASS and put it through a subsystem restart; @ret_cfg_ares are
 * the QDSP6SS_RET_CFG bits set before the restart.
 */
TEE_Result qcom_hoya_lpass_reset(uint32_t ret_cfg_ares);

#endif /* _CLOCK_HOYA_H_ */
