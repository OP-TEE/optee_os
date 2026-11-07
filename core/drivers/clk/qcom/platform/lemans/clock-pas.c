// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>

#include "clock_group.h"
#include "clock_hoya.h"

register_phys_mem(MEM_AREA_IO_NSEC, AOSS_CC_BASE, AOSS_CC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GLOBAL_BASE, RPMH_PDC_GLOBAL_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_COMPUTE_BASE,
		  RPMH_PDC_COMPUTE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_NSP_BASE, RPMH_PDC_NSP_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GPDSP0_BASE, RPMH_PDC_GPDSP0_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GPDSP1_BASE, RPMH_PDC_GPDSP1_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_AUDIO_BASE, RPMH_PDC_AUDIO_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);

/* Lucid-EVO PLL register offsets, relative to the PLL register block base. */
static const struct qcom_pll_offsets lucid_evo_pll_offsets = {
	.mode = 0x0,
	.opmode = 0x4,
	.l_val = 0x10,
	.alpha_val = 0x14,
	.user_ctl = 0x18,
	.user_ctl_u = 0x1c,
	.config_ctl = 0x20,
	.config_ctl_u = 0x24,
	.config_ctl_u1 = 0x28,
};

static const struct qcom_pll_config q6_pll_cfg = {
	.offsets = &lucid_evo_pll_offsets,
	.l_val = 0x32,
	.cal_l_val = 0x44,
	.pre_div = 1,
	.config_ctl = 0x20485699,
	.config_ctl_u = 0x00182261,
	.config_ctl_u1 = 0x32aa299c,
	.user_ctl = 0x00000000,
	.user_ctl_u = 0x00400805,
	/* alpha (default) fractional mode */
};

/*
 * Bring the QDSP6 out of reset after the boot FSM completes: lock the Q6 PLL,
 * switch the core RCG onto it, then release the core. Runs after fw_start()
 * since the Q6 PLL registers must not be touched until the FSM is done.
 */
static TEE_Result cdsp_enable_processor(paddr_t turing_base)
{
	vaddr_t boot_base = QCOM_IO_VA(turing_base + TURINGNSP_BOOT_OFFSET,
				       TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t pll_base = boot_base - TURINGNSP_BOOT_OFFSET +
			   TURINGNSP_Q6_PLL_OFFSET;
	vaddr_t core_cc = boot_base - TURINGNSP_BOOT_OFFSET +
			  TURINGNSP_CORE_CC_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	if (!boot_base)
		return TEE_ERROR_GENERIC;

	res = qcom_lucidevo_pll_enable(pll_base, &q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_set_rate(core_cc + QDSP6SS_CORE_CFG_RCGR,
				  core_cc + QDSP6SS_CORE_CMD_RCGR,
				  Q6RCG_CFG_VALUE);
	if (res != TEE_SUCCESS)
		return res;

	/* Release the core only after the PLL has been initialised. */
	io_setbits32(boot_base + QDSP6SS_BOOT_CORE_START, BIT(0));

	return TEE_SUCCESS;
}

static const struct qcom_pll_config lpass_q6_pll_cfg = {
	.offsets = &lucid_evo_pll_offsets,
	.l_val = 0x2c,
	.cal_l_val = 0x44,
	.pre_div = 1,
	.config_ctl = 0x20485699,
	.config_ctl_u = 0x00182261,
	.config_ctl_u1 = 0x32aa299c,
	.user_ctl = 0x00000000,
	.user_ctl_u = 0x00400805,
	/* alpha (default) fractional mode */
};

/*
 * Set up clocks for the LPASS / ADSP QDSP6. Unlike the Turing NSP, the Q6 PLL
 * and core RCG are configured here, before the boot FSM in lpass_fw_start.
 */
static TEE_Result lpass_setup(void)
{
	vaddr_t lpass_base = QCOM_IO_VA(LPASS_BASE, LPASS_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t aon_cc = lpass_base + LPASS_AON_CC_OFFSET;
	vaddr_t top_cc = lpass_base + LPASS_TOP_CC_OFFSET;
	vaddr_t core_cc = lpass_base + LPASS_CORE_CC_OFFSET;
	vaddr_t pll_base = lpass_base + LPASS_PLL_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc_base || !lpass_base)
		return TEE_ERROR_GENERIC;

	/* 4. Enable LPASS access from the config NoC. */
	res = qcom_clock_enable_cbc(gcc_base + GCC_CFG_NOC_LPASS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	/* AHB master/slave clocks, required to reach the QDSP6SS registers. */
	res = qcom_clock_enable_cbc(aon_cc + LPASS_AON_CC_Q6_AHBM_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(aon_cc + LPASS_AON_CC_Q6_AHBS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	/* LPASS interface clock. */
	res = qcom_clock_enable_cbc(top_cc + LPASS_TOP_CC_LPI_Q6_AXIM_HS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	/* Enable the QDSP6 core clock branch. */
	res = qcom_clock_enable_cbc(core_cc + LPASS_QDSP6SS_CORE_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	/* Configure and lock the Q6 PLL, then switch the core RCG onto it. */
	res = qcom_lucidevo_pll_enable(pll_base, &lpass_q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	return qcom_clock_set_rate(core_cc + LPASS_QDSP6SS_CORE_CFG_RCGR,
				   core_cc + LPASS_QDSP6SS_CORE_CMD_RCGR,
				   Q6RCG_CFG_VALUE);
}

static const struct qcom_pll_config gpdsp_q6_pll_cfg = {
	.offsets = &lucid_evo_pll_offsets,
	.l_val = 0x3a,
	.cal_l_val = 0x44,
	.pre_div = 1,
	.config_ctl = 0x20485699,
	.config_ctl_u = 0x00182261,
	.config_ctl_u1 = 0x32aa299c,
	.user_ctl = 0x00000000,
	.user_ctl_u = 0x00400805,
	/* alpha (default) fractional mode */
};

static const struct hoya_nsp cdsp0 = {
	.base = TURING_0_BASE,
	.gcc_cfg_ahb_cbcr = GCC_TURING_0_CFG_AHB_CBCR,
	.tcsr_haltreq = TCSR_TURING_HALTREQ,
	.tcsr_haltack = TCSR_TURING_HALTACK,
	.tcsr_master_idle = TCSR_TURING_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_TURING_PWR_ON,
	.pdc_base = RPMH_PDC_COMPUTE_BASE,
	.pdc_size = RPMH_PDC_COMPUTE_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_COMPUTE_BIT,
	.restart_bit = COMPUTESS_RESTART_SS_0_BIT,
	.ret_cfg_ares = QDSP6SS_RET_CFG_RET_ARES_ENA_BIT,
	.ret_cfg_settle_us = 2000,
};

static const struct hoya_nsp cdsp1 = {
	.base = TURING_1_BASE,
	.gcc_cfg_ahb_cbcr = GCC_TURING_1_CFG_AHB_CBCR,
	.tcsr_haltreq = TCSR_TURING1_HALT_REQ,
	.tcsr_haltack = TCSR_TURING1_HALT_ACK,
	.tcsr_master_idle = TCSR_TURING1_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_TURING1_PWR_ON,
	.pdc_base = RPMH_PDC_NSP_BASE,
	.pdc_size = RPMH_PDC_NSP_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_NSP_BIT,
	.restart_bit = COMPUTESS_RESTART_SS_1_BIT,
	.ret_cfg_ares = QDSP6SS_RET_CFG_RET_ARES_ENA_BIT,
};

static const struct hoya_gpdsp gpdsp0 = {
	.base = TURING_GDSP_0_BASE,
	.gcc_cfg_ahb_cbcr = GCC_GPDSP_0_CFG_AHB_CBCR,
	.gcc_aggre_axi_cbcr = GCC_AGGRE_NOC_GPDSP_0_AXI_CBCR,
	.tcsr_haltreq = TCSR_GPDSP0_HALT_REQ,
	.tcsr_haltack = TCSR_GPDSP0_HALT_ACK,
	.tcsr_il0_master_idle = TCSR_GPDSP0_IL0_MASTER_IDLE,
	.tcsr_il1_master_idle = TCSR_GPDSP0_IL1_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_GPDSP0_PWR_ON,
	.pdc_base = RPMH_PDC_GPDSP0_BASE,
	.pdc_size = RPMH_PDC_GPDSP0_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_GPDSP0_BIT,
	.restart_bit = GPDSP_RESTART_SS_0_BIT,
	.ret_cfg_ares = QDSP6SS_RET_CFG_RET_ARES_ENA_BIT,
};

static const struct hoya_gpdsp gpdsp1 = {
	.base = TURING_GDSP_1_BASE,
	.gcc_cfg_ahb_cbcr = GCC_GPDSP_1_CFG_AHB_CBCR,
	.gcc_aggre_axi_cbcr = GCC_AGGRE_NOC_GPDSP_1_AXI_CBCR,
	.tcsr_haltreq = TCSR_GPDSP1_HALT_REQ,
	.tcsr_haltack = TCSR_GPDSP1_HALT_ACK,
	.tcsr_il0_master_idle = TCSR_GPDSP1_IL0_MASTER_IDLE,
	.tcsr_il1_master_idle = TCSR_GPDSP1_IL1_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_GPDSP1_PWR_ON,
	.pdc_base = RPMH_PDC_GPDSP1_BASE,
	.pdc_size = RPMH_PDC_GPDSP1_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_GPDSP1_BIT,
	.restart_bit = GPDSP_RESTART_SS_1_BIT,
	.ret_cfg_ares = QDSP6SS_RET_CFG_RET_ARES_ENA_BIT,
};

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return hoya_nsp_enable_processor_lucidevo(&cdsp0, &q6_pll_cfg);
	case QCOM_CLKS_TURING1:
		return hoya_nsp_enable_processor_lucidevo(&cdsp1, &q6_pll_cfg);
	case QCOM_CLKS_LPASS:
	case QCOM_CLKS_GPDSP0:
	case QCOM_CLKS_GPDSP1:
		/*
		 * The Q6 PLL and core RCG were configured before the boot
		 * FSM, which also released the core.
		 */
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return hoya_nsp_reset(&cdsp0);
	case QCOM_CLKS_TURING1:
		return hoya_nsp_reset(&cdsp1);
	case QCOM_CLKS_GPDSP0:
		return hoya_gpdsp_reset(&gpdsp0);
	case QCOM_CLKS_GPDSP1:
		return hoya_gpdsp_reset(&gpdsp1);
	case QCOM_CLKS_LPASS:
		return hoya_lpass_reset(QDSP6SS_RET_CFG_RET_ARES_ENA_BIT);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return hoya_nsp_enable(&cdsp0);
	case QCOM_CLKS_TURING1:
		return hoya_nsp_enable(&cdsp1);
	case QCOM_CLKS_LPASS:
		return hoya_lpass_setup_lucidevo(&lpass_q6_pll_cfg);
	case QCOM_CLKS_GPDSP0:
		return hoya_gpdsp_setup_lucidevo(&gpdsp0, &gpdsp_q6_pll_cfg);
	case QCOM_CLKS_GPDSP1:
		return hoya_gpdsp_setup_lucidevo(&gpdsp1, &gpdsp_q6_pll_cfg);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
