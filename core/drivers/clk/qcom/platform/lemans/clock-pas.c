// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

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
static const struct qcom_lucidevo_pll_offsets lucid_evo_pll_offsets = {
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

static const struct qcom_lucidevo_pll_config q6_pll_cfg = {
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

static const struct qcom_lucidevo_pll_config lpass_q6_pll_cfg = {
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

static const struct qcom_lucidevo_pll_config gpdsp_q6_pll_cfg = {
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
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	TEE_Result res = 0;

	if (!gcc_base)
		return TEE_ERROR_GENERIC;

	switch (group) {
	case QCOM_CLKS_TURING:
		res = hoya_nsp_enable(&cdsp0);
		if (res != TEE_SUCCESS)
			goto timeout;
		break;
	case QCOM_CLKS_TURING1:
		res = hoya_nsp_enable(&cdsp1);
		if (res != TEE_SUCCESS)
			goto timeout;
		break;
	case QCOM_CLKS_LPASS:
		return hoya_lpass_setup_lucidevo(&lpass_q6_pll_cfg);
	case QCOM_CLKS_GPDSP0:
		return hoya_gpdsp_setup_lucidevo(&gpdsp0, &gpdsp_q6_pll_cfg);
	case QCOM_CLKS_GPDSP1:
		return hoya_gpdsp_setup_lucidevo(&gpdsp1, &gpdsp_q6_pll_cfg);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
timeout:
	EMSG("Timeout trying to enable clock group %d\n", group);
	return TEE_ERROR_TIMEOUT;
}
