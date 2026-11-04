// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

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
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GPDSP0_BASE, RPMH_PDC_GPDSP0_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_AUDIO_BASE, RPMH_PDC_AUDIO_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, ROUNDDOWN(TCSR_SPARE_RG63_WO_1,
					      SMALL_PAGE_SIZE),
		  SMALL_PAGE_SIZE);

/* QDSP6SS_RET_CFG bits set before a restart */
#define RET_CFG_ARES	(QDSP6SS_RET_CFG_RET_ARES_ENA_BIT | \
			 QDSP6SS_RET_CFG_NRET_ARES_ENA_BIT)

/* Lucid-EVO PLL register offsets, relative to the PLL register block base */
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

/* The L value is replaced by the one from the NSP soft SKU */
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

static const struct hoya_nsp cdsp = {
	.base = TURING_0_BASE,
	.gcc_cfg_ahb_cbcr = GCC_TURING_0_CFG_AHB_CBCR,
	.tcsr_haltreq = TCSR_TURING_HALTREQ,
	.tcsr_haltack = TCSR_TURING_HALTACK,
	.tcsr_master_idle = TCSR_TURING_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_TURING_PWR_ON,
	.pdc_base = RPMH_PDC_COMPUTE_BASE,
	.pdc_size = RPMH_PDC_COMPUTE_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_COMPUTE_BIT,
	.restart_bit = AOSS_CC_SS_0_RESTART_BIT,
	.ret_cfg_ares = RET_CFG_ARES,
	.ret_cfg_settle_us = 2000,
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
	.restart_bit = AOSS_CC_SS_0_RESTART_BIT,
	.ret_cfg_ares = RET_CFG_ARES,
};

static uint32_t cdsp_q6_pll_l_val(vaddr_t sku_reg)
{
	uint32_t sku = io_read32(sku_reg);
	uint32_t l_val = 0;

	if (sku & NSP_SOFT_SKU_DISABLE_BIT)
		return q6_pll_cfg.l_val;

	l_val = (sku & NSP_SOFT_SKU_Q6_PLL_L_VAL_MASK) >>
		NSP_SOFT_SKU_Q6_PLL_L_VAL_SHIFT;
	if (l_val < q6_pll_cfg.l_val)
		return NSP_SOFT_SKU_Q6_PLL_L_VAL_768MHZ;

	return l_val;
}

static TEE_Result cdsp_enable_processor(void)
{
	vaddr_t sku_reg = QCOM_IO_VA(TCSR_SPARE_RG63_WO_1, sizeof(uint32_t));
	struct qcom_lucidevo_pll_config pll = q6_pll_cfg;

	if (!sku_reg)
		return TEE_ERROR_GENERIC;

	pll.l_val = cdsp_q6_pll_l_val(sku_reg);

	return hoya_nsp_enable_processor_lucidevo(&cdsp, &pll);
}

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_enable_processor();
	case QCOM_CLKS_LPASS:
	case QCOM_CLKS_GPDSP0:
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
		return hoya_nsp_reset(&cdsp);
	case QCOM_CLKS_GPDSP0:
		return hoya_gpdsp_reset(&gpdsp0);
	case QCOM_CLKS_LPASS:
		return hoya_lpass_reset(RET_CFG_ARES);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return hoya_nsp_enable(&cdsp);
	case QCOM_CLKS_LPASS:
		return hoya_lpass_setup_lucidevo(&lpass_q6_pll_cfg);
	case QCOM_CLKS_GPDSP0:
		return hoya_gpdsp_setup_lucidevo(&gpdsp0, &gpdsp_q6_pll_cfg);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
