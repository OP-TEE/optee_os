// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

#include "clock_group.h"

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

/* HALT_ACK polls for up to 1 s */
#define HALT_ACK_TIMEOUT_US		(200000 * 5)

static TEE_Result cdsp_enable(void)
{
	struct io_pa_va turing_cc_io = {
		.pa = TURING_0_BASE + TURINGNSP_CC_OFFSET
	};
	vaddr_t cc_base = io_pa_or_va(&turing_cc_io, 0x50000);
	uint64_t timeout = timeout_init_us(10000);
	TEE_Result res = TEE_SUCCESS;

	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_Q6SS_AHBS_AON);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_Q6SS_ALT_RESET_AON);
	if (res != TEE_SUCCESS)
		return res;

	io_clrbits32(cc_base + TURINGNSP_Q6SS_ALT_RESET_CTL,
		     Q6SS_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT);
	io_clrbits32(cc_base + TURINGNSP_Q6SS_ALT_RESET_AON,
		     CBCR_BRANCH_ENABLE_BIT);

	io_setbits32(cc_base + TURINGNSP_NSPNOC, CBCR_BRANCH_ENABLE_BIT);

	/* Retention flop initialization */
	io_clrbits32(cc_base + TURINGNSP_VAPSS_GDSCR, 0x1);
	while (!timeout_elapsed(timeout)) {
		if (io_read32(cc_base + TURINGNSP_VAPSS_GDSCR) & 0x80000000)
			goto out;

		udelay(10);
	}

	return TEE_ERROR_TIMEOUT;
out:
	io_setbits32(cc_base + TURINGNSP_VAPSS_GDSCR, 0x801);

	return TEE_SUCCESS;
}

static uint32_t cdsp_q6_pll_l_val(void)
{
	struct io_pa_va sku_io = { .pa = TCSR_SPARE_RG63_WO_1 };
	uint32_t sku = io_read32(io_pa_or_va(&sku_io, sizeof(uint32_t)));
	uint32_t l_val = 0;

	if (sku == NSP_SOFT_SKU_POR_VALUE || sku & NSP_SOFT_SKU_DISABLE_BIT)
		return TURINGNSP_Q6_PLL_L_VAL;

	l_val = (sku & NSP_SOFT_SKU_Q6_PLL_L_VAL_MASK) >>
		NSP_SOFT_SKU_Q6_PLL_L_VAL_SHIFT;
	if (l_val < TURINGNSP_Q6_PLL_L_VAL)
		return NSP_SOFT_SKU_Q6_PLL_L_VAL_768MHZ;

	return l_val;
}

/*
 * Bring the QDSP6 out of reset after the boot FSM completes: lock the Q6 PLL,
 * switch the core RCG onto it, then release the core. Runs after fw_start()
 * since the Q6 PLL registers must not be touched until the FSM is done.
 */
static TEE_Result cdsp_enable_processor(void)
{
	struct io_pa_va proc_io = {
		.pa = TURING_0_BASE + TURINGNSP_BOOT_OFFSET
	};
	vaddr_t boot_base = io_pa_or_va(&proc_io, TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t pll_base = boot_base - TURINGNSP_BOOT_OFFSET +
			   TURINGNSP_Q6_PLL_OFFSET;
	vaddr_t core_cc = boot_base - TURINGNSP_BOOT_OFFSET +
			  TURINGNSP_CORE_CC_OFFSET;
	struct qcom_lucidevo_pll_config q6_pll_cfg = {
		.l_val = cdsp_q6_pll_l_val(),
		.cal_l_val = TURINGNSP_Q6_PLL_CAL_L_VAL,
		.pre_div = 1,
		.config_ctl = TURINGNSP_Q6_PLL_CONFIG_CTL,
		.config_ctl_u = TURINGNSP_Q6_PLL_CONFIG_CTL_U,
		.config_ctl_u1 = TURINGNSP_Q6_PLL_CONFIG_CTL_U1,
		.user_ctl = TURINGNSP_Q6_PLL_USER_CTL,
		.user_ctl_u = TURINGNSP_Q6_PLL_USER_CTL_U,
	};
	TEE_Result res = TEE_SUCCESS;

	res = qcom_lucidevo_pll_enable(pll_base, &q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_set_rate(core_cc + QDSP6SS_CORE_CFG_RCGR,
				  core_cc + QDSP6SS_CORE_CMD_RCGR,
				  Q6RCG_CFG_VALUE);
	if (res != TEE_SUCCESS)
		return res;

	io_setbits32(boot_base + QDSP6SS_BOOT_CORE_START, BIT(0));

	return TEE_SUCCESS;
}

static const struct qcom_lucidevo_pll_config lpass_q6_pll_cfg = {
	.l_val = LPASS_Q6_PLL_L_VAL,
	.cal_l_val = LPASS_Q6_PLL_CAL_L_VAL,
	.pre_div = 1,
	.config_ctl = LPASS_Q6_PLL_CONFIG_CTL,
	.config_ctl_u = LPASS_Q6_PLL_CONFIG_CTL_U,
	.config_ctl_u1 = LPASS_Q6_PLL_CONFIG_CTL_U1,
	.user_ctl = LPASS_Q6_PLL_USER_CTL,
	.user_ctl_u = LPASS_Q6_PLL_USER_CTL_U,
};

/*
 * Unlike the Turing NSP, the LPASS Q6 PLL and core RCG are configured here,
 * before the boot FSM in lpass_fw_start.
 */
static TEE_Result lpass_setup(void)
{
	struct io_pa_va gcc_io = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&gcc_io, GCC_SIZE);
	struct io_pa_va lpass_io = { .pa = LPASS_BASE };
	vaddr_t lpass_base = io_pa_or_va(&lpass_io, LPASS_SIZE);
	vaddr_t aon_cc = lpass_base + LPASS_AON_CC_OFFSET;
	vaddr_t top_cc = lpass_base + LPASS_TOP_CC_OFFSET;
	vaddr_t core_cc = lpass_base + LPASS_CORE_CC_OFFSET;
	vaddr_t pll_base = lpass_base + LPASS_PLL_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc_base || !lpass_base)
		return TEE_ERROR_GENERIC;

	res = qcom_clock_enable_cbc(gcc_base + GCC_CFG_NOC_LPASS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(aon_cc + LPASS_AON_CC_Q6_AHBM_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(aon_cc + LPASS_AON_CC_Q6_AHBS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(top_cc + LPASS_TOP_CC_LPI_Q6_AXIM_HS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(core_cc + LPASS_QDSP6SS_CORE_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_lucidevo_pll_enable(pll_base, &lpass_q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	return qcom_clock_set_rate(core_cc + LPASS_QDSP6SS_CORE_CFG_RCGR,
				   core_cc + LPASS_QDSP6SS_CORE_CMD_RCGR,
				   Q6RCG_CFG_VALUE);
}

static const struct qcom_lucidevo_pll_config gpdsp_q6_pll_cfg = {
	.l_val = GPDSP_Q6_PLL_L_VAL,
	.cal_l_val = GPDSP_Q6_PLL_CAL_L_VAL,
	.pre_div = 1,
	.config_ctl = GPDSP_Q6_PLL_CONFIG_CTL,
	.config_ctl_u = GPDSP_Q6_PLL_CONFIG_CTL_U,
	.config_ctl_u1 = GPDSP_Q6_PLL_CONFIG_CTL_U1,
	.user_ctl = GPDSP_Q6_PLL_USER_CTL,
	.user_ctl_u = GPDSP_Q6_PLL_USER_CTL_U,
};

/*
 * Like LPASS, the GP-DSP Q6 PLL and core RCG are configured here, before the
 * boot FSM in gpdsp0_fw_start.
 */
static TEE_Result gpdsp_setup(void)
{
	struct io_pa_va gcc_io = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&gcc_io, GCC_SIZE);
	struct io_pa_va gdsp_io = { .pa = TURING_GDSP_0_BASE };
	vaddr_t base = io_pa_or_va(&gdsp_io, TURING_GDSP_0_SIZE);
	vaddr_t gdsp_cc = base + TURINGGDSP_GDSP_CC_OFFSET;
	vaddr_t core_cc = base + TURINGGDSP_CORE_CC_OFFSET;
	vaddr_t pll_base = base + TURINGGDSP_PLL_OFFSET;
	vaddr_t pub = base + TURINGGDSP_PUB_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc_base || !base)
		return TEE_ERROR_GENERIC;

	res = qcom_clock_enable_cbc(gcc_base + GCC_GPDSP_0_CFG_AHB_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(gcc_base + GCC_AGGRE_NOC_GPDSP_0_AXI_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(gdsp_cc + TURINGGDSP_Q6SS_AHBS_AON_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	io_write32(pub + TURINGGDSP_QDSP6SS_DBG_CFG, 0);
	io_setbits32(core_cc + TURINGGDSP_QDSP6SS_CORE_CBCR,
		     CBCR_BRANCH_ENABLE_BIT);

	res = qcom_lucidevo_pll_enable(pll_base, &gpdsp_q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	return qcom_clock_set_rate(core_cc + TURINGGDSP_QDSP6SS_CORE_CFG_RCGR,
				   core_cc + TURINGGDSP_QDSP6SS_CORE_CMD_RCGR,
				   Q6RCG_CFG_VALUE);
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

static void halt_mem_noc(vaddr_t tcsr, uint32_t haltreq, uint32_t haltack)
{
	uint64_t timeout = timeout_init_us(HALT_ACK_TIMEOUT_US);

	io_setbits32(tcsr + haltreq, TCSR_HALT_BIT);

	while (!(io_read32(tcsr + haltack) & TCSR_HALT_BIT)) {
		if (timeout_elapsed(timeout))
			break;
		udelay(5);
	}
}

/*
 * Put the NSP through a full subsystem reset (AOSS_CC_COMPUTESS_RESTART and
 * PDC sync reset) before bring-up, so the Q6 does not come out of reset
 * from a stale state left by an earlier boot stage.
 */
static TEE_Result cdsp_reset_processor(void)
{
	struct io_pa_va turing_cc_io = {
		.pa = TURING_0_BASE + TURINGNSP_CC_OFFSET
	};
	vaddr_t cc_base = io_pa_or_va(&turing_cc_io,
				     TURINGNSP_PROC_WINDOW_SIZE);
	struct io_pa_va pub_io = { .pa = TURING_0_BASE +
					 TURINGNSP_BOOT_OFFSET };
	vaddr_t pub_base = io_pa_or_va(&pub_io, TURINGNSP_PROC_WINDOW_SIZE);
	struct io_pa_va gcc_io = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&gcc_io, GCC_SIZE);
	struct io_pa_va aoss_io = { .pa = AOSS_CC_BASE };
	vaddr_t aoss_cc = io_pa_or_va(&aoss_io, AOSS_CC_SIZE);
	struct io_pa_va pdc_g_io = { .pa = RPMH_PDC_GLOBAL_BASE };
	vaddr_t pdc_global = io_pa_or_va(&pdc_g_io, RPMH_PDC_GLOBAL_SIZE);
	struct io_pa_va pdc_s_io = { .pa = RPMH_PDC_COMPUTE_BASE };
	vaddr_t pdc_status = io_pa_or_va(&pdc_s_io, RPMH_PDC_COMPUTE_SIZE);
	struct io_pa_va tcsr_io = { .pa = TCSR_MUTEX_BASE };
	vaddr_t tcsr = io_pa_or_va(&tcsr_io, TCSR_MUTEX_SIZE);
	TEE_Result res = TEE_SUCCESS;

	if (io_read32(pdc_status + RPMH_PDC_MODE_STATUS_DRV0) &
	    PDC_MODE_STATUS_SEQ_BUSY_BIT)
		return TEE_ERROR_BUSY;

	/* Activate a full QDSP6 reset before the SSR */
	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_Q6SS_ALT_RESET_AON);
	if (res != TEE_SUCCESS)
		return res;
	io_setbits32(cc_base + TURINGNSP_Q6SS_ALT_RESET_CTL,
		     Q6SS_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT);

	io_setbits32(pub_base + TURINGNSP_QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA_BIT |
		     QDSP6SS_RET_CFG_NRET_ARES_ENA_BIT);
	dsb();
	udelay(2000);

	/* Retain the NSP_AUX registers across the reset */
	io_setbits32(cc_base + TURINGNSP_NSPAUX_XO_CBCR, CBCR_CLK_ENABLE_BIT);
	io_setbits32(cc_base + TURINGNSP_NSPAUX_GDSCR,
		     NSPAUX_GDSCR_RETAIN_FF_ENABLE_BIT);

	/* Disconnect the SWAY NIU socket to halt config-NoC traffic */
	io_clrbits32(gcc_base + GCC_TURING_0_CFG_AHB_CBCR, CBCR_CLK_ENABLE_BIT);

	if ((io_read32(tcsr + TCSR_TURING_PWR_ON) & TCSR_HALT_BIT) &&
	    !(io_read32(tcsr + TCSR_TURING_MASTER_IDLE) & TCSR_HALT_BIT))
		halt_mem_noc(tcsr, TCSR_TURING_HALTREQ, TCSR_TURING_HALTACK);

	io_setbits32(pdc_global + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_COMPUTE_BIT);

	io_setbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
		     AOSS_CC_SS_0_RESTART_BIT);
	udelay(200);
	io_clrbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
		     AOSS_CC_SS_0_RESTART_BIT);
	dsb();
	udelay(200);

	io_clrbits32(pdc_global + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_COMPUTE_BIT);
	io_clrbits32(tcsr + TCSR_TURING_HALTREQ, TCSR_HALT_BIT);
	udelay(100);

	return TEE_SUCCESS;
}

/*
 * Put the GP-DSP through a full subsystem reset (AOSS_CC_GPDSP_RESTART and
 * PDC sync reset) before bring-up. Unlike the Turing NSP there is no
 * NSPAUX/ALT_RESET retention handling and the idle check covers two ports.
 */
static TEE_Result gpdsp_reset_processor(void)
{
	struct io_pa_va gdsp_io = { .pa = TURING_GDSP_0_BASE };
	vaddr_t base = io_pa_or_va(&gdsp_io, TURING_GDSP_0_SIZE);
	vaddr_t pub = base + TURINGGDSP_PUB_OFFSET;
	struct io_pa_va gcc_io = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&gcc_io, GCC_SIZE);
	struct io_pa_va aoss_io = { .pa = AOSS_CC_BASE };
	vaddr_t aoss_cc = io_pa_or_va(&aoss_io, AOSS_CC_SIZE);
	struct io_pa_va pdc_g_io = { .pa = RPMH_PDC_GLOBAL_BASE };
	vaddr_t pdc_global = io_pa_or_va(&pdc_g_io, RPMH_PDC_GLOBAL_SIZE);
	struct io_pa_va pdc_s_io = { .pa = RPMH_PDC_GPDSP0_BASE };
	vaddr_t pdc_status = io_pa_or_va(&pdc_s_io, RPMH_PDC_GPDSP0_SIZE);
	struct io_pa_va tcsr_io = { .pa = TCSR_MUTEX_BASE };
	vaddr_t tcsr = io_pa_or_va(&tcsr_io, TCSR_MUTEX_SIZE);

	if (!base || !gcc_base || !aoss_cc || !pdc_global || !pdc_status ||
	    !tcsr)
		return TEE_ERROR_GENERIC;

	if (io_read32(pdc_status + RPMH_PDC_MODE_STATUS_DRV0) &
	    PDC_MODE_STATUS_SEQ_BUSY_BIT)
		return TEE_ERROR_BUSY;

	io_setbits32(pub + TURINGGDSP_QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA_BIT |
		     QDSP6SS_RET_CFG_NRET_ARES_ENA_BIT);
	dsb();
	udelay(2000);

	/* Disconnect the SWAY NIU socket to halt config-NoC traffic */
	io_clrbits32(gcc_base + GCC_GPDSP_0_CFG_AHB_CBCR, CBCR_CLK_ENABLE_BIT);

	if ((io_read32(tcsr + TCSR_GPDSP0_PWR_ON) & TCSR_HALT_BIT) &&
	    (!(io_read32(tcsr + TCSR_GPDSP0_IL0_MASTER_IDLE) & TCSR_HALT_BIT) ||
	     !(io_read32(tcsr + TCSR_GPDSP0_IL1_MASTER_IDLE) & TCSR_HALT_BIT)))
		halt_mem_noc(tcsr, TCSR_GPDSP0_HALT_REQ, TCSR_GPDSP0_HALT_ACK);

	io_setbits32(pdc_global + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_GPDSP0_BIT);

	io_setbits32(aoss_cc + AOSS_CC_GPDSP_RESTART, AOSS_CC_SS_0_RESTART_BIT);
	udelay(200);
	io_clrbits32(aoss_cc + AOSS_CC_GPDSP_RESTART, AOSS_CC_SS_0_RESTART_BIT);
	dsb();
	udelay(200);

	io_clrbits32(pdc_global + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_GPDSP0_BIT);
	io_clrbits32(tcsr + TCSR_GPDSP0_HALT_REQ, TCSR_HALT_BIT);
	udelay(100);

	return TEE_SUCCESS;
}

/*
 * Put LPASS through a subsystem restart (AOSS_CC_LPASS_RESTART and PDC sync
 * reset), so that a stopped or crashed ADSP is booted again from reset.
 */
static TEE_Result lpass_reset_processor(void)
{
	struct io_pa_va gcc_io = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&gcc_io, GCC_SIZE);
	struct io_pa_va lpass_io = { .pa = LPASS_BASE };
	vaddr_t lpass_base = io_pa_or_va(&lpass_io, LPASS_SIZE);
	vaddr_t aon_cc = lpass_base + LPASS_AON_CC_OFFSET;
	vaddr_t pub = lpass_base + LPASS_PUB_OFFSET;
	struct io_pa_va aoss_io = { .pa = AOSS_CC_BASE };
	vaddr_t aoss_cc = io_pa_or_va(&aoss_io, AOSS_CC_SIZE);
	struct io_pa_va pdc_g_io = { .pa = RPMH_PDC_GLOBAL_BASE };
	vaddr_t pdc_global = io_pa_or_va(&pdc_g_io, RPMH_PDC_GLOBAL_SIZE);
	struct io_pa_va pdc_s_io = { .pa = RPMH_PDC_AUDIO_BASE };
	vaddr_t pdc_status = io_pa_or_va(&pdc_s_io, RPMH_PDC_AUDIO_SIZE);
	struct io_pa_va tcsr_io = { .pa = TCSR_MUTEX_BASE };
	vaddr_t tcsr = io_pa_or_va(&tcsr_io, TCSR_MUTEX_SIZE);
	TEE_Result res = TEE_SUCCESS;

	if (!gcc_base || !lpass_base || !aoss_cc || !pdc_global ||
	    !pdc_status || !tcsr)
		return TEE_ERROR_GENERIC;

	if (io_read32(pdc_status + RPMH_PDC_MODE_STATUS_DRV0) &
	    PDC_MODE_STATUS_SEQ_BUSY_BIT)
		return TEE_ERROR_BUSY;

	/* The QDSP6SS registers are reachable only with these branches on */
	res = qcom_clock_enable_cbc(gcc_base + GCC_CFG_NOC_LPASS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(aon_cc + LPASS_AON_CC_Q6_AHBS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	/* Reset the retention flops as well; lpass_fw_start clears these */
	io_setbits32(pub + LPASS_QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA_BIT |
		     QDSP6SS_RET_CFG_NRET_ARES_ENA_BIT);

	/* A QDSP6 in a bad state may never ack; halt_mem_noc() times out */
	halt_mem_noc(tcsr, TCSR_LPASS_HALTREQ, TCSR_LPASS_HALTACK);

	io_setbits32(pdc_global + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_AUDIO_BIT);
	io_setbits32(aoss_cc + AOSS_CC_LPASS_RESTART, AOSS_CC_SS_0_RESTART_BIT);
	dsb();
	mdelay(10);

	io_clrbits32(pdc_global + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_AUDIO_BIT);
	io_clrbits32(aoss_cc + AOSS_CC_LPASS_RESTART, AOSS_CC_SS_0_RESTART_BIT);
	dsb();
	udelay(200);

	io_clrbits32(tcsr + TCSR_LPASS_HALTREQ, TCSR_HALT_BIT);
	udelay(100);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_reset_processor();
	case QCOM_CLKS_GPDSP0:
		return gpdsp_reset_processor();
	case QCOM_CLKS_LPASS:
		return lpass_reset_processor();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, GCC_SIZE);
	TEE_Result res = TEE_SUCCESS;

	switch (group) {
	case QCOM_CLKS_TURING:
		res = qcom_clock_enable_cbc(gcc_base +
					    GCC_TURING_0_CFG_AHB_CBCR);
		if (res)
			goto timeout;

		res = cdsp_enable();
		if (res)
			goto timeout;

		return TEE_SUCCESS;
	case QCOM_CLKS_LPASS:
		return lpass_setup();
	case QCOM_CLKS_GPDSP0:
		return gpdsp_setup();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

timeout:
	EMSG("Timeout trying to enable clock group %d", group);
	return TEE_ERROR_TIMEOUT;
}
