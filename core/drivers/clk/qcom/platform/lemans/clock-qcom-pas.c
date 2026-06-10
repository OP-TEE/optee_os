// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

#include "clock_group_qcom.h"

#define CBCR_BRANCH_ENABLE_BIT		BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT		BIT(1)
#define CBCR_BRANCH_OFF_BIT		BIT(31)

register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, GCC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, AOSS_CC_BASE, AOSS_CC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GLOBAL_BASE, RPMH_PDC_GLOBAL_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_COMPUTE_BASE,
		  RPMH_PDC_COMPUTE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_NSP_BASE, RPMH_PDC_NSP_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);

static TEE_Result cdsp_enable(paddr_t turing_base)
{
	struct io_pa_va turing_cc_io = {
		.pa = turing_base + TURINGNSP_CC_OFFSET
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
		     CBCR_BRANCH_ENABLE_BIT);
	io_clrbits32(cc_base + TURINGNSP_Q6SS_ALT_RESET_AON,
		     CBCR_BRANCH_ENABLE_BIT);

	io_setbits32(cc_base + TURINGNSP_NSPNOC,
		     CBCR_BRANCH_ENABLE_BIT);

	/* Retention flop */
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

static const struct qcom_lucidevo_pll_config q6_pll_cfg = {
	.l_val = TURINGNSP_Q6_PLL_L_VAL,
	.cal_l_val = TURINGNSP_Q6_PLL_CAL_L_VAL,
	.pre_div = 1,
	.config_ctl = TURINGNSP_Q6_PLL_CONFIG_CTL,
	.config_ctl_u = TURINGNSP_Q6_PLL_CONFIG_CTL_U,
	.config_ctl_u1 = TURINGNSP_Q6_PLL_CONFIG_CTL_U1,
	.user_ctl = TURINGNSP_Q6_PLL_USER_CTL,
	.user_ctl_u = TURINGNSP_Q6_PLL_USER_CTL_U,
	/* alpha (default) fractional mode */
};

/*
 * Bring the QDSP6 out of reset once the boot FSM has completed: configure and
 * lock the Q6 PLL, switch the core RCG onto it, then release the core. This
 * mirrors the CLOCK_PROCESSOR_TURING case of Clock_EnableProcessorEx in the
 * reference ClockPIL driver. The Q6 PLL register space must not be accessed
 * until the boot FSM is done, so this runs after cdspN_fw_start().
 */
static TEE_Result cdsp_enable_processor(paddr_t turing_base)
{
	struct io_pa_va proc_io = {
		.pa = turing_base + TURINGNSP_BOOT_OFFSET
	};
	vaddr_t boot_base = io_pa_or_va(&proc_io, TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t pll_base = boot_base - TURINGNSP_BOOT_OFFSET +
			   TURINGNSP_Q6_PLL_OFFSET;
	vaddr_t core_cc = boot_base - TURINGNSP_BOOT_OFFSET +
			  TURINGNSP_CORE_CC_OFFSET;
	TEE_Result res = TEE_SUCCESS;

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

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_enable_processor(TURING_0_BASE);
	case QCOM_CLKS_TURING1:
		return cdsp_enable_processor(TURING_1_BASE);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

/*
 * Per-instance register selection for the Turing/NSP reset sequence. CDSP0 and
 * CDSP1 use the same Turing-CC offsets (parameterised by turing_base) but
 * differ in the GCC AHB CBCR, the TCSR halt/power block, and the PDC / AOSS
 * restart fields. This descriptor captures those deltas.
 */
struct cdsp_reset_regs {
	paddr_t turing_base;
	uint32_t gcc_cfg_ahb_cbcr;	/* offset within GCC window */
	uint32_t tcsr_haltreq;		/* offsets within TCSR mutex window */
	uint32_t tcsr_haltack;
	uint32_t tcsr_master_idle;
	uint32_t tcsr_pwr_on;
	paddr_t pdc_status_base;	/* RPMH PDC block for the busy check */
	uint32_t pdc_status_size;
	uint32_t pdc_sync_reset_bit;	/* field within RPMH_PDC_SYNC_RESET */
	uint32_t computess_restart_bit;	/* bit in AOSS_CC_COMPUTESS_RESTART */
	uint32_t ret_cfg_settle_us;	/* settle us after RET_CFG, CDSP0 */
};

static const struct cdsp_reset_regs cdsp0_reset_regs = {
	.turing_base = TURING_0_BASE,
	.gcc_cfg_ahb_cbcr = GCC_TURING_0_CFG_AHB_CBCR,
	.tcsr_haltreq = TCSR_TURING_HALTREQ,
	.tcsr_haltack = TCSR_TURING_HALTACK,
	.tcsr_master_idle = TCSR_TURING_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_TURING_PWR_ON,
	.pdc_status_base = RPMH_PDC_COMPUTE_BASE,
	.pdc_status_size = RPMH_PDC_COMPUTE_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_COMPUTE_BIT,
	.computess_restart_bit = COMPUTESS_RESTART_SS_0_BIT,
	.ret_cfg_settle_us = 2000,
};

static const struct cdsp_reset_regs cdsp1_reset_regs = {
	.turing_base = TURING_1_BASE,
	.gcc_cfg_ahb_cbcr = GCC_TURING_1_CFG_AHB_CBCR,
	.tcsr_haltreq = TCSR_TURING1_HALT_REQ,
	.tcsr_haltack = TCSR_TURING1_HALT_ACK,
	.tcsr_master_idle = TCSR_TURING1_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_TURING1_PWR_ON,
	.pdc_status_base = RPMH_PDC_NSP_BASE,
	.pdc_status_size = RPMH_PDC_NSP_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_NSP_BIT,
	.computess_restart_bit = COMPUTESS_RESTART_SS_1_BIT,
	.ret_cfg_settle_us = 0,
};

/* HALT_ACK polls for up to 1s (200000 * 5us), matching the reference. */
#define CDSP_HALT_ACK_TIMEOUT_US	(200000 * 5)

/*
 * Put the QDSP6/NSP through a full subsystem reset before bring-up, mirroring
 * Reset_TURINGProcessor / Reset_TURING1Processor in the reference ClockPIL.
 * This returns the core to a clean state (asserting AOSS_CC_COMPUTESS_RESTART
 * and the PDC sync reset) so the Q6 does not come out of reset from a stale or
 * partially-initialised state left by an earlier boot stage.
 */
static TEE_Result cdsp_reset_processor(const struct cdsp_reset_regs *r)
{
	struct io_pa_va turing_cc_io = { .pa = r->turing_base +
						TURINGNSP_CC_OFFSET };
	vaddr_t cc_base = io_pa_or_va(&turing_cc_io,
				     TURINGNSP_PROC_WINDOW_SIZE);
	struct io_pa_va pub_io = { .pa = r->turing_base +
					 TURINGNSP_BOOT_OFFSET };
	vaddr_t pub_base = io_pa_or_va(&pub_io, TURINGNSP_PROC_WINDOW_SIZE);
	struct io_pa_va gcc_io = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&gcc_io, GCC_SIZE);
	struct io_pa_va aoss_io = { .pa = AOSS_CC_BASE };
	vaddr_t aoss_cc = io_pa_or_va(&aoss_io, AOSS_CC_SIZE);
	struct io_pa_va pdc_g_io = { .pa = RPMH_PDC_GLOBAL_BASE };
	vaddr_t pdc_global = io_pa_or_va(&pdc_g_io, RPMH_PDC_GLOBAL_SIZE);
	struct io_pa_va pdc_s_io = { .pa = r->pdc_status_base };
	vaddr_t pdc_status = io_pa_or_va(&pdc_s_io, r->pdc_status_size);
	struct io_pa_va tcsr_io = { .pa = TCSR_MUTEX_BASE };
	vaddr_t tcsr = io_pa_or_va(&tcsr_io, TCSR_MUTEX_SIZE);
	uint64_t timeout = 0;
	TEE_Result res = TEE_SUCCESS;

	/* Bail if the PDC sequencer is mid-transition. */
	if (io_read32(pdc_status + RPMH_PDC_MODE_STATUS_DRV0) &
	    PDC_MODE_STATUS_SEQ_BUSY_BIT)
		return TEE_ERROR_BUSY;

	/* Activate a full QDSP6 reset before the SSR. */
	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_Q6SS_ALT_RESET_AON);
	if (res != TEE_SUCCESS)
		return res;
	io_setbits32(cc_base + TURINGNSP_Q6SS_ALT_RESET_CTL,
		     Q6SS_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT);

	/*
	 * Reset the retention logic. On CDSP0 the reference waits for the write
	 * to settle (CDSP1 omits this); ret_cfg_settle_us captures that delta.
	 */
	io_setbits32(pub_base + TURINGNSP_QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA_BIT);
	if (r->ret_cfg_settle_us) {
		dsb();
		udelay(r->ret_cfg_settle_us);
	}

	/* Retain the NSP_AUX registers across the reset. */
	io_setbits32(cc_base + TURINGNSP_NSPAUX_XO_CBCR, CBCR_CLK_ENABLE_BIT);
	io_setbits32(cc_base + TURINGNSP_NSPAUX_GDSCR,
		     NSPAUX_GDSCR_RETAIN_FF_ENABLE_BIT);

	/* Disconnect the SWAY NIU socket to halt config-NoC traffic. */
	io_clrbits32(gcc_base + r->gcc_cfg_ahb_cbcr, CBCR_CLK_ENABLE_BIT);

	/* If powered on and the master port is busy, halt mem-NoC traffic. */
	if ((io_read32(tcsr + r->tcsr_pwr_on) & TCSR_TURING_BIT) &&
	    !(io_read32(tcsr + r->tcsr_master_idle) & TCSR_TURING_BIT)) {
		io_setbits32(tcsr + r->tcsr_haltreq, TCSR_TURING_BIT);

		timeout = timeout_init_us(CDSP_HALT_ACK_TIMEOUT_US);
		while (!(io_read32(tcsr + r->tcsr_haltack) &
			 TCSR_TURING_BIT)) {
			if (timeout_elapsed(timeout))
				break;
			udelay(5);
		}
	}

	/* Assert the PDC reset, then pulse the subsystem restart. */
	io_setbits32(pdc_global + RPMH_PDC_SYNC_RESET, r->pdc_sync_reset_bit);

	io_setbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
		     r->computess_restart_bit);
	udelay(200);
	io_clrbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
		     r->computess_restart_bit);
	dsb();
	udelay(200);

	/* De-assert the PDC reset and clear the halt request. */
	io_clrbits32(pdc_global + RPMH_PDC_SYNC_RESET, r->pdc_sync_reset_bit);
	io_clrbits32(tcsr + r->tcsr_haltreq, TCSR_TURING_BIT);
	udelay(100);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_reset_processor(&cdsp0_reset_regs);
	case QCOM_CLKS_TURING1:
		return cdsp_reset_processor(&cdsp1_reset_regs);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, GCC_SIZE);
	TEE_Result res = 0;

	switch (group) {
	case QCOM_CLKS_TURING:
		/* Turing bus clock branch connected to the NIU socket */
		res = qcom_clock_enable_cbc(gcc_base +
					    GCC_TURING_0_CFG_AHB_CLK);
		if (res)
			goto timeout;

		res = cdsp_enable(TURING_0_BASE);
		if (res != TEE_SUCCESS)
			goto timeout;
		break;
	case QCOM_CLKS_TURING1:
		/* Turing bus clock branch connected to the NIU socket */
		res = qcom_clock_enable_cbc(gcc_base +
					    GCC_TURING_1_CFG_AHB_CLK);
		if (res)
			goto timeout;

		res = cdsp_enable(TURING_1_BASE);
		if (res != TEE_SUCCESS)
			goto timeout;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
timeout:
	EMSG("Timeout trying to enable clock group %d\n", group);
	return TEE_ERROR_TIMEOUT;
}
