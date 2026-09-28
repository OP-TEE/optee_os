// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

#include "clock_group.h"

/* Core VA of a registered or mapped MMIO range, 0 if there is none. */
#define QCOM_IO_VA(phys, size) \
	((vaddr_t)phys_to_virt_io((phys), (size)))

register_phys_mem(MEM_AREA_IO_NSEC, AOSS_CC_BASE, AOSS_CC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GLOBAL_BASE, RPMH_PDC_GLOBAL_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_COMPUTE_BASE,
		  RPMH_PDC_COMPUTE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_NSP_BASE, RPMH_PDC_NSP_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GPDSP0_BASE, RPMH_PDC_GPDSP0_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GPDSP1_BASE, RPMH_PDC_GPDSP1_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_AUDIO_BASE, RPMH_PDC_AUDIO_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);

static bool lpass_halt_acked(uint32_t val)
{
	return val & TCSR_LPASS_BIT;
}

static bool rcg_update_done(uint32_t val)
{
	return !(val & CMD_RCGR_UPDATE_BIT);
}

static bool qch_inactive(uint32_t val)
{
	return !(val & QCHANNEL_CTL_QACTIVE_BIT);
}

static bool qch_accepted(uint32_t val)
{
	return !(val & QCHANNEL_CTL_QACCEPTN_BIT);
}

/* No AG NoC port other than port 0 (LPASS_CORE_HM) is still sensed. */
static bool sbm_only_port0_sensed(uint32_t val)
{
	return !(val & ~LPASS_AG_NOC_SBM_PORT0_BIT);
}

static bool gdsc_is_on(uint32_t val)
{
	return val & GDSCR_PWR_ON_BIT;
}

static bool gdsc_is_off(uint32_t val)
{
	return !gdsc_is_on(val);
}

static bool bcr_is_asserted(uint32_t val)
{
	return val & BCR_BLK_ARES_BIT;
}

static TEE_Result cdsp_enable(paddr_t turing_base)
{
	vaddr_t cc_base = QCOM_IO_VA(turing_base + TURINGNSP_CC_OFFSET,
				     0x50000);
	uint64_t timeout = timeout_init_us(10000);
	TEE_Result res = TEE_SUCCESS;

	if (!cc_base)
		return TEE_ERROR_GENERIC;

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

static const struct qcom_lucidevo_pll_config lpass_q6_pll_cfg = {
	.l_val = LPASS_Q6_PLL_L_VAL,
	.cal_l_val = LPASS_Q6_PLL_CAL_L_VAL,
	.pre_div = 1,
	.config_ctl = LPASS_Q6_PLL_CONFIG_CTL,
	.config_ctl_u = LPASS_Q6_PLL_CONFIG_CTL_U,
	.config_ctl_u1 = LPASS_Q6_PLL_CONFIG_CTL_U1,
	.user_ctl = LPASS_Q6_PLL_USER_CTL,
	.user_ctl_u = LPASS_Q6_PLL_USER_CTL_U,
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

static const struct qcom_lucidevo_pll_config gpdsp_q6_pll_cfg = {
	.l_val = GPDSP_Q6_PLL_L_VAL,
	.cal_l_val = GPDSP_Q6_PLL_CAL_L_VAL,
	.pre_div = 1,
	.config_ctl = GPDSP_Q6_PLL_CONFIG_CTL,
	.config_ctl_u = GPDSP_Q6_PLL_CONFIG_CTL_U,
	.config_ctl_u1 = GPDSP_Q6_PLL_CONFIG_CTL_U1,
	.user_ctl = GPDSP_Q6_PLL_USER_CTL,
	.user_ctl_u = GPDSP_Q6_PLL_USER_CTL_U,
	/* alpha (default) fractional mode */
};

/*
 * Set up clocks for a GP-DSP (TURINGGDSP) QDSP6. Like LPASS, the Q6 PLL and
 * core RCG are configured here, before the boot FSM in gpdspN_fw_start.
 */
static TEE_Result gpdsp_setup(paddr_t gdsp_base, uint32_t gcc_cfg_ahb_cbcr,
			      uint32_t gcc_aggre_axi_cbcr)
{
	vaddr_t base = QCOM_IO_VA(gdsp_base, TURING_GDSP_0_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t gdsp_cc = base + TURINGGDSP_GDSP_CC_OFFSET;
	vaddr_t core_cc = base + TURINGGDSP_CORE_CC_OFFSET;
	vaddr_t pll_base = base + TURINGGDSP_PLL_OFFSET;
	vaddr_t pub = base + TURINGGDSP_PUB_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc_base || !base)
		return TEE_ERROR_GENERIC;

	/* Turing slave-way bus clock branch, also on NIU socket. */
	res = qcom_clock_enable_cbc(gcc_base + gcc_cfg_ahb_cbcr);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(gcc_base + gcc_aggre_axi_cbcr);
	if (res != TEE_SUCCESS)
		return res;

	/* Q6SS slave clock, required to reach the QDSP6SS registers. */
	res = qcom_clock_enable_cbc(gdsp_cc + TURINGGDSP_Q6SS_AHBS_AON_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	/* Program the debug config register, then enable core clock. */
	io_write32(pub + TURINGGDSP_QDSP6SS_DBG_CFG, 0);
	io_setbits32(core_cc + TURINGGDSP_QDSP6SS_CORE_CBCR,
		     CBCR_BRANCH_ENABLE_BIT);

	/* Configure and lock the Q6 PLL, then switch the core RCG onto it. */
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
		return cdsp_enable_processor(TURING_0_BASE);
	case QCOM_CLKS_TURING1:
		return cdsp_enable_processor(TURING_1_BASE);
	case QCOM_CLKS_LPASS:
		/*
		 * LPASS configures its Q6 PLL and core RCG in lpass_setup
		 * (before the boot FSM) and releases the core in
		 * lpass_fw_start, so there is no post-boot step here.
		 */
		return TEE_SUCCESS;
	case QCOM_CLKS_GPDSP0:
	case QCOM_CLKS_GPDSP1:
		/*
		 * Like LPASS, the GP-DSP Q6 PLL and core RCG are configured in
		 * gpdsp_setup and the core released in gpdspN_fw_start, so
		 * there is no post-boot step here.
		 */
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

/*
 * Per-instance register selection for the Turing/NSP reset sequence: CDSP0 and
 * CDSP1 share the Turing-CC offsets but differ in the GCC/TCSR/PDC/AOSS fields.
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
 * Put the QDSP6/NSP through a full subsystem reset (AOSS_CC_COMPUTESS_RESTART
 * and PDC sync reset) when it is shut down, so that it boots again from reset.
 */
static TEE_Result cdsp_reset_processor(const struct cdsp_reset_regs *r)
{
	vaddr_t pub_base = QCOM_IO_VA(r->turing_base + TURINGNSP_BOOT_OFFSET,
				      TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t cc_base = QCOM_IO_VA(r->turing_base + TURINGNSP_CC_OFFSET,
				     TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t pdc_global = QCOM_IO_VA(RPMH_PDC_GLOBAL_BASE,
					RPMH_PDC_GLOBAL_SIZE);
	vaddr_t pdc_status = QCOM_IO_VA(r->pdc_status_base,
					r->pdc_status_size);
	vaddr_t tcsr = QCOM_IO_VA(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t aoss_cc = QCOM_IO_VA(AOSS_CC_BASE, AOSS_CC_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	TEE_Result res = TEE_SUCCESS;
	uint64_t timeout = 0;

	if (!pub_base || !cc_base || !gcc_base || !aoss_cc || !pdc_global ||
	    !pdc_status || !tcsr)
		return TEE_ERROR_GENERIC;

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
	 * Reset the retention logic; CDSP0 waits for the write to settle
	 * (CDSP1 omits this), captured by ret_cfg_settle_us.
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

/*
 * Per-instance register selection for the GP-DSP reset sequence: GDSP0 and
 * GDSP1 share the QDSP6 PUB offsets but differ in the GCC/TCSR/PDC/AOSS fields.
 */
struct gpdsp_reset_regs {
	paddr_t gdsp_base;
	uint32_t gcc_cfg_ahb_cbcr;	/* offset within GCC window */
	uint32_t tcsr_haltreq;		/* offsets within TCSR mutex window */
	uint32_t tcsr_haltack;
	uint32_t tcsr_il0_master_idle;
	uint32_t tcsr_il1_master_idle;
	uint32_t tcsr_pwr_on;
	paddr_t pdc_status_base;	/* RPMH PDC block for the busy check */
	uint32_t pdc_status_size;
	uint32_t pdc_sync_reset_bit;	/* field within RPMH_PDC_SYNC_RESET */
	uint32_t gpdsp_restart_bit;	/* field within AOSS_CC_GPDSP_RESTART */
};

static const struct gpdsp_reset_regs gpdsp0_reset_regs = {
	.gdsp_base = TURING_GDSP_0_BASE,
	.gcc_cfg_ahb_cbcr = GCC_GPDSP_0_CFG_AHB_CBCR,
	.tcsr_haltreq = TCSR_GPDSP0_HALT_REQ,
	.tcsr_haltack = TCSR_GPDSP0_HALT_ACK,
	.tcsr_il0_master_idle = TCSR_GPDSP0_IL0_MASTER_IDLE,
	.tcsr_il1_master_idle = TCSR_GPDSP0_IL1_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_GPDSP0_PWR_ON,
	.pdc_status_base = RPMH_PDC_GPDSP0_BASE,
	.pdc_status_size = RPMH_PDC_GPDSP0_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_GPDSP0_BIT,
	.gpdsp_restart_bit = GPDSP_RESTART_SS_0_BIT,
};

static const struct gpdsp_reset_regs gpdsp1_reset_regs = {
	.gdsp_base = TURING_GDSP_1_BASE,
	.gcc_cfg_ahb_cbcr = GCC_GPDSP_1_CFG_AHB_CBCR,
	.tcsr_haltreq = TCSR_GPDSP1_HALT_REQ,
	.tcsr_haltack = TCSR_GPDSP1_HALT_ACK,
	.tcsr_il0_master_idle = TCSR_GPDSP1_IL0_MASTER_IDLE,
	.tcsr_il1_master_idle = TCSR_GPDSP1_IL1_MASTER_IDLE,
	.tcsr_pwr_on = TCSR_GPDSP1_PWR_ON,
	.pdc_status_base = RPMH_PDC_GPDSP1_BASE,
	.pdc_status_size = RPMH_PDC_GPDSP1_SIZE,
	.pdc_sync_reset_bit = PDC_SYNC_RESET_GPDSP1_BIT,
	.gpdsp_restart_bit = GPDSP_RESTART_SS_1_BIT,
};

/* HALT_ACK polls for up to 1s (200000 * 5us), matching the reference. */
#define GPDSP_HALT_ACK_TIMEOUT_US	(200000 * 5)

/*
 * Put a GP-DSP QDSP6 through a full subsystem reset (AOSS_CC_GPDSP_RESTART and
 * PDC sync reset) when it is shut down. Unlike the Turing NSP there is no
 * NSPAUX/ALT_RESET retention handling and the idle check covers two ports.
 */
static TEE_Result gpdsp_reset_processor(const struct gpdsp_reset_regs *r)
{
	vaddr_t pdc_global = QCOM_IO_VA(RPMH_PDC_GLOBAL_BASE,
					RPMH_PDC_GLOBAL_SIZE);
	vaddr_t pdc_status = QCOM_IO_VA(r->pdc_status_base,
					r->pdc_status_size);
	vaddr_t base = QCOM_IO_VA(r->gdsp_base, TURING_GDSP_0_SIZE);
	vaddr_t tcsr = QCOM_IO_VA(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t aoss_cc = QCOM_IO_VA(AOSS_CC_BASE, AOSS_CC_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t pub = base + TURINGGDSP_PUB_OFFSET;
	uint64_t timeout = 0;

	if (!base || !gcc_base || !aoss_cc || !pdc_global || !pdc_status ||
	    !tcsr)
		return TEE_ERROR_GENERIC;

	/* Bail if the PDC sequencer is mid-transition. */
	if (io_read32(pdc_status + RPMH_PDC_MODE_STATUS_DRV0) &
	    PDC_MODE_STATUS_SEQ_BUSY_BIT)
		return TEE_ERROR_BUSY;

	/* Reset the retention logic and let the write settle. */
	io_setbits32(pub + TURINGGDSP_QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA_BIT);
	dsb();
	udelay(2000);

	/* Disconnect the SWAY NIU socket to halt config-NoC traffic. */
	io_clrbits32(gcc_base + r->gcc_cfg_ahb_cbcr, CBCR_CLK_ENABLE_BIT);

	/*
	 * If powered on and either master port (IL0 or IL1) is busy, halt
	 * mem-NoC traffic and wait for the acknowledge.
	 */
	if (io_read32(tcsr + r->tcsr_pwr_on) & TCSR_TURING_BIT) {
		if (!(io_read32(tcsr + r->tcsr_il0_master_idle) &
		      TCSR_TURING_BIT) ||
		    !(io_read32(tcsr + r->tcsr_il1_master_idle) &
		      TCSR_TURING_BIT)) {
			io_setbits32(tcsr + r->tcsr_haltreq, TCSR_TURING_BIT);

			timeout = timeout_init_us(GPDSP_HALT_ACK_TIMEOUT_US);
			while (!(io_read32(tcsr + r->tcsr_haltack) &
				 TCSR_TURING_BIT)) {
				if (timeout_elapsed(timeout))
					break;
				udelay(5);
			}
		}
	}

	/* Assert the PDC reset, then pulse the subsystem restart. */
	io_setbits32(pdc_global + RPMH_PDC_SYNC_RESET, r->pdc_sync_reset_bit);

	io_setbits32(aoss_cc + AOSS_CC_GPDSP_RESTART, r->gpdsp_restart_bit);
	udelay(200);
	io_clrbits32(aoss_cc + AOSS_CC_GPDSP_RESTART, r->gpdsp_restart_bit);
	dsb();
	udelay(200);

	/* De-assert the PDC reset and clear the halt request. */
	io_clrbits32(pdc_global + RPMH_PDC_SYNC_RESET, r->pdc_sync_reset_bit);
	io_clrbits32(tcsr + r->tcsr_haltreq, TCSR_TURING_BIT);
	udelay(100);

	return TEE_SUCCESS;
}

/* HALT_ACK polls for up to 1s; a QDSP6 in a bad state may never ack. */
#define LPASS_HALT_ACK_TIMEOUT_US	(200000 * 5)
#define LPASS_COLLAPSE_TIMEOUT_US	400000
#define LPASS_AUDIO_HM_ON_TIMEOUT_US	10000
#define LPASS_QCHANNEL_TRIES		10

static TEE_Result lpass_rcg_to_xo(vaddr_t cmd_rcgr, vaddr_t cfg_rcgr)
{
	uint32_t val = 0;

	io_clrbits32(cfg_rcgr, CFG_RCGR_SRC_SEL_MASK | CFG_RCGR_SRC_DIV_MASK);
	io_setbits32(cmd_rcgr, CMD_RCGR_UPDATE_BIT);

	return IO_READ32_POLL_TIMEOUT(cmd_rcgr, val, rcg_update_done(val), 1,
				      LPASS_COLLAPSE_TIMEOUT_US);
}

/* Quiesce and power collapse LPASS_CORE_HM if it is on. */
static TEE_Result lpass_core_hm_collapse(vaddr_t lpass_base, vaddr_t sbm)
{
	vaddr_t top_cc = lpass_base + LPASS_TOP_CC_OFFSET;
	vaddr_t hm_cc = lpass_base + LPASS_CORE_HM_CC_OFFSET;
	vaddr_t aon_cc = lpass_base + LPASS_AON_CC_OFFSET;
	vaddr_t gdscr = top_cc + LPASS_TOP_CC_CORE_HM_GDSCR;
	vaddr_t qch = hm_cc + LPASS_CORE_HM_AF_NOC_QCHANNEL_CTL;
	TEE_Result res = TEE_SUCCESS;
	unsigned int tries = 0;
	uint32_t val = 0;

	/* Retention would keep the core state across the reset. */
	io_clrbits32(top_cc + LPASS_TOP_CC_CORE_GDSCR_DEBUG_VOTE,
		     GDSCR_DEBUG_VOTE_RETENTION_BIT);
	io_clrbits32(gdscr, GDSCR_RETAIN_FF_ENABLE_BIT);

	if (!(io_read32(gdscr) & GDSCR_PWR_ON_BIT))
		return TEE_SUCCESS;

	/* Halt the AF NoC through its QChannel, retrying while it denies. */
	do {
		if (tries++ == LPASS_QCHANNEL_TRIES)
			return TEE_ERROR_BUSY;

		io_setbits32(qch, QCHANNEL_CTL_QREQN_BIT);
		io_setbits32(qch, QCHANNEL_CTL_SW_OVERRIDE_EN_BIT);
		res = IO_READ32_POLL_TIMEOUT(qch, val, qch_inactive(val), 2,
					     LPASS_COLLAPSE_TIMEOUT_US);
		if (res)
			return res;

		/* QDENY decides the retry; a late QACCEPTn is not an error. */
		io_clrbits32(qch, QCHANNEL_CTL_QREQN_BIT);
		IO_READ32_POLL_TIMEOUT(qch, val, qch_accepted(val), 2,
				       LPASS_COLLAPSE_TIMEOUT_US);
	} while (io_read32(qch) & QCHANNEL_CTL_QDENY_BIT);

	res = lpass_rcg_to_xo(hm_cc + LPASS_CORE_HM_CORE_CMD_RCGR,
			      hm_cc + LPASS_CORE_HM_CORE_CFG_RCGR);
	if (res)
		return res;

	/* PLL standby. */
	io_clrbits32(hm_cc + LPASS_CORE_HM_DIG_PLL_OPMODE, PLL_OPMODE_MASK);

	/* Isolate LPASS_CORE_HM from the AG NoC. */
	io_write32(sbm + LPASS_AG_NOC_SBM_FLAGOUTSET0_LOW,
		   LPASS_AG_NOC_SBM_PORT0_BIT);
	res = IO_READ32_POLL_TIMEOUT(sbm + LPASS_AG_NOC_SBM_SENSEIN0_LOW, val,
				     sbm_only_port0_sensed(val), 2,
				     LPASS_COLLAPSE_TIMEOUT_US);
	if (res)
		return res;

	io_setbits32(aon_cc + LPASS_AON_CC_CORE_HM_COLLAPSE_VOTE, BIT(0));
	io_setbits32(gdscr, GDSCR_SW_COLLAPSE_BIT);

	return IO_READ32_POLL_TIMEOUT(gdscr, val, gdsc_is_off(val), 2,
				      LPASS_COLLAPSE_TIMEOUT_US);
}

/* Park the LPASS_AUDIO_HM clocks and PLL, then power collapse it. */
static TEE_Result lpass_audio_hm_collapse(vaddr_t audio_cc, vaddr_t hm_gdscr)
{
	vaddr_t pll_mode = audio_cc + LPASS_AUDIO_CC_PLL_MODE;
	vaddr_t mclk_rcgr = audio_cc + LPASS_AUDIO_CC_RX_MCLK_CMD_RCGR;
	TEE_Result res = TEE_SUCCESS;
	uint32_t val = 0;

	if (io_read32(audio_cc + LPASS_AUDIO_CC_RX_MCLK_MODE_MUXSEL) & BIT(0)) {
		res = lpass_rcg_to_xo(mclk_rcgr, mclk_rcgr + RCGR_CFG_OFFSET);
		if (res)
			return res;
	}

	io_clrbits32(pll_mode, PLL_MODE_OUTCTRL_BIT);
	io_clrbits32(audio_cc + LPASS_AUDIO_CC_PLL_OPMODE, PLL_OPMODE_MASK);
	io_clrbits32(pll_mode, PLL_MODE_RESET_N_BIT);
	io_clrbits32(pll_mode, PLL_MODE_BYPASSNL_BIT);
	io_clrbits32(audio_cc + LPASS_AUDIO_CC_DIG_PLL_OPMODE, PLL_OPMODE_MASK);

	io_setbits32(hm_gdscr, GDSCR_SW_COLLAPSE_BIT);

	return IO_READ32_POLL_TIMEOUT(hm_gdscr, val, gdsc_is_off(val), 5,
				      LPASS_COLLAPSE_TIMEOUT_US);
}

/* Reset LPASS_AUDIO_HM, then power collapse it and LPASS_AUDIO_ML. */
static TEE_Result lpass_audio_collapse(vaddr_t lpass_base)
{
	vaddr_t aon_cc = lpass_base + LPASS_AON_CC_OFFSET;
	vaddr_t audio_cc = lpass_base + LPASS_AUDIO_CC_OFFSET;
	vaddr_t hm_gdscr = aon_cc + LPASS_AON_CC_AUDIO_HM_GDSCR;
	vaddr_t ml_gdscr = aon_cc + LPASS_AON_CC_AUDIO_ML_GDSCR;
	vaddr_t bcr = aon_cc + LPASS_AON_CC_AUDIO_HM_BCR;
	TEE_Result res = TEE_SUCCESS;
	uint32_t val = 0;

	/* The block reset needs the domain powered. */
	io_clrbits32(hm_gdscr, GDSCR_SW_COLLAPSE_BIT);
	res = IO_READ32_POLL_TIMEOUT(hm_gdscr, val, gdsc_is_on(val), 5,
				     LPASS_AUDIO_HM_ON_TIMEOUT_US);
	if (res)
		return res;

	io_setbits32(bcr, BCR_BLK_ARES_BIT);
	res = IO_READ32_POLL_TIMEOUT(bcr, val, bcr_is_asserted(val), 1,
				     LPASS_COLLAPSE_TIMEOUT_US);
	if (res)
		return res;
	/* At least five sleep clock cycles each way. */
	udelay(150);
	io_clrbits32(bcr, BCR_BLK_ARES_BIT);
	udelay(150);

	if (io_read32(hm_gdscr) & GDSCR_PWR_ON_BIT) {
		res = lpass_audio_hm_collapse(audio_cc, hm_gdscr);
		if (res)
			return res;
	}

	if (io_read32(ml_gdscr) & GDSCR_PWR_ON_BIT)
		io_setbits32(ml_gdscr, GDSCR_SW_COLLAPSE_BIT);

	return TEE_SUCCESS;
}

/*
 * Put LPASS through a subsystem restart (AOSS_CC_LPASS_RESTART and PDC sync
 * reset), so that a stopped or crashed ADSP boots again from reset.
 */
static TEE_Result lpass_reset_processor(void)
{
	vaddr_t pdc_global = QCOM_IO_VA(RPMH_PDC_GLOBAL_BASE,
					RPMH_PDC_GLOBAL_SIZE);
	vaddr_t pdc_status = QCOM_IO_VA(RPMH_PDC_AUDIO_BASE,
					RPMH_PDC_AUDIO_SIZE);
	vaddr_t tcsr = QCOM_IO_VA(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t aoss_cc = QCOM_IO_VA(AOSS_CC_BASE, AOSS_CC_SIZE);
	vaddr_t lpass_base = QCOM_IO_VA(LPASS_BASE, LPASS_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t aon_cc = lpass_base + LPASS_AON_CC_OFFSET;
	vaddr_t pub = lpass_base + LPASS_PUB_OFFSET;
	vaddr_t sbm = lpass_base + LPASS_AG_NOC_SBM_OFFSET;
	TEE_Result res = TEE_SUCCESS;
	uint32_t val = 0;
	bool island = false;

	if (!gcc_base || !lpass_base || !aoss_cc || !pdc_global ||
	    !pdc_status || !tcsr)
		return TEE_ERROR_GENERIC;

	/* Bail if the PDC sequencer is mid-transition. */
	if (io_read32(pdc_status + RPMH_PDC_MODE_STATUS_DRV0) &
	    PDC_MODE_STATUS_SEQ_BUSY_BIT)
		return TEE_ERROR_BUSY;

	/* The QDSP6SS registers are reachable only with these branches on. */
	res = qcom_clock_enable_cbc(gcc_base + GCC_CFG_NOC_LPASS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(aon_cc + LPASS_AON_CC_Q6_AHBS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = lpass_core_hm_collapse(lpass_base, sbm);
	if (res != TEE_SUCCESS)
		return res;

	island = io_read32(lpass_base + LPASS_TOP_CC_OFFSET +
			   LPASS_TOP_CC_ISLAND_MODE_STATUS) &
		 LPASS_ISLAND_MODE_BIT;
	if (!island) {
		res = lpass_audio_collapse(lpass_base);
		if (res != TEE_SUCCESS)
			return res;
	}

	/* Reset the retention flops too; the QDSP6 clears this once it runs. */
	io_setbits32(pub + LPASS_QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA_BIT);

	io_setbits32(tcsr + TCSR_LPASS_HALTREQ, TCSR_LPASS_BIT);
	/* A QDSP6 in a bad state may never ack; reset it anyway. */
	IO_READ32_POLL_TIMEOUT(tcsr + TCSR_LPASS_HALTACK, val,
			       lpass_halt_acked(val), 5,
			       LPASS_HALT_ACK_TIMEOUT_US);

	io_setbits32(pdc_global + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_AUDIO_BIT);
	io_setbits32(aoss_cc + AOSS_CC_LPASS_RESTART, LPASS_RESTART_SS_BIT);
	dsb();
	mdelay(10);

	io_clrbits32(pdc_global + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_AUDIO_BIT);
	io_clrbits32(aoss_cc + AOSS_CC_LPASS_RESTART, LPASS_RESTART_SS_BIT);
	dsb();
	udelay(200);

	io_clrbits32(tcsr + TCSR_LPASS_HALTREQ, TCSR_LPASS_BIT);
	udelay(100);

	io_write32(sbm + LPASS_AG_NOC_SBM_FLAGOUTSET0_LOW, 0);
	io_write32(sbm + LPASS_AG_NOC_SBM_FLAGOUTCLR0_LOW,
		   LPASS_AG_NOC_SBM_PORT1_BIT);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_reset_processor(&cdsp0_reset_regs);
	case QCOM_CLKS_TURING1:
		return cdsp_reset_processor(&cdsp1_reset_regs);
	case QCOM_CLKS_GPDSP0:
		return gpdsp_reset_processor(&gpdsp0_reset_regs);
	case QCOM_CLKS_GPDSP1:
		return gpdsp_reset_processor(&gpdsp1_reset_regs);
	case QCOM_CLKS_LPASS:
		return lpass_reset_processor();
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
	case QCOM_CLKS_LPASS:
		return lpass_setup();
	case QCOM_CLKS_GPDSP0:
		return gpdsp_setup(TURING_GDSP_0_BASE, GCC_GPDSP_0_CFG_AHB_CBCR,
				   GCC_AGGRE_NOC_GPDSP_0_AXI_CBCR);
	case QCOM_CLKS_GPDSP1:
		return gpdsp_setup(TURING_GDSP_1_BASE, GCC_GPDSP_1_CFG_AHB_CBCR,
				   GCC_AGGRE_NOC_GPDSP_1_AXI_CBCR);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
timeout:
	EMSG("Timeout trying to enable clock group %d\n", group);
	return TEE_ERROR_TIMEOUT;
}
