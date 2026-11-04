// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk_qcom.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

#include "clock_hoya.h"

/* HALT_ACK polls for up to 1s (200000 * 5us), matching the reference. */
#define HALT_ACK_TIMEOUT_US		(200000 * 5)

#define LPASS_COLLAPSE_TIMEOUT_US	400000
#define LPASS_AUDIO_HM_ON_TIMEOUT_US	10000
#define LPASS_QCHANNEL_TRIES		10

static bool halt_acked(uint32_t val)
{
	return val & TCSR_HALT_BIT;
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

static bool tcsr_bit_set(vaddr_t reg)
{
	return io_read32(reg) & TCSR_HALT_BIT;
}

static bool pdc_low_power(vaddr_t pdc)
{
	return io_read32(pdc + RPMH_PDC_MODE_STATUS_DRV0) &
	       PDC_MODE_STATUS_BIT;
}

/* A QDSP6 in a bad state may never ack; the caller resets it anyway. */
static void q6_halt(vaddr_t haltreq, vaddr_t haltack)
{
	uint32_t val = 0;

	io_setbits32(haltreq, TCSR_HALT_BIT);
	IO_READ32_POLL_TIMEOUT(haltack, val, halt_acked(val), 5,
			       HALT_ACK_TIMEOUT_US);
}

/* Pulse the subsystem restart with the subsystem PDC held in reset. */
static void q6_restart(vaddr_t pdc_global, uint32_t pdc_bit,
		       vaddr_t restart, uint32_t restart_bit)
{
	io_setbits32(pdc_global + RPMH_PDC_SYNC_RESET, pdc_bit);

	io_setbits32(restart, restart_bit);
	udelay(200);
	io_clrbits32(restart, restart_bit);
	dsb();
	udelay(200);

	io_clrbits32(pdc_global + RPMH_PDC_SYNC_RESET, pdc_bit);
}

/* Powered on with its master port still busy */
static bool nsp_master_busy(vaddr_t tcsr, const struct hoya_nsp *nsp)
{
	if (!tcsr_bit_set(tcsr + nsp->tcsr_pwr_on))
		return false;

	return !tcsr_bit_set(tcsr + nsp->tcsr_master_idle);
}

/* Powered on with either master port (IL0 or IL1) still busy */
static bool gpdsp_master_busy(vaddr_t tcsr, const struct hoya_gpdsp *gpdsp)
{
	if (!tcsr_bit_set(tcsr + gpdsp->tcsr_pwr_on))
		return false;

	return !tcsr_bit_set(tcsr + gpdsp->tcsr_il0_master_idle) ||
	       !tcsr_bit_set(tcsr + gpdsp->tcsr_il1_master_idle);
}

static bool gdsc_wait_on(vaddr_t gdscr, uint64_t timeout)
{
	while (!timeout_elapsed(timeout)) {
		if (gdsc_is_on(io_read32(gdscr)))
			return true;

		udelay(10);
	}

	return false;
}

TEE_Result hoya_nsp_enable(const struct hoya_nsp *nsp)
{
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t boot_base = 0;
	vaddr_t core_cc = 0;
	vaddr_t cc_base = 0;
	uint64_t timeout = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc_base)
		return TEE_ERROR_GENERIC;

	/* Turing bus clock branch connected to the NIU socket */
	res = qcom_clock_enable_cbc(gcc_base + nsp->gcc_cfg_ahb_cbcr);
	if (res != TEE_SUCCESS)
		return res;

	cc_base = QCOM_IO_VA(nsp->base + TURINGNSP_CC_OFFSET,
			     TURINGNSP_PROC_WINDOW_SIZE);
	boot_base = QCOM_IO_VA(nsp->base + TURINGNSP_BOOT_OFFSET,
			       TURINGNSP_PROC_WINDOW_SIZE);
	timeout = timeout_init_us(10000);
	if (!cc_base || !boot_base)
		return TEE_ERROR_GENERIC;

	core_cc = boot_base - TURINGNSP_BOOT_OFFSET + TURINGNSP_CORE_CC_OFFSET;

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

	/* Retention flop */
	io_clrbits32(cc_base + TURINGNSP_VAPSS_GDSCR, GDSCR_SW_COLLAPSE_BIT);
	if (!gdsc_wait_on(cc_base + TURINGNSP_VAPSS_GDSCR, timeout))
		return TEE_ERROR_TIMEOUT;

	io_setbits32(cc_base + TURINGNSP_VAPSS_GDSCR,
		     GDSCR_RETAIN_FF_ENABLE_BIT | GDSCR_SW_COLLAPSE_BIT);

	/* QDSP6 core, AXI and NSP_AUX branches the boot FSM needs */
	io_setbits32(core_cc + TURINGNSP_QDSP6SS_CORE_CBCR,
		     CBCR_BRANCH_ENABLE_BIT);
	io_setbits32(cc_base + TURINGNSP_Q6SS_Q6_AXIM_CBCR,
		     CBCR_HW_CTL_ENABLE_BIT);
	io_setbits32(cc_base + TURINGNSP_Q6SS_AXIS2_CBCR,
		     CBCR_HW_CTL_ENABLE_BIT);
	io_setbits32(cc_base + TURINGNSP_NSPAUX_XO_CBCR,
		     CBCR_BRANCH_ENABLE_BIT);

	return TEE_SUCCESS;
}

TEE_Result
hoya_nsp_enable_processor_lucidevo(const struct hoya_nsp *nsp,
				   const struct qcom_lucidevo_pll_config *pll)
{
	vaddr_t boot_base = QCOM_IO_VA(nsp->base + TURINGNSP_BOOT_OFFSET,
				       TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t pll_base = boot_base - TURINGNSP_BOOT_OFFSET +
			   TURINGNSP_Q6_PLL_OFFSET;
	vaddr_t core_cc = boot_base - TURINGNSP_BOOT_OFFSET +
			  TURINGNSP_CORE_CC_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	if (!boot_base)
		return TEE_ERROR_GENERIC;

	/* The Q6 PLL registers must not be touched before the FSM is done */
	res = qcom_lucidevo_pll_enable(pll_base, pll);
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

TEE_Result hoya_nsp_reset(const struct hoya_nsp *nsp)
{
	vaddr_t pub_base = QCOM_IO_VA(nsp->base + TURINGNSP_BOOT_OFFSET,
				      TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t cc_base = QCOM_IO_VA(nsp->base + TURINGNSP_CC_OFFSET,
				     TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t pdc_global = QCOM_IO_VA(RPMH_PDC_GLOBAL_BASE,
					RPMH_PDC_GLOBAL_SIZE);
	vaddr_t pdc_status = QCOM_IO_VA(nsp->pdc_base, nsp->pdc_size);
	vaddr_t tcsr = QCOM_IO_VA(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t aoss_cc = QCOM_IO_VA(AOSS_CC_BASE, AOSS_CC_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	TEE_Result res = TEE_SUCCESS;

	if (!pub_base || !cc_base || !gcc_base || !aoss_cc || !pdc_global ||
	    !pdc_status || !tcsr)
		return TEE_ERROR_GENERIC;

	/* Bail while the PDC holds the NSP in low power. */
	if (pdc_low_power(pdc_status))
		return TEE_ERROR_BUSY;

	/* Activate a full QDSP6 reset before the SSR. */
	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_Q6SS_ALT_RESET_AON);
	if (res != TEE_SUCCESS)
		return res;
	io_setbits32(cc_base + TURINGNSP_Q6SS_ALT_RESET_CTL,
		     Q6SS_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT);

	/* Reset the retention logic */
	io_setbits32(pub_base + TURINGNSP_QDSP6SS_RET_CFG, nsp->ret_cfg_ares);
	if (nsp->ret_cfg_settle_us) {
		dsb();
		udelay(nsp->ret_cfg_settle_us);
	}

	/* Retain the NSP_AUX registers across the reset. */
	io_setbits32(cc_base + TURINGNSP_NSPAUX_XO_CBCR,
		     CBCR_BRANCH_ENABLE_BIT);
	io_setbits32(cc_base + TURINGNSP_NSPAUX_GDSCR,
		     NSPAUX_GDSCR_RETAIN_FF_ENABLE_BIT);

	/* Disconnect the SWAY NIU socket to halt config-NoC traffic. */
	io_clrbits32(gcc_base + nsp->gcc_cfg_ahb_cbcr, CBCR_BRANCH_ENABLE_BIT);

	/* Halt mem-NoC traffic. */
	if (nsp_master_busy(tcsr, nsp))
		q6_halt(tcsr + nsp->tcsr_haltreq, tcsr + nsp->tcsr_haltack);

	q6_restart(pdc_global, nsp->pdc_sync_reset_bit,
		   aoss_cc + AOSS_CC_COMPUTESS_RESTART, nsp->restart_bit);

	io_clrbits32(tcsr + nsp->tcsr_haltreq, TCSR_HALT_BIT);
	udelay(100);

	return TEE_SUCCESS;
}

TEE_Result
hoya_gpdsp_setup_lucidevo(const struct hoya_gpdsp *gpdsp,
			  const struct qcom_lucidevo_pll_config *pll)
{
	vaddr_t base = QCOM_IO_VA(gpdsp->base, TURINGGDSP_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t gdsp_cc = base + TURINGGDSP_GDSP_CC_OFFSET;
	vaddr_t core_cc = base + TURINGGDSP_CORE_CC_OFFSET;
	vaddr_t pll_base = base + TURINGGDSP_PLL_OFFSET;
	vaddr_t pub = base + TURINGGDSP_PUB_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc_base || !base)
		return TEE_ERROR_GENERIC;

	/* Turing slave-way bus clock branch, also on NIU socket. */
	res = qcom_clock_enable_cbc(gcc_base + gpdsp->gcc_cfg_ahb_cbcr);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(gcc_base + gpdsp->gcc_aggre_axi_cbcr);
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
	res = qcom_lucidevo_pll_enable(pll_base, pll);
	if (res != TEE_SUCCESS)
		return res;

	return qcom_clock_set_rate(core_cc + TURINGGDSP_QDSP6SS_CORE_CFG_RCGR,
				   core_cc + TURINGGDSP_QDSP6SS_CORE_CMD_RCGR,
				   Q6RCG_CFG_VALUE);
}

/* Halt the GP-DSP bus traffic and pulse its subsystem restart. */
static void gpdsp_restart(const struct hoya_gpdsp *gpdsp, vaddr_t gcc_base,
			  vaddr_t tcsr, vaddr_t pdc_global, vaddr_t aoss_cc)
{
	/* Disconnect the SWAY NIU socket to halt config-NoC traffic. */
	io_clrbits32(gcc_base + gpdsp->gcc_cfg_ahb_cbcr,
		     CBCR_BRANCH_ENABLE_BIT);

	/* Halt mem-NoC traffic. */
	if (gpdsp_master_busy(tcsr, gpdsp))
		q6_halt(tcsr + gpdsp->tcsr_haltreq, tcsr + gpdsp->tcsr_haltack);

	q6_restart(pdc_global, gpdsp->pdc_sync_reset_bit,
		   aoss_cc + AOSS_CC_GPDSP_RESTART, gpdsp->restart_bit);

	io_clrbits32(tcsr + gpdsp->tcsr_haltreq, TCSR_HALT_BIT);
	udelay(100);
}

TEE_Result hoya_gpdsp_reset(const struct hoya_gpdsp *gpdsp)
{
	vaddr_t pdc_global = QCOM_IO_VA(RPMH_PDC_GLOBAL_BASE,
					RPMH_PDC_GLOBAL_SIZE);
	vaddr_t pdc_status = QCOM_IO_VA(gpdsp->pdc_base, gpdsp->pdc_size);
	vaddr_t base = QCOM_IO_VA(gpdsp->base, TURINGGDSP_SIZE);
	vaddr_t tcsr = QCOM_IO_VA(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t aoss_cc = QCOM_IO_VA(AOSS_CC_BASE, AOSS_CC_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t pub = base + TURINGGDSP_PUB_OFFSET;

	if (!base || !gcc_base || !aoss_cc || !pdc_global || !pdc_status ||
	    !tcsr)
		return TEE_ERROR_GENERIC;

	/*
	 * While the PDC holds the GP-DSP in low power mode, accessing its
	 * registers stalls the CPU. A first restart takes it out of the PDC's
	 * hands so that the retention logic can be reset too.
	 */
	if (pdc_low_power(pdc_status)) {
		gpdsp_restart(gpdsp, gcc_base, tcsr, pdc_global, aoss_cc);
		if (pdc_low_power(pdc_status))
			return TEE_ERROR_BUSY;
	}

	/* Reset the retention logic and let the write settle. */
	io_setbits32(pub + TURINGGDSP_QDSP6SS_RET_CFG, gpdsp->ret_cfg_ares);
	dsb();
	udelay(2000);

	gpdsp_restart(gpdsp, gcc_base, tcsr, pdc_global, aoss_cc);

	return TEE_SUCCESS;
}

/* A clock branch the LPASS QDSP6 needs, and what it is for */
struct lpass_q6_branch {
	const char *purpose;
	uint32_t cbcr;	/* Relative to LPASS_BASE */
};

/* In enable order */
static const struct lpass_q6_branch lpass_q6_branches[] = {
	{ "QDSP6 AHB master",
	  LPASS_AON_CC_OFFSET + LPASS_AON_CC_Q6_AHBM_CBCR },
	{ "QDSP6SS register access",
	  LPASS_AON_CC_OFFSET + LPASS_AON_CC_Q6_AHBS_CBCR },
	{ "QDSP6 LPI AXI master",
	  LPASS_TOP_CC_OFFSET + LPASS_TOP_CC_LPI_Q6_AXIM_HS_CBCR },
	{ "QDSP6 core", LPASS_CORE_CC_OFFSET + LPASS_QDSP6SS_CORE_CBCR },
};

TEE_Result
hoya_lpass_setup_lucidevo(const struct qcom_lucidevo_pll_config *pll)
{
	vaddr_t lpass_base = QCOM_IO_VA(LPASS_BASE, LPASS_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t core_cc = lpass_base + LPASS_CORE_CC_OFFSET;
	vaddr_t pll_base = lpass_base + LPASS_PLL_OFFSET;
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	if (!gcc_base || !lpass_base)
		return TEE_ERROR_GENERIC;

	/* Enable LPASS access from the config NoC. */
	res = qcom_clock_enable_cbc(gcc_base + GCC_CFG_NOC_LPASS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	for (i = 0; i < ARRAY_SIZE(lpass_q6_branches); i++) {
		const struct lpass_q6_branch *b = lpass_q6_branches + i;

		res = qcom_clock_enable_cbc(lpass_base + b->cbcr);
		if (res != TEE_SUCCESS) {
			EMSG("LPASS %s clock enable failed: %#"PRIx32,
			     b->purpose, res);
			return res;
		}
	}

	/* Configure and lock the Q6 PLL, then switch the core RCG onto it. */
	res = qcom_lucidevo_pll_enable(pll_base, pll);
	if (res != TEE_SUCCESS)
		return res;

	return qcom_clock_set_rate(core_cc + LPASS_QDSP6SS_CORE_CFG_RCGR,
				   core_cc + LPASS_QDSP6SS_CORE_CMD_RCGR,
				   Q6RCG_CFG_VALUE);
}

static TEE_Result lpass_rcg_to_xo(vaddr_t cmd_rcgr, vaddr_t cfg_rcgr)
{
	uint32_t val = 0;

	io_clrbits32(cfg_rcgr, CFG_RCGR_SRC_SEL_MASK | CFG_RCGR_SRC_DIV_MASK);
	io_setbits32(cmd_rcgr, CMD_RCGR_UPDATE_BIT);

	if (IO_READ32_POLL_TIMEOUT(cmd_rcgr, val, rcg_update_done(val), 1,
				   LPASS_COLLAPSE_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
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

	if (!gdsc_is_on(io_read32(gdscr)))
		return TEE_SUCCESS;

	/* Halt the AF NoC through its QChannel, retrying while it denies. */
	do {
		if (tries++ == LPASS_QCHANNEL_TRIES)
			return TEE_ERROR_BUSY;

		io_setbits32(qch, QCHANNEL_CTL_QREQN_BIT);
		io_setbits32(qch, QCHANNEL_CTL_SW_OVERRIDE_EN_BIT);
		if (IO_READ32_POLL_TIMEOUT(qch, val, qch_inactive(val), 2,
					   LPASS_COLLAPSE_TIMEOUT_US))
			return TEE_ERROR_TIMEOUT;

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
	if (IO_READ32_POLL_TIMEOUT(sbm + LPASS_AG_NOC_SBM_SENSEIN0_LOW, val,
				   sbm_only_port0_sensed(val), 2,
				   LPASS_COLLAPSE_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	io_setbits32(aon_cc + LPASS_AON_CC_CORE_HM_COLLAPSE_VOTE, BIT(0));
	io_setbits32(gdscr, GDSCR_SW_COLLAPSE_BIT);

	if (IO_READ32_POLL_TIMEOUT(gdscr, val, gdsc_is_off(val), 2,
				   LPASS_COLLAPSE_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

/* Park the LPASS_AUDIO_HM clocks and PLL, then power collapse it. */
static TEE_Result lpass_audio_hm_collapse(vaddr_t audio_cc, vaddr_t hm_gdscr)
{
	vaddr_t pll_mode = audio_cc + LPASS_AUDIO_CC_PLL_MODE;
	vaddr_t mclk_rcgr = audio_cc + LPASS_AUDIO_CC_RX_MCLK_CMD_RCGR;
	TEE_Result res = TEE_SUCCESS;
	uint32_t val = 0;

	if (io_read32(audio_cc + LPASS_AUDIO_CC_RX_MCLK_MODE_MUXSEL) &
	    RX_MCLK_MODE_MUXSEL_SEL_BIT) {
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

	if (IO_READ32_POLL_TIMEOUT(hm_gdscr, val, gdsc_is_off(val), 5,
				   LPASS_COLLAPSE_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
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
	if (IO_READ32_POLL_TIMEOUT(hm_gdscr, val, gdsc_is_on(val), 5,
				   LPASS_AUDIO_HM_ON_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	io_setbits32(bcr, BCR_BLK_ARES_BIT);
	if (IO_READ32_POLL_TIMEOUT(bcr, val, bcr_is_asserted(val), 1,
				   LPASS_COLLAPSE_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;
	/* At least five sleep clock cycles each way. */
	udelay(150);
	io_clrbits32(bcr, BCR_BLK_ARES_BIT);
	udelay(150);

	if (gdsc_is_on(io_read32(hm_gdscr))) {
		res = lpass_audio_hm_collapse(audio_cc, hm_gdscr);
		if (res)
			return res;
	}

	if (gdsc_is_on(io_read32(ml_gdscr)))
		io_setbits32(ml_gdscr, GDSCR_SW_COLLAPSE_BIT);

	return TEE_SUCCESS;
}

static bool lpass_in_island(vaddr_t lpass_base)
{
	return io_read32(lpass_base + LPASS_TOP_CC_OFFSET +
			 LPASS_TOP_CC_ISLAND_MODE_STATUS) &
	       LPASS_ISLAND_MODE_BIT;
}

/* Quiesce LPASS_CORE_HM and the audio domains before the restart. */
static TEE_Result lpass_quiesce(vaddr_t lpass_base, vaddr_t sbm,
				uint32_t ret_cfg_ares)
{
	vaddr_t aon_cc = lpass_base + LPASS_AON_CC_OFFSET;
	vaddr_t pub = lpass_base + LPASS_PUB_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	/* The QDSP6SS registers are reachable only with this branch on. */
	res = qcom_clock_enable_cbc(aon_cc + LPASS_AON_CC_Q6_AHBS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	res = lpass_core_hm_collapse(lpass_base, sbm);
	if (res != TEE_SUCCESS)
		return res;

	if (!lpass_in_island(lpass_base)) {
		res = lpass_audio_collapse(lpass_base);
		if (res != TEE_SUCCESS)
			return res;
	}

	/* Reset the retention flops too. */
	io_setbits32(pub + LPASS_QDSP6SS_RET_CFG, ret_cfg_ares);

	return TEE_SUCCESS;
}

TEE_Result hoya_lpass_reset(uint32_t ret_cfg_ares)
{
	vaddr_t pdc_global = QCOM_IO_VA(RPMH_PDC_GLOBAL_BASE,
					RPMH_PDC_GLOBAL_SIZE);
	vaddr_t pdc_status = QCOM_IO_VA(RPMH_PDC_AUDIO_BASE,
					RPMH_PDC_AUDIO_SIZE);
	vaddr_t tcsr = QCOM_IO_VA(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t aoss_cc = QCOM_IO_VA(AOSS_CC_BASE, AOSS_CC_SIZE);
	vaddr_t lpass_base = QCOM_IO_VA(LPASS_BASE, LPASS_SIZE);
	vaddr_t gcc_base = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t sbm = lpass_base + LPASS_AG_NOC_SBM_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc_base || !lpass_base || !aoss_cc || !pdc_global ||
	    !pdc_status || !tcsr)
		return TEE_ERROR_GENERIC;

	res = qcom_clock_enable_cbc(gcc_base + GCC_CFG_NOC_LPASS_CBCR);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * While the PDC holds LPASS in low power mode, accessing its registers
	 * stalls the CPU; the subsystem restart below resets it all the same.
	 */
	if (!pdc_low_power(pdc_status)) {
		res = lpass_quiesce(lpass_base, sbm, ret_cfg_ares);
		if (res != TEE_SUCCESS)
			return res;
	}

	q6_halt(tcsr + TCSR_LPASS_HALTREQ, tcsr + TCSR_LPASS_HALTACK);

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

	io_clrbits32(tcsr + TCSR_LPASS_HALTREQ, TCSR_HALT_BIT);
	udelay(100);

	io_write32(sbm + LPASS_AG_NOC_SBM_FLAGOUTSET0_LOW, 0);
	io_write32(sbm + LPASS_AG_NOC_SBM_FLAGOUTCLR0_LOW,
		   LPASS_AG_NOC_SBM_PORT1_BIT);

	return TEE_SUCCESS;
}
