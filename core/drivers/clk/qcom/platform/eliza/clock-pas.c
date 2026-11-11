// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <drivers/qcom_qdsp6ss.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

#include "clock_group.h"

/*
 * Secure only: a non-secure mapping silently drops writes to the LPASS EVB
 * select, Q6 alternate reset and AON branches
 */
register_phys_mem(MEM_AREA_IO_SEC, GCC_BASE, GCC_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, LPASS_BASE, LPASS_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, TURING_BASE, TURING_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, RPMH_PDC_AUDIO_BASE, RPMH_PDC_AUDIO_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, RPMH_PDC_COMPUTE_BASE,
		  RPMH_PDC_COMPUTE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, AOSS_CC_RESTART_BASE, AOSS_CC_RESTART_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, LPASS_HOST_LINK_BASE, LPASS_HOST_LINK_SIZE);

static bool setup_done[QCOM_CLKS_MAX];

static vaddr_t map(paddr_t pa, size_t size)
{
	struct io_pa_va io = { .pa = pa };

	return io_pa_or_va(&io, size);
}

static const struct qcom_pll_offsets q6_pll_offsets =
	QCOM_LUCID_EVO_PLL_OFFSETS;

/* Lucid OLE: the calibration L goes to the process and ring oscillator */
static const struct qcom_pll_config q6_pll_cfg = {
	.offsets = &q6_pll_offsets,
	.l_val = Q6_PLL_L_VAL,
	.cal_l_val = SHIFT_U32(Q6_PLL_CAL_L_VAL, 8) | Q6_PLL_CAL_L_VAL,
	.pre_div = 1,
	.config_ctl = Q6_PLL_CONFIG_CTL,
	.config_ctl_u = Q6_PLL_CONFIG_CTL_U,
	.config_ctl_u1 = Q6_PLL_CONFIG_CTL_U1,
	.user_ctl = Q6_PLL_USER_CTL,
	.user_ctl_u = Q6_PLL_USER_CTL_U,
};

static TEE_Result q6_clock_enable(vaddr_t pll, vaddr_t cmd_rcgr,
				  vaddr_t cfg_rcgr)
{
	TEE_Result res = TEE_SUCCESS;

	io_write32(pll + PLL_TEST_CTL, Q6_PLL_TEST_CTL);
	io_write32(pll + PLL_TEST_CTL_U, Q6_PLL_TEST_CTL_U);
	io_write32(pll + PLL_TEST_CTL_U1, Q6_PLL_TEST_CTL_U1);
	io_write32(pll + PLL_TEST_CTL_U2, Q6_PLL_TEST_CTL_U2);

	res = qcom_lucidevo_pll_enable(pll, &q6_pll_cfg);
	if (res)
		return res;

	return qcom_clock_set_rate(cfg_rcgr, cmd_rcgr, Q6RCG_CFG_VALUE);
}

/*
 * XBL uses the Q6 memory as boot IMEM and leaves the Q6 boot clock on GPLL0:
 * one LPASS restart with the Q6 in alternate reset is needed before it boots
 */
static void lpass_boot_reset(vaddr_t gcc, vaddr_t lpass, vaddr_t aoss)
{
	static bool done;

	if (done)
		return;

	io_clrbits32(gcc + GCC_LPASS_Q6SS_BOOT_GPLL0_MUXR, Q6SS_BOOT_GPLL0);
	io_write32(lpass + LPASS_ALT_RESET_Q6SS, Q6SS_ALT_RESET_ARES);
	udelay(50);
	io_write32(aoss + AOSS_CC_LPASS_RESTART, AOSS_CC_RESTART_ASSERT);
	udelay(500);
	io_write32(aoss + AOSS_CC_LPASS_RESTART, 0);
	udelay(500);
	io_write32(lpass + LPASS_ALT_RESET_Q6SS, 0);
	udelay(50);

	done = true;
}

/* The LPASS path to DDR the Q6 fetches its image over */
static void lpass_bus_on(vaddr_t gcc)
{
	static const uint32_t gcc_cbcr[] = {
		GCC_LPASS_AUDIO_QTB_CBCR, GCC_LPASS_QTB_AHB_CBCR,
		GCC_QMIP_LPASS_QTB_AHB_CBCR, GCC_DDRSS_LPASS_SHUB_CBCR,
		GCC_LPASS_AON_NOC_DDRSS_SHUB_CBCR,
		GCC_LPASS_AGGRE_NOC_DDRSS_SHUB_CBCR,
		GCC_LPASS_AGGRE_NOC_DDRSS_SHUB_LPASSCH_PIPE_CBCR,
		GCC_LPASS_AGGRE_NOC_MPU_CLIENT_DDRSS_SHUB_CBCR,
		GCC_LPASS_HW_AF_NOC_DDRSS_SHUB_CBCR,
	};

	/* Hardware controlled: the QTB domain comes up on demand once voted */
	io_setbits32(gcc + GCC_HYP_VOTE_LPASS_QTB_CLK, CBCR_BRANCH_ENABLE_BIT);
	io_clrbits32(gcc + GCC_HYP_VOTE_LPASS_QTB_GDS, GDSCR_SW_COLLAPSE);

	/* Enable only: these run once the LPASS interconnect vote is in */
	for (size_t i = 0; i < ARRAY_SIZE(gcc_cbcr); i++)
		io_setbits32(gcc + gcc_cbcr[i], CBCR_BRANCH_ENABLE_BIT);
}

static TEE_Result lpass_setup(void)
{
	vaddr_t gcc = map(GCC_BASE, GCC_SIZE);
	vaddr_t lpass = map(LPASS_BASE, LPASS_SIZE);
	vaddr_t aoss = map(AOSS_CC_RESTART_BASE, AOSS_CC_RESTART_SIZE);
	vaddr_t cc = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc || !lpass || !aoss)
		return TEE_ERROR_GENERIC;
	cc = lpass + LPASS_QDSP6SS_CC;

	res = qcom_clock_enable_cbc(gcc + GCC_CFG_NOC_LPASS_CBCR);
	if (res)
		return res;

	lpass_boot_reset(gcc, lpass, aoss);
	lpass_bus_on(gcc);

	/* The LPI NoC clock is either RCG-gated or needs its branch on. */
	if (io_read32(lpass + LPASS_LPI_NOC_HS_CLK_ENABLE_LOW) &
	    LPI_NOC_HS_CLK_RCG_GATED) {
		io_clrbits32(lpass + LPASS_AON_LPI_NOC_HS_CBCR,
			     CBCR_BRANCH_ENABLE_BIT);
	} else {
		res = qcom_clock_enable_cbc(lpass + LPASS_AON_LPI_NOC_HS_CBCR);
		if (res)
			return res;
	}

	res = qcom_clock_enable_cbc(lpass + LPASS_AON_Q6_AXIM_CBCR);
	if (res)
		return res;

	io_setbits32(cc + LPASS_QDSP6SS_CORE_CBCR, CBCR_BRANCH_ENABLE_BIT);
	io_write32(lpass + LPASS_QDSP6SS + QDSP6SS_DBG_CFG, 0);
	io_write32(lpass + LPASS_RSC_WAIT_EVENT_OVRD_MASK,
		   LPASS_RSC_WAIT_EVENT_OVRD);

	/* The ADSP QDSP6 runs from its Q6 PLL from the first instruction */
	return q6_clock_enable(lpass + LPASS_QDSP6SS_PLL,
			       cc + LPASS_QDSP6SS_CORE_CMD_RCGR,
			       cc + LPASS_QDSP6SS_CORE_CFG_RCGR);
}

/* QDSP6SS clocks a CDSP shutdown stops, relative to TURING_QDSP6SS_CC */
static const uint32_t turing_stop_cbcr[] = {
	TURING_QDSP6SS_CORE_CBCR, TURING_QDSP6SS_SLPGEN_CBCR,
	TURING_QDSP6SS_L2MEM_SLPGEN_CBCR, TURING_QDSP6SS_L2ITCM_SLPGEN_CBCR,
	TURING_QDSP6SS_L2VTCM_SLPGEN_CBCR, TURING_QDSP6SS_MON_CBCR,
	TURING_QDSP6SS_ACD_SCAN_CBCR,
};

static TEE_Result turing_setup(void)
{
	vaddr_t gcc = map(GCC_BASE, GCC_SIZE);
	vaddr_t turing = map(TURING_BASE, TURING_SIZE);
	TEE_Result res = TEE_SUCCESS;

	if (!gcc || !turing)
		return TEE_ERROR_GENERIC;

	res = qcom_clock_enable_cbc(gcc + GCC_TURING_CFG_AHB_CBCR);
	if (res)
		return res;

	io_setbits32(turing + TURING_Q6SS_Q6_AXIM_CBCR, CBCR_HW_CTL_ENABLE_BIT);
	io_setbits32(turing + TURING_CENG_CBCR, CBCR_HW_CTL_ENABLE_BIT);
	io_setbits32(turing + TURING_NSPNOC_CBCR, CBCR_BRANCH_ENABLE_BIT);

	/* Undo a previous shutdown: clocks forced off, reset bypass */
	io_clrbits32(turing + TURING_Q6SS_AHBM_AON_CBCR, CBCR_CLK_DIS);
	io_clrbits32(turing + TURING_Q6SS_AHBS_AON_CBCR, CBCR_CLK_DIS);

	res = qcom_clock_enable_cbc(turing + TURING_Q6SS_ALT_RESET_AON_CBCR);
	if (res)
		return res;
	io_clrbits32(turing + TURING_Q6SS_ALT_RESET_CTL, ALT_ARES_BYPASS);
	io_clrbits32(turing + TURING_Q6SS_ALT_RESET_AON_CBCR,
		     CBCR_BRANCH_ENABLE_BIT);

	res = qcom_clock_enable_cbc(turing + TURING_Q6SS_AHBS_AON_CBCR);
	if (res)
		return res;

	/* The QDSP6SS clock controller sits behind the Q6 slave clock */
	for (size_t i = 0; i < ARRAY_SIZE(turing_stop_cbcr); i++)
		io_clrbits32(turing + TURING_QDSP6SS_CC + turing_stop_cbcr[i],
			     CBCR_CLK_DIS);
	io_write32(turing + TURING_QDSP6SS + QDSP6SS_DBG_CFG, 0);
	io_setbits32(turing + TURING_QDSP6SS_CC + TURING_QDSP6SS_CORE_CBCR,
		     CBCR_BRANCH_ENABLE_BIT);
	dsb();

	return TEE_SUCCESS;
}

/*
 * The NSP Q6 PLL is reachable only after the boot FSM; the core starts once
 * it is locked so that the firmware never reprograms it mid-setup
 */
static TEE_Result turing_start(void)
{
	vaddr_t turing = map(TURING_BASE, TURING_SIZE);
	TEE_Result res = TEE_SUCCESS;
	vaddr_t cc = 0;

	if (!turing)
		return TEE_ERROR_GENERIC;
	cc = turing + TURING_QDSP6SS_CC;

	res = q6_clock_enable(turing + TURING_QDSP6SS_PLL,
			      cc + TURING_QDSP6SS_CORE_CMD_RCGR,
			      cc + TURING_QDSP6SS_CORE_CFG_RCGR);
	if (res)
		return res;
	udelay(5);

	qcom_qdsp6ss_core_start(turing + TURING_QDSP6SS);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	if (group >= QCOM_CLKS_MAX)
		return res;
	/* The DTB stage sets the clocks up; the image stage finds them on. */
	if (setup_done[group])
		return TEE_SUCCESS;

	switch (group) {
	case QCOM_CLKS_LPASS:
		res = lpass_setup();
		break;
	case QCOM_CLKS_TURING:
		res = turing_setup();
		break;
	default:
		EMSG("Unsupported clock group %d", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (res)
		EMSG("Clock group %d setup failed: %#"PRIx32, group, res);
	else
		setup_done[group] = true;

	return res;
}

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group)
{
	if (group == QCOM_CLKS_TURING)
		return turing_start();

	return TEE_SUCCESS;
}

static bool gdscr_off(uint32_t val)
{
	return !(val & GDSCR_PWR_ON);
}

static bool gdscr_on(uint32_t val)
{
	return val & GDSCR_PWR_ON;
}

static bool pdc_hm_on(uint32_t val)
{
	return val & PDC_HM_GDS_PWR_ON;
}

static bool island_off(uint32_t val)
{
	return !(val & LPI_HM_IS_IN_ISLAND_MODE);
}

static bool bcr_reset_done(uint32_t val)
{
	return val & BCR_BLK_ARES_COMPLETE;
}

static bool halt_acked(uint32_t val)
{
	return val & TCSR_HALTACK_ACK;
}

static bool lpass_all_halted(uint32_t val)
{
	return (val & TCSR_LPASS_HALT_ALL) == TCSR_LPASS_HALT_ALL;
}

static bool lpicx_accepted(uint32_t val)
{
	return !(val & LPICX_QACCEPTN);
}

static bool cbcr_clk_off(uint32_t val)
{
	return val & CBCR_BRANCH_OFF_BIT;
}

static TEE_Result lpass_core_hm_collapse(vaddr_t lpass)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t cfg = 0;
	int ret = 0;

	if (!(io_read32(lpass + LPASS_CORE_HM_GDSCR) & GDSCR_PWR_ON))
		return TEE_SUCCESS;

	/* A pending debug vote would keep the core out of the reset */
	io_write32(lpass + LPASS_CORE_GDSCR_DEBUG_VOTE, 0);
	io_clrbits32(lpass + LPASS_CORE_HM_GDSCR, GDSCR_RETAIN_FF_ENABLE);

	cfg = io_read32(lpass + LPASS_CORE_CC_CORE_CFG_RCGR);
	cfg &= ~(RCGR_SRC_SEL_MASK | RCGR_SRC_DIV_MASK);
	res = qcom_clock_set_rate(lpass + LPASS_CORE_CC_CORE_CFG_RCGR,
				  lpass + LPASS_CORE_CC_CORE_CMD_RCGR, cfg);
	if (res)
		EMSG("LPASS core RCG did not switch to XO");
	io_clrbits32(lpass + LPASS_CORE_CC_DIG_PLL_OPMODE, PLL_OPMODE_MASK);

	io_setbits32(lpass + LPASS_CORE_HM_COLLAPSE_VOTE, HM_COLLAPSE_VOTE);
	io_setbits32(lpass + LPASS_CORE_HM_GDSCR, GDSCR_SW_COLLAPSE);
	REG_POLL_TIMEOUT(lpass + LPASS_CORE_HM_GDSCR, 10 * 1000, 5, &ret,
			 gdscr_off);
	if (ret) {
		EMSG("LPASS_CORE_HM did not collapse");
		if (!res)
			res = TEE_ERROR_TIMEOUT;
	}

	return res;
}

static TEE_Result lpass_audio_hm_reset(vaddr_t lpass)
{
	TEE_Result res = TEE_SUCCESS;
	int ret = 0;

	res = qcom_clock_enable_cbc(lpass + LPASS_AON_SLEEP_CBCR);
	if (res)
		return res;

	if (!(io_read32(lpass + LPASS_AUDIO_HM_GDSCR) & GDSCR_PWR_ON)) {
		io_clrbits32(lpass + LPASS_AUDIO_HM_GDSCR, GDSCR_SW_COLLAPSE);
		REG_POLL_TIMEOUT(lpass + LPASS_AUDIO_HM_GDSCR, 10 * 1000, 5,
				 &ret, gdscr_on);
		if (ret)
			return TEE_ERROR_TIMEOUT;
	}

	res = qcom_clock_enable_cbc(lpass + LPASS_AUDIO_HM_H_CBCR);
	if (res)
		return res;

	io_setbits32(lpass + LPASS_AUDIO_HM_BCR, BCR_BLK_ARES);
	REG_POLL_TIMEOUT(lpass + LPASS_AUDIO_HM_BCR, 200, 1, &ret,
			 bcr_reset_done);
	if (ret) {
		io_setbits32(lpass + LPASS_AUDIO_HM_BCR, BCR_Q_FORCE_RESET);
		udelay(150);
		io_clrbits32(lpass + LPASS_AUDIO_HM_BCR, BCR_Q_FORCE_RESET);
	}
	io_clrbits32(lpass + LPASS_AUDIO_HM_BCR, BCR_BLK_ARES);
	udelay(250);

	io_setbits32(lpass + LPASS_AUDIO_HM_GDSCR, GDSCR_SW_COLLAPSE);
	REG_POLL_TIMEOUT(lpass + LPASS_AUDIO_HM_GDSCR, 10 * 1000, 5, &ret,
			 gdscr_off);
	if (ret) {
		EMSG("LPASS_AUDIO_HM did not collapse");
		return TEE_ERROR_TIMEOUT;
	}

	return TEE_SUCCESS;
}

static TEE_Result lpass_reset(void)
{
	vaddr_t lpass = map(LPASS_BASE, LPASS_SIZE);
	vaddr_t tcsr = map(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t pdc = map(RPMH_PDC_AUDIO_BASE, RPMH_PDC_AUDIO_SIZE);
	vaddr_t link = map(LPASS_HOST_LINK_BASE, LPASS_HOST_LINK_SIZE);
	vaddr_t aoss = map(AOSS_CC_RESTART_BASE, AOSS_CC_RESTART_SIZE);
	TEE_Result res = TEE_SUCCESS;
	TEE_Result rc = TEE_SUCCESS;
	int ret = 0;

	if (!lpass || !tcsr || !pdc || !link || !aoss)
		return TEE_ERROR_GENERIC;

	/* The restart always runs, the Q6 must not keep running */
	res = lpass_core_hm_collapse(lpass);
	io_clrbits32(lpass + LPASS_CORE_GDSCR_DEBUG_VOTE, GDSCR_DEBUG_VOTE);
	io_clrbits32(lpass + LPASS_CORE_HM_GDSCR, GDSCR_RETAIN_FF_ENABLE);

	/* An LPI island has to be left before the audio module can reset */
	if (!island_off(io_read32(lpass + LPASS_LPI_HM_ISLAND_MODE_STATUS))) {
		io_setbits32(lpass + LPASS_PDC_HM_GDS_OVERRIDE_CTRL,
			     PDC_HM_GDS_SW_OVERRIDE);
		REG_POLL_TIMEOUT(lpass + LPASS_PDC_HM_GDS_OVERRIDE_CTRL, 500,
				 1, &ret, pdc_hm_on);
		REG_POLL_TIMEOUT(lpass + LPASS_LPI_HM_ISLAND_MODE_STATUS, 500,
				 1, &ret, island_off);
	}
	if (!island_off(io_read32(lpass + LPASS_LPI_HM_ISLAND_MODE_STATUS))) {
		EMSG("LPASS LPI island did not exit");
		rc = TEE_ERROR_TIMEOUT;
	} else {
		rc = lpass_audio_hm_reset(lpass);
		if (rc)
			EMSG("LPASS_AUDIO_HM reset failed: %#"PRIx32, rc);
	}
	if (!res)
		res = rc;

	io_write32(lpass + LPASS_QDSP6SS + QDSP6SS_RET_CFG,
		   QDSP6SS_RET_CFG_RET_ARES_ENA |
		   QDSP6SS_RET_CFG_NRET_ARES_ENA);
	io_setbits32(lpass + LPASS_ALT_RESET_Q6SS, Q6SS_ALT_RESET_ARES);

	io_write32(tcsr + TCSR_LPASS_HALTREQ, TCSR_LPASS_HALT_Q6);
	REG_POLL_TIMEOUT(tcsr + TCSR_LPASS_HALTACK, 1000 * 1000, 5, &ret,
			 halt_acked);
	if (ret) {
		EMSG("ADSP bus master halt not acknowledged");
		if (!res)
			res = TEE_ERROR_TIMEOUT;
	}
	/* Not a failure: the halt of all LPASS masters does not complete */
	io_write32(tcsr + TCSR_LPASS_HALTREQ, TCSR_LPASS_HALT_ALL);
	REG_POLL_TIMEOUT(tcsr + TCSR_LPASS_HALTACK, 500, 5, &ret,
			 lpass_all_halted);
	if (ret)
		DMSG("LPASS bus masters halt acknowledged %#"PRIx32,
		     io_read32(tcsr + TCSR_LPASS_HALTACK));

	io_write32(tcsr + TCSR_LPASS_LPICX_QREQN, 0);
	REG_POLL_TIMEOUT(tcsr + TCSR_LPASS_LPICX_QACCEPTN, 500, 5, &ret,
			 lpicx_accepted);
	if (ret &&
	    (io_read32(tcsr + TCSR_LPASS_LPICX_QACCEPTN) & LPICX_QDENY)) {
		io_write32(tcsr + TCSR_LPASS_LPICX_QREQN, LPICX_QREQN_RUN);
		udelay(10);
		io_write32(tcsr + TCSR_LPASS_LPICX_QREQN, 0);
		REG_POLL_TIMEOUT(tcsr + TCSR_LPASS_LPICX_QACCEPTN, 500, 5,
				 &ret, lpicx_accepted);
	}
	if (ret) {
		EMSG("LPASS LPICX NoC isolation not accepted");
		if (!res)
			res = TEE_ERROR_TIMEOUT;
	}

	io_setbits32(link, LPASS_SYNC_REQ_CHL_RSIDE);
	io_setbits32(pdc, PDC_SYNC_RESET);
	mdelay(10);
	io_write32(aoss + AOSS_CC_LPASS_RESTART, AOSS_CC_RESTART_ASSERT);
	udelay(200);
	io_setbits32(link, LPASS_SYNC_RSP_CHL_WSIDE);
	udelay(1);
	io_clrbits32(link, LPASS_SYNC_RSP_CHL_WSIDE);
	io_clrbits32(pdc, PDC_SYNC_RESET);

	io_write32(tcsr + TCSR_LPASS_HALTREQ, 0);
	io_write32(tcsr + TCSR_LPASS_LPICX_QREQN, LPICX_QREQN_RUN);
	io_write32(aoss + AOSS_CC_LPASS_RESTART, 0);
	udelay(200);
	io_clrbits32(link, LPASS_SYNC_REQ_CHL_RSIDE);
	io_clrbits32(lpass + LPASS_PDC_HM_GDS_OVERRIDE_CTRL,
		     PDC_HM_GDS_SW_OVERRIDE);
	udelay(100);

	return res;
}

static TEE_Result turing_reset(void)
{
	vaddr_t gcc = map(GCC_BASE, GCC_SIZE);
	vaddr_t turing = map(TURING_BASE, TURING_SIZE);
	vaddr_t tcsr = map(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t pdc = map(RPMH_PDC_COMPUTE_BASE, RPMH_PDC_COMPUTE_SIZE);
	vaddr_t aoss = map(AOSS_CC_RESTART_BASE, AOSS_CC_RESTART_SIZE);
	TEE_Result res = TEE_SUCCESS;
	vaddr_t cc = 0;
	int ret = 0;

	if (!gcc || !turing || !tcsr || !pdc || !aoss)
		return TEE_ERROR_GENERIC;
	cc = turing + TURING_QDSP6SS_CC;

	/* The restart always runs, the Q6 must not keep running */
	res = qcom_clock_enable_cbc(turing + TURING_Q6SS_ALT_RESET_AON_CBCR);
	if (res)
		EMSG("CDSP alternate reset clock did not start");
	io_setbits32(turing + TURING_Q6SS_ALT_RESET_CTL, ALT_ARES_BYPASS);
	io_setbits32(turing + TURING_QDSP6SS + QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA |
		     QDSP6SS_RET_CFG_NRET_ARES_ENA);

	io_clrbits32(gcc + GCC_TURING_CFG_AHB_CBCR, CBCR_BRANCH_ENABLE_BIT);

	/* Either master port busy means traffic may still be in flight */
	if ((io_read32(tcsr + TCSR_TURING_PWR_ON) & TCSR_PWR_ON_STATUS) &&
	    (!(io_read32(tcsr + TCSR_TURING_MASTER_IDLE) &
	       TCSR_MASTER_IDLE_STATUS) ||
	     !(io_read32(tcsr + TCSR_TURING_IL1_MASTER_IDLE) &
	       TCSR_MASTER_IDLE_STATUS))) {
		io_setbits32(tcsr + TCSR_TURING_HALTREQ, TCSR_HALTREQ_REQ);
		REG_POLL_TIMEOUT(tcsr + TCSR_TURING_HALTACK, 1000 * 1000, 5,
				 &ret, halt_acked);
		if (ret) {
			EMSG("CDSP bus master halt not acknowledged");
			if (!res)
				res = TEE_ERROR_TIMEOUT;
		}
	}

	io_setbits32(pdc, PDC_SYNC_RESET);

	/* Without its bus clocks the Turing window must not be touched */
	if (qcom_clock_enable_cbc(gcc + GCC_TURING_CFG_AHB_CBCR) ||
	    qcom_clock_enable_cbc(turing + TURING_WRAPPER_AON_CBCR) ||
	    qcom_clock_enable_cbc(turing + TURING_Q6SS_AHBS_AON_CBCR)) {
		EMSG("CDSP AHB clocks did not start");
		if (!res)
			res = TEE_ERROR_TIMEOUT;
		goto restart;
	}

	/* The restart must not reach flops that are still clocked */
	io_clrbits32(cc + TURING_QDSP6SS_CORE_CMD_RCGR, CMD_RCGR_ROOT_EN);
	for (size_t i = 0; i < ARRAY_SIZE(turing_stop_cbcr); i++)
		io_setbits32(cc + turing_stop_cbcr[i], CBCR_CLK_DIS);
	io_mask32(cc + TURING_QDSP6SS_DEBUG_MUX_MUXR, DEBUG_MUX_SEL_MASK,
		  DEBUG_MUX_SEL_MASK);
	io_write32(turing + TURING_QDSP6SS_ACD_GFMUX_CFG, 0);
	io_setbits32(turing + TURING_Q6SS_AHBM_AON_CBCR, CBCR_CLK_DIS);
	io_setbits32(turing + TURING_Q6SS_AHBS_AON_CBCR, CBCR_CLK_DIS);
	REG_POLL_TIMEOUT(turing + TURING_Q6SS_AHBM_AON_CBCR, 10 * 1000, 10,
			 &ret, cbcr_clk_off);
	if (!ret)
		REG_POLL_TIMEOUT(turing + TURING_Q6SS_AHBS_AON_CBCR, 10 * 1000,
				 10, &ret, cbcr_clk_off);
	if (ret) {
		EMSG("CDSP AHB clocks did not stop");
		if (!res)
			res = TEE_ERROR_TIMEOUT;
	}

restart:
	io_write32(aoss + AOSS_CC_COMPUTESS_RESTART, AOSS_CC_RESTART_ASSERT);
	udelay(200);
	io_clrbits32(tcsr + TCSR_TURING_HALTREQ, TCSR_HALTREQ_REQ);
	mdelay(10);
	io_clrbits32(pdc, PDC_SYNC_RESET);
	io_write32(aoss + AOSS_CC_COMPUTESS_RESTART, 0);
	dsb();
	udelay(200);

	return res;
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group)
{
	TEE_Result res = TEE_SUCCESS;

	if (group >= QCOM_CLKS_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (group == QCOM_CLKS_TURING)
		res = turing_reset();
	else if (group == QCOM_CLKS_LPASS)
		res = lpass_reset();

	setup_done[group] = false;

	return res;
}
