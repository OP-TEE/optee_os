// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Ltd
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>

#ifdef CFG_QCOM_PAS_PTA
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

static inline bool vapss_gdscr_pwr_on(uint32_t val)
{
	return val & VAPSS_GDSCR_PWR_ON_MASK;
}

static inline bool vapss_gdscr_pwr_off(uint32_t val)
{
	return !vapss_gdscr_pwr_on(val);
}

static inline bool vapss_cfg_gdscr_pwr_up_complete(uint32_t val)
{
	return val & VAPSS_CFG_GDSCR_PWR_UP_COMPLETE_MASK;
}

static inline bool vapss_gds_hw_state_idle(uint32_t val)
{
	uint32_t state = (val & VAPSS_GDS_HW_STATE_MASK) >>
		VAPSS_GDS_HW_STATE_SHIFT;

	return state == 0;
}

static inline bool vapss_gds_hw_state_powerup_wait(uint32_t val)
{
	uint32_t state = (val & VAPSS_GDS_HW_STATE_MASK) >>
		VAPSS_GDS_HW_STATE_SHIFT;

	/* ready to power up */
	return state == 0xA;
}

static int compute_cc_enable(void)
{
	struct io_pa_va turing_cc_io = { .pa = TURING_BASE + TURING_CC_OFFSET };
	vaddr_t cc_base = io_pa_or_va(&turing_cc_io, TURING_CC_SIZE);
	int res = 0;

	io_clrbits32(cc_base + TURING_Q6SS_Q6_AXIM_CLK, CBCR_BRANCH_ENABLE_BIT);
	io_setbits32(cc_base + TURING_Q6SS_Q6_AXIM_CLK, CBCR_HW_CTL_ENABLE_BIT);
	io_setbits32(cc_base + TURING_CENG_CLK, CBCR_HW_CTL_ENABLE_BIT);
	io_clrbits32(cc_base + TURING_NSPNOC_CLK, CBCR_HW_CTL_ENABLE_BIT);

	res = qcom_clock_enable_cbc(cc_base + TURING_Q6SS_AHBS_AON_CLK);
	if (res)
		return res;

	/* Retention flop initialization sequence */

	io_clrbits32(cc_base + TURING_VAPSS_GDSCR,
		     VAPSS_GDSCR_SW_COLLAPSE_MASK);

	REG_POLL_TIMEOUT(cc_base + TURING_VAPSS_GDSCR,
			 10 * 1000, 10, &res, vapss_gdscr_pwr_on);
	if (res)
		return res;

	REG_POLL_TIMEOUT(cc_base + TURING_VAPSS_CFG_GDSCR,
			 10 * 1000, 10, &res,
			 vapss_cfg_gdscr_pwr_up_complete);
	if (res)
		return res;

	REG_POLL_TIMEOUT(cc_base + TURING_VAPSS_GDS_HW_CTRL,
			 10 * 1000, 10, &res, vapss_gds_hw_state_idle);
	if (res)
		return res;

	io_setbits32(cc_base + TURING_VAPSS_GDSCR,
		     VAPSS_GDSCR_RETAIN_FF_ENABLE_MASK);

	io_setbits32(cc_base + TURING_VAPSS_GDSCR,
		     VAPSS_GDSCR_SW_COLLAPSE_MASK);

	REG_POLL_TIMEOUT(cc_base + TURING_VAPSS_GDSCR,
			 10 * 1000, 10, &res, vapss_gdscr_pwr_off);
	if (res)
		return res;

	REG_POLL_TIMEOUT(cc_base + TURING_VAPSS_GDS_HW_CTRL,
			 10 * 1000, 10, &res, vapss_gds_hw_state_powerup_wait);
	if (res)
		return res;

	return 0;
}

static int lpass_gdsc_enable(void)
{
	struct io_pa_va gdsc_io = { .pa = LPASS_BASE + LPASS_GDSC_OFFSET };
	vaddr_t gdsc_base = io_pa_or_va(&gdsc_io, LPASS_GDSC_SIZE);
	int res = 0;

	res = qcom_clock_enable_cbc(gdsc_base + TOP_CC_AGGNOC_MPU_LS_CLK);
	if (res)
		return res;

	return qcom_clock_enable_cbc(gdsc_base + TOP_CC_LPI_Q6_AXIM_HS_CLK);
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, GCC_SIZE);
	TEE_Result res = TEE_ERROR_GENERIC;

	switch (group) {
	case QCOM_CLKS_WPSS:
		res = qcom_clock_enable_cbc(gcc_base + GCC_WPSS_AHB_CLK);
		if (res)
			goto timeout;
		res = qcom_clock_enable_cbc(gcc_base +
					    GCC_WPSS_AHB_BDG_MST_CLK);
		if (res)
			goto timeout;
		res = qcom_clock_enable_cbc(gcc_base + GCC_WPSS_RSCP_CLK);
		if (res)
			goto timeout;
		break;
	case QCOM_CLKS_TURING:
		res = qcom_clock_enable_cbc(gcc_base + GCC_TURING_CFG_AHB_CLK);
		if (res)
			goto timeout;
		res = compute_cc_enable();
		if (res)
			goto timeout;
		break;
	case QCOM_CLKS_LPASS:
		res = qcom_clock_enable_cbc(gcc_base + GCC_CFG_NOC_LPASS_CLK);
		if (res)
			goto timeout;
		res = lpass_gdsc_enable();
		if (res)
			goto timeout;
		break;
	default:
		EMSG("Unsupported clock group %d\n", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
timeout:
	EMSG("Timeout trying to enable clock group %d\n", group);
	return TEE_ERROR_TIMEOUT;
}

#else
TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group __unused)
{
	return  TEE_ERROR_NOT_SUPPORTED;
}
#endif /* ! CFG_QCOM_PAS_PTA */
