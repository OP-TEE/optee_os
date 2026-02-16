// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Ltd
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <malloc.h>
#include <stdint.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <trace.h>
#include <platform_config.h>

#include "clock_group_qcom.h"

/* CBCR register fields */
#define CBCR_BRANCH_ENABLE_BIT		BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT		BIT(1)
#define CBCR_BRANCH_OFF_BIT		BIT(31)

register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, GCC_SIZE);

#define REG_POLL_TIMEOUT(_addr, _timeout_us, _delay_us, _retp, _match)	\
	do {								\
		uint32_t __val;						\
		int __rc;						\
									\
		__rc = IO_READ32_POLL_TIMEOUT(_addr, __val,		\
					     (_match)(__val),		\
					     _delay_us, _timeout_us);	\
		*(_retp) = __rc ? -1 : 0;				\
	} while (0)

static inline bool cbcr_branch_on(uint32_t val)
{
	return !(val & CBCR_BRANCH_OFF_BIT);
}

/* Enable clock controlled by CBC soft macro */
static int clk_enable_cbc(vaddr_t cbcr)
{
	int ret = 0;

	io_setbits32(cbcr, CBCR_BRANCH_ENABLE_BIT);

	REG_POLL_TIMEOUT(cbcr, 10 * 1000, 10, &ret, cbcr_branch_on);

	return ret;
}

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

	res = clk_enable_cbc(cc_base + TURING_Q6SS_AHBS_AON_CLK);
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

TEE_Result qcom_clock_enable(enum qcom_clk_group group)
{
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, GCC_SIZE);
	int res = 0;

	switch (group) {
	case QCOM_CLKS_WPSS:
		res = clk_enable_cbc(gcc_base + GCC_WPSS_AHB_CLK);
		if (res)
			goto timeout;
		res = clk_enable_cbc(gcc_base + GCC_WPSS_AHB_BDG_MST_CLK);
		if (res)
			goto timeout;
		res = clk_enable_cbc(gcc_base + GCC_WPSS_RSCP_CLK);
		if (res)
			goto timeout;
		break;
	case QCOM_CLKS_TURING:
		res = clk_enable_cbc(gcc_base + GCC_TURING_CFG_AHB_CLK);
		if (res)
			goto timeout;
		res = compute_cc_enable();
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
