/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CLK_QCOM_H_
#define _CLK_QCOM_H_

#include <drivers/clk.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

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

enum qcom_clk_group {
	QCOM_CLKS_WPSS,
	QCOM_CLKS_TURING,
	QCOM_CLKS_TURING1,
	QCOM_CLKS_LPASS,
	QCOM_CLKS_GPDSP0,
	QCOM_CLKS_GPDSP1,
	QCOM_CLKS_MAX,
};

#define CBCR_BRANCH_ENABLE_BIT		BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT		BIT(1)
#define CBCR_BRANCH_OFF_BIT		BIT(31)
#define CMD_RCGR_UPDATE_BIT		BIT(0)

static inline bool cbcr_branch_on(uint32_t val)
{
	return !(val & CBCR_BRANCH_OFF_BIT);
}

/* Register configuration for a Lucid-EVO PLL. */
struct qcom_lucidevo_pll_config {
	uint32_t l_val;
	uint32_t cal_l_val;
	uint32_t alpha_val;
	uint32_t pre_div;		/* div-1..div-8; 0 = div-1 */
	uint32_t config_ctl;
	uint32_t config_ctl_u;
	uint32_t config_ctl_u1;
	uint32_t user_ctl;
	uint32_t user_ctl_u;
	bool frac_mode_mn;		/* false = alpha (default for Q6) */
};

TEE_Result qcom_clock_enable(enum qcom_clk_group group);
TEE_Result qcom_clock_enable_cbc(vaddr_t cbcr);
TEE_Result qcom_clock_set_rate(vaddr_t cfg_rcgr, vaddr_t cmd_rcgr,
			       uint32_t cfg_value);

/* Configure, lock and enable a Lucid-EVO PLL at @pll_base; returns
 * TEE_ERROR_TIMEOUT if it fails to lock.
 */
TEE_Result qcom_lucidevo_pll_enable(vaddr_t pll_base,
				    const struct qcom_lucidevo_pll_config *cfg);

#if defined(CFG_QCOM_CLK_CFG)
/*
 * qcom has no secure DT, so a consumer acquires the clk by name instead
 * of clk_dt_get_by_name().
 */
TEE_Result qcom_clk_get_by_name(const char *name, struct clk **out);

/* Enable hardware DFS on a registered clk (no clk_ops equivalent). */
TEE_Result qcom_clk_enable_dfs(struct clk *clk);

/*
 * Copies out DFS-selectable rates for @clk paired with each row's DFS
 * index -- never hands out a pointer into this driver's own config table.
 */
TEE_Result qcom_clk_get_dfs_rates_array(struct clk *clk, size_t start_index,
					unsigned long *rates,
					uint8_t *dfs_indices, size_t *count);
#else
static inline TEE_Result qcom_clk_get_by_name(const char *name __unused,
					      struct clk **out __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result qcom_clk_enable_dfs(struct clk *clk __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
qcom_clk_get_dfs_rates_array(struct clk *clk __unused,
			     size_t start_index __unused,
			     unsigned long *rates __unused,
			     uint8_t *dfs_indices __unused,
			     size_t *count __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_QCOM_CLK_CFG */

#ifdef CFG_QCOM_PAS_PTA
TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group);
TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group);
TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group);
#else
static inline TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group
					       __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
qcom_clock_enable_pas_processor(enum qcom_clk_group group __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group
					      __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

#endif /* _CLK_QCOM_H_ */
