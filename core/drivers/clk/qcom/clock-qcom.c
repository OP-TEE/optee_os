// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Ltd
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <mm/core_mmu.h>

#define CBCR_BRANCH_ENABLE_BIT		BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT		BIT(1)
#define CBCR_BRANCH_OFF_BIT		BIT(31)

/* Lucid-EVO PLL register offsets, relative to the PLL register block base. */
#define PLL_MODE			0x0
#define PLL_OPMODE			0x4
#define PLL_L_VAL			0x10
#define PLL_ALPHA_VAL			0x14
#define PLL_USER_CTL			0x18
#define PLL_USER_CTL_U			0x1c
#define PLL_CONFIG_CTL			0x20
#define PLL_CONFIG_CTL_U		0x24
#define PLL_CONFIG_CTL_U1		0x28

/* PLL_MODE fields */
#define PLL_MODE_OUTCTRL		BIT(0)
#define PLL_MODE_RESET_N		BIT(2)
#define PLL_MODE_LOCK_DET		BIT(31)

/* PLL_OPMODE values */
#define PLL_OPMODE_RUN			0x1

/* PLL_L_VAL fields */
#define PLL_L_VAL_L_MASK		0x0000ffff
#define PLL_L_VAL_CAL_L_SHIFT		16
#define PLL_L_VAL_CAL_L_MASK		0xffff0000

/* PLL_USER_CTL fields */
#define PLL_USER_CTL_PLLOUT_MAIN_EN	BIT(0)
#define PLL_USER_CTL_PRE_DIV_SHIFT	22
#define PLL_USER_CTL_PRE_DIV_MASK	0x01c00000
#define PLL_USER_CTL_POST_DIV_ODD_MASK	0x0003c000
#define PLL_USER_CTL_POST_DIV_EVEN_MASK	0x00003c00
#define PLL_USER_CTL_FRAC_FORMAT_SEL	BIT(28)

/* PLL_USER_CTL_U fields */
#define PLL_USER_CTL_U_FINE_LOCK_DET	BIT(0)

static inline bool cbcr_branch_on(uint32_t val)
{
	return !(val & CBCR_BRANCH_OFF_BIT);
}

TEE_Result qcom_clock_enable_cbc(vaddr_t cbcr)
{
	int ret = 0;

	io_setbits32(cbcr, CBCR_BRANCH_ENABLE_BIT);

	/*
	 * When the branch is in hardware clock-control mode (HW_CTL set),
	 * CLK_OFF is driven by hardware and is not affected by the software
	 * CLK_ENABLE write, so polling it would spin until timeout. Skip the
	 * poll in that case, matching ENABLE_CBCR_AND_SPIN in the reference
	 * ClockPIL driver.
	 */
	if (io_read32(cbcr) & CBCR_HW_CTL_ENABLE_BIT)
		return TEE_SUCCESS;

	REG_POLL_TIMEOUT(cbcr, 10 * 1000, 10, &ret, cbcr_branch_on);

	if (ret < 0)
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

static inline bool pll_locked(uint32_t val)
{
	return val & PLL_MODE_LOCK_DET;
}

TEE_Result qcom_lucidevo_pll_enable(vaddr_t pll_base,
				    const struct qcom_lucidevo_pll_config *cfg)
{
	uint32_t user_val = 0;
	int ret = 0;

	/* Reg settings: program the static PLL trim/config registers. */
	io_write32(pll_base + PLL_CONFIG_CTL, cfg->config_ctl);
	io_write32(pll_base + PLL_CONFIG_CTL_U, cfg->config_ctl_u);
	io_write32(pll_base + PLL_CONFIG_CTL_U1, cfg->config_ctl_u1);
	io_write32(pll_base + PLL_USER_CTL, cfg->user_ctl);
	io_write32(pll_base + PLL_USER_CTL_U, cfg->user_ctl_u);

	/* ConfigPLL: program L value and fractional value. */
	io_mask32(pll_base + PLL_L_VAL, cfg->l_val, PLL_L_VAL_L_MASK);
	io_write32(pll_base + PLL_ALPHA_VAL, cfg->alpha_val);

	/* Select fractional format and program the pre-/post-div ratios. */
	user_val = io_read32(pll_base + PLL_USER_CTL);
	if (cfg->frac_mode_mn)
		user_val |= PLL_USER_CTL_FRAC_FORMAT_SEL;
	else
		user_val &= ~PLL_USER_CTL_FRAC_FORMAT_SEL;

	user_val &= ~(PLL_USER_CTL_PRE_DIV_MASK |
		      PLL_USER_CTL_POST_DIV_ODD_MASK |
		      PLL_USER_CTL_POST_DIV_EVEN_MASK);
	if (cfg->pre_div >= 1 && cfg->pre_div <= 8)
		user_val |= SHIFT_U32(cfg->pre_div - 1,
				      PLL_USER_CTL_PRE_DIV_SHIFT) &
			    PLL_USER_CTL_PRE_DIV_MASK;
	io_write32(pll_base + PLL_USER_CTL, user_val);

	/* Always use fine-grained lock detection. */
	io_setbits32(pll_base + PLL_USER_CTL_U, PLL_USER_CTL_U_FINE_LOCK_DET);

	/* SetCalConfig: program the calibration L value. */
	io_mask32(pll_base + PLL_L_VAL,
		  SHIFT_U32(cfg->cal_l_val, PLL_L_VAL_CAL_L_SHIFT),
		  PLL_L_VAL_CAL_L_MASK);

	/* Enable: select RUN opmode and take the PLL out of reset. */
	io_write32(pll_base + PLL_OPMODE, PLL_OPMODE_RUN);
	io_setbits32(pll_base + PLL_MODE, PLL_MODE_RESET_N);

	/* Wait for the PLL to lock. */
	REG_POLL_TIMEOUT(pll_base + PLL_MODE, 10 * 1000, 10, &ret, pll_locked);
	if (ret < 0)
		return TEE_ERROR_TIMEOUT;

	/* Enable PLL outputs and the main output. */
	io_setbits32(pll_base + PLL_MODE, PLL_MODE_OUTCTRL);
	io_setbits32(pll_base + PLL_USER_CTL, PLL_USER_CTL_PLLOUT_MAIN_EN);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_set_rate(vaddr_t cfg_rcgr, vaddr_t cmd_rcgr,
			       uint32_t cfg_value)
{
	uint32_t val = 0;

	io_write32(cfg_rcgr, cfg_value);
	io_write32(cmd_rcgr, CMD_RCGR_UPDATE_BIT);

	if (IO_READ32_POLL_TIMEOUT(cmd_rcgr, val, !(val & CMD_RCGR_UPDATE_BIT),
				   1, 10 * 1000))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
	case QCOM_CLKS_TURING1:
	case QCOM_CLKS_LPASS:
	case QCOM_CLKS_WPSS:
	case QCOM_CLKS_GPDSP0:
	case QCOM_CLKS_GPDSP1:
		return qcom_clock_enable_pas(group);
	default:
		EMSG("Unsupported clock group %d\n", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
