// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Ltd
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <mm/core_mmu.h>
#include <trace.h>

register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, GCC_SIZE);

#define QCOM_CLOCK_UPDATE_TIMEOUT_US	U(10000)

#define CBCR_BRANCH_ENABLE_BIT		BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT		BIT(1)
#define CBCR_BRANCH_OFF_BIT		BIT(31)

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

TEE_Result qcom_clock_enable_cbc(vaddr_t cbcr)
{
	int ret = 0;

	io_setbits32(cbcr, CBCR_BRANCH_ENABLE_BIT);

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
	const struct qcom_lucidevo_pll_offsets *offsets = NULL;
	uint32_t user_val = 0;
	int ret = 0;

	if (!cfg || !cfg->offsets)
		return TEE_ERROR_BAD_PARAMETERS;

	offsets = cfg->offsets;

	io_write32(pll_base + offsets->config_ctl, cfg->config_ctl);
	io_write32(pll_base + offsets->config_ctl_u, cfg->config_ctl_u);
	io_write32(pll_base + offsets->config_ctl_u1, cfg->config_ctl_u1);
	io_write32(pll_base + offsets->user_ctl, cfg->user_ctl);
	io_write32(pll_base + offsets->user_ctl_u, cfg->user_ctl_u);

	io_mask32(pll_base + offsets->l_val, cfg->l_val, PLL_L_VAL_L_MASK);
	io_write32(pll_base + offsets->alpha_val, cfg->alpha_val);

	user_val = io_read32(pll_base + offsets->user_ctl);
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
	io_write32(pll_base + offsets->user_ctl, user_val);

	io_setbits32(pll_base + offsets->user_ctl_u,
		     PLL_USER_CTL_U_FINE_LOCK_DET);

	io_mask32(pll_base + offsets->l_val,
		  SHIFT_U32(cfg->cal_l_val, PLL_L_VAL_CAL_L_SHIFT),
		  PLL_L_VAL_CAL_L_MASK);

	io_write32(pll_base + offsets->opmode, PLL_OPMODE_RUN);
	io_setbits32(pll_base + offsets->mode, PLL_MODE_RESET_N);

	REG_POLL_TIMEOUT(pll_base + offsets->mode, 10 * 1000, 10, &ret,
			 pll_locked);
	if (ret < 0)
		return TEE_ERROR_TIMEOUT;

	io_setbits32(pll_base + offsets->mode, PLL_MODE_OUTCTRL);
	io_setbits32(pll_base + offsets->user_ctl,
		     PLL_USER_CTL_PLLOUT_MAIN_EN);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_set_rate(vaddr_t cfg_rcgr, vaddr_t cmd_rcgr,
			       uint32_t cfg_value)
{
	uint32_t val = 0;

	io_write32(cfg_rcgr, cfg_value);
	io_setbits32(cmd_rcgr, CMD_RCGR_UPDATE_BIT);

	if (IO_READ32_POLL_TIMEOUT(cmd_rcgr, val, !(val & CMD_RCGR_UPDATE_BIT),
				   1, QCOM_CLOCK_UPDATE_TIMEOUT_US))
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
		EMSG("Unsupported clock group %d", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
