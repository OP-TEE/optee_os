// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Ltd
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <libfdt.h>
#include <malloc.h>
#include <stdint.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <trace.h>
#include <platform_config.h>

/* CBCR register fields */
#define CBCR_BRANCH_ENABLE_BIT  BIT(0)
#define CBCR_BRANCH_OFF_BIT     BIT(31)

/* Enable clock controlled by CBC soft macro */
static TEE_Result clk_enable_cbc(paddr_t cbcr)
{
	uint64_t timer;

	io_write32(cbcr, CBCR_BRANCH_ENABLE_BIT);

	timer = timeout_init_us(10000 * 1000);
	do {
		if (!(io_read32(cbcr) & CBCR_BRANCH_OFF_BIT))
			return TEE_SUCCESS;
		if (timeout_elapsed(timer))
			return TEE_ERROR_TIMEOUT;
		udelay(10);
	} while (1);
}

/* SC7280 clock offsets */
#define GCC_WPSS_AHB_CLK 0x9d154
#define GCC_WPSS_AHB_BDG_MST_CLK 0x9d158
#define GCC_WPSS_RSCP_CLK 0x9d16c

TEE_Result qcom_clock_enable(enum qcom_clk_group group)
{
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, 0x100000);
	TEE_Result res;

	switch (group) {
	case QCOM_CLKS_WPSS:
		res = clk_enable_cbc(gcc_base + GCC_WPSS_AHB_CLK);
		if (res)
			return res;
		res = clk_enable_cbc(gcc_base + GCC_WPSS_AHB_BDG_MST_CLK);
		if (res)
			return res;
		res = clk_enable_cbc(gcc_base + GCC_WPSS_RSCP_CLK);
		if (res)
			return res;
		break;
	default:
		EMSG("Unsupported clock group %d\n", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}
