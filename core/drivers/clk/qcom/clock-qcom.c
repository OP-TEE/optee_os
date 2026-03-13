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
#define CBCR_BRANCH_ENABLE_BIT  BIT(0)
#define CBCR_BRANCH_OFF_BIT     BIT(31)

register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, GCC_SIZE);

/* Enable clock controlled by CBC soft macro */
static int clk_enable_cbc(paddr_t cbcr)
{
	uint64_t timer;

	io_write32(cbcr, CBCR_BRANCH_ENABLE_BIT);

	timer = timeout_init_us(10 * 1000);
	do {
		if (!(io_read32(cbcr) & CBCR_BRANCH_OFF_BIT))
			return 0;
		if (timeout_elapsed(timer))
			return -1;
		udelay(10);
	} while (1);
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
	default:
		EMSG("Unsupported clock group %d\n", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;

timeout:
	EMSG("Timeout trying to enable clock group %d\n", group);
	return TEE_ERROR_TIMEOUT;
}
