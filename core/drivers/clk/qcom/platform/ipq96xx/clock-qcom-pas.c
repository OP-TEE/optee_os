// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "clock_group_qcom.h"

static void cdsp_gcc_clk_enable(vaddr_t gcc_base)
{
	io_write32(gcc_base + GCC_Q6SS_TSCTR_1TO2_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_TURING_EPCB_RX_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_TURING_Q6_AXIM_DIV_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_TURING_PCLK_DBG_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_TURING_Q6SS_TRIG_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_TURING_CXO_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_TURING_ATBM_AT_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_TURING_AHBS_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_TURING_GEMNOC_CLK_CBCR, CBCR_CLK_ENABLE);
	io_write32(gcc_base + GCC_CNOC_TURING_AHBS_CLK_CBCR, CBCR_CLK_ENABLE);
}

static void cdsp_cc_enable(vaddr_t cc_base, vaddr_t qdsp6ss_base)
{
	io_write32(cc_base + TURING_CC_Q6SS_Q6_AXIM_CBCR, CLK_ENABLE_HW_CTL);
	io_write32(cc_base + TURING_CC_CENG_CDSP_CBCR, CLK_ENABLE_HW_CTL);

	io_write32(cc_base + TURING_CC_CENG_PROC_CBCR, CLK_ENABLE_WITH_TIMING);
	io_write32(cc_base + TURING_CC_CDSPNOC_CBCR, CLK_ENABLE_WITH_TIMING);

	io_write32(cc_base + TURING_CC_Q6SS_AHBS_AON_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_CENG_CDSP_AO_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_CENG_AHBS_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_CDSPNOC_AHBS_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_CDSPAUX_XO_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_Q6SS_AHBS_AON_MXC_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_XO_DIV_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_CDSPNOC_APB_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_Q6SS_AHBM_AON_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_ALT_RESET_AON_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_DEBUG_CBCR, CLK_ENABLE_BIT);
	io_write32(cc_base + TURING_CC_PLL_TEST_CBCR, CLK_ENABLE_BIT);

	io_write32(qdsp6ss_base + QDSP6SS_CORE_CBCR, CLK_ENABLE_HW_CTL);
	io_write32(qdsp6ss_base + QDSP6SS_SLPGEN_CBCR, CLK_ENABLE_HW_CTL);
	io_write32(qdsp6ss_base + QDSP6SS_L2MEM_SLPGEN_CBCR, CLK_ENABLE_HW_CTL);
	io_write32(qdsp6ss_base + QDSP6SS_L2VTCM_SLPGEN_CBCR,
		   CLK_ENABLE_HW_CTL);
	io_write32(qdsp6ss_base + QDSP6SS_MON_CBCR, CLK_ENABLE_HW_CTL);
	io_write32(qdsp6ss_base + QDSP6SS_DEBUG_CBCR, CLK_ENABLE_BIT);

	io_write32(cc_base + CDSPAUX_BUS_BRIDGE_HALT,
		   CDSPAUX_BRIDGE_DELAY_CYCLES);
}

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group __unused)
{
	/* The DSP core is released entirely within the PTA fw_start path. */
	return TEE_SUCCESS;
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group __unused)
{
	/* CDSP teardown is handled by the PTA fw_shutdown path. */
	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	struct io_pa_va gcc = { .pa = GCC_BASE };
	struct io_pa_va turing = { .pa = TURING_BASE };
	vaddr_t gcc_base = 0;
	vaddr_t turing_base = 0;

	if (group != QCOM_CLKS_TURING) {
		EMSG("Unsupported clock group %d", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	gcc_base = io_pa_or_va(&gcc, GCC_SIZE);
	turing_base = io_pa_or_va(&turing, TURING_SIZE);
	if (!gcc_base || !turing_base)
		return TEE_ERROR_GENERIC;

	cdsp_gcc_clk_enable(gcc_base);

	/* Let the GCC clocks stabilise. */
	mdelay(10);

	cdsp_cc_enable(turing_base + TURING_CC_OFFSET,
		       turing_base + TURING_QDSP6SS_OFFSET);

	return TEE_SUCCESS;
}
