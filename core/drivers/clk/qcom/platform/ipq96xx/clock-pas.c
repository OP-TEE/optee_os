// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "clock_group.h"

static TEE_Result cdsp_gcc_clk_enable(vaddr_t gcc_base)
{
	static const uint32_t cbcr_offsets[] = {
		GCC_Q6SS_TSCTR_1TO2_CLK_CBCR,
		GCC_TURING_EPCB_RX_CLK_CBCR,
		GCC_TURING_Q6_AXIM_DIV_CLK_CBCR,
		GCC_TURING_PCLK_DBG_CLK_CBCR,
		GCC_TURING_Q6SS_TRIG_CLK_CBCR,
		GCC_TURING_CXO_CLK_CBCR,
		GCC_TURING_ATBM_AT_CLK_CBCR,
		GCC_TURING_AHBS_CLK_CBCR,
		GCC_TURING_GEMNOC_CLK_CBCR,
		GCC_CNOC_TURING_AHBS_CLK_CBCR,
	};
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(cbcr_offsets); i++) {
		res = qcom_clock_enable_cbc(gcc_base + cbcr_offsets[i]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result cdsp_cc_enable(vaddr_t cc_base, vaddr_t qdsp6ss_base)
{
	static const uint32_t cc_cbcr_offsets[] = {
		TURING_CC_Q6SS_AHBS_AON_CBCR,
		TURING_CC_CENG_CDSP_AO_CBCR,
		TURING_CC_CENG_AHBS_CBCR,
		TURING_CC_CDSPNOC_AHBS_CBCR,
		TURING_CC_CDSPAUX_XO_CBCR,
		TURING_CC_Q6SS_AHBS_AON_MXC_CBCR,
		TURING_CC_XO_DIV_CBCR,
		TURING_CC_CDSPNOC_APB_CBCR,
		TURING_CC_Q6SS_AHBM_AON_CBCR,
		TURING_CC_ALT_RESET_AON_CBCR,
		TURING_CC_DEBUG_CBCR,
		TURING_CC_PLL_TEST_CBCR,
	};
	static const uint32_t qdsp6ss_cbcr_offsets[] = {
		QDSP6SS_CORE_CBCR,
		QDSP6SS_SLPGEN_CBCR,
		QDSP6SS_L2MEM_SLPGEN_CBCR,
		QDSP6SS_L2VTCM_SLPGEN_CBCR,
		QDSP6SS_MON_CBCR,
	};
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	io_setbits32(cc_base + TURING_CC_Q6SS_Q6_AXIM_CBCR,
		     CBCR_BRANCH_ENABLE_BIT | CBCR_HW_CTL_ENABLE_BIT);
	io_setbits32(cc_base + TURING_CC_CENG_CDSP_CBCR,
		     CBCR_BRANCH_ENABLE_BIT | CBCR_HW_CTL_ENABLE_BIT);

	io_setbits32(cc_base + TURING_CC_CENG_PROC_CBCR,
		     CBCR_BRANCH_ENABLE_BIT | CBCR_HW_CTL_ENABLE_BIT |
		     (CLK_SLEEP_CYCLES << CLK_SLEEP_SHIFT) |
		     (CLK_WAKEUP_CYCLES << CLK_WAKEUP_SHIFT));
	io_setbits32(cc_base + TURING_CC_CDSPNOC_CBCR,
		     CBCR_BRANCH_ENABLE_BIT | CBCR_HW_CTL_ENABLE_BIT |
		     (CLK_SLEEP_CYCLES << CLK_SLEEP_SHIFT) |
		     (CLK_WAKEUP_CYCLES << CLK_WAKEUP_SHIFT));

	for (i = 0; i < ARRAY_SIZE(cc_cbcr_offsets); i++) {
		res = qcom_clock_enable_cbc(cc_base + cc_cbcr_offsets[i]);
		if (res)
			return res;
	}

	for (i = 0; i < ARRAY_SIZE(qdsp6ss_cbcr_offsets); i++)
		io_setbits32(qdsp6ss_base + qdsp6ss_cbcr_offsets[i],
			     CBCR_BRANCH_ENABLE_BIT | CBCR_HW_CTL_ENABLE_BIT);

	res = qcom_clock_enable_cbc(qdsp6ss_base + QDSP6SS_DEBUG_CBCR);
	if (res)
		return res;

	io_write32(cc_base + CDSPAUX_BUS_BRIDGE_HALT,
		   CDSPAUX_BRIDGE_DELAY_CYCLES);

	return TEE_SUCCESS;
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
	TEE_Result res = TEE_SUCCESS;

	if (group != QCOM_CLKS_TURING) {
		EMSG("Unsupported clock group %d", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	gcc_base = io_pa_or_va(&gcc, GCC_SIZE);
	turing_base = io_pa_or_va(&turing, TURING_SIZE);
	if (!gcc_base || !turing_base)
		return TEE_ERROR_GENERIC;

	res = cdsp_gcc_clk_enable(gcc_base);
	if (res)
		goto timeout;

	res = cdsp_cc_enable(turing_base + TURING_CC_OFFSET,
			     turing_base + TURING_QDSP6SS_OFFSET);
	if (res)
		goto timeout;

	return TEE_SUCCESS;
timeout:
	EMSG("Timeout trying to enable clock group %d", group);
	return TEE_ERROR_TIMEOUT;
}
