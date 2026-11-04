// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <stddef.h>
#include <util.h>

#include "nspss.h"
#include "pas_subsys.h"

static struct qcom_pas_subsys subsystems[] = {
	{
		.data = {
			.pas_id = DTB_ID_TURING,
			.clk_group = QCOM_CLKS_TURING,
			.map_type = MEM_AREA_IO_NSEC,
		},
		.ops = &nspss0_dtb_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
	{
		.data = {
			.pas_id = PAS_ID_TURING,
			.base.pa = CDSP_0_BASE,
			.size = CDSP_0_SIZE,
			.clk_group = QCOM_CLKS_TURING,
			.map_type = MEM_AREA_IO_NSEC,
		},
		.ops = &nspss0_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
	{
		.data = {
			.pas_id = DTB_ID_TURING1,
			.clk_group = QCOM_CLKS_TURING1,
			.map_type = MEM_AREA_IO_NSEC,
		},
		.ops = &nspss1_dtb_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
	{
		.data = {
			.pas_id = PAS_ID_TURING1,
			.base.pa = CDSP_1_BASE,
			.size = CDSP_1_SIZE,
			.clk_group = QCOM_CLKS_TURING1,
			.map_type = MEM_AREA_IO_NSEC,
		},
		.ops = &nspss1_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
	{
		.data = {
			.pas_id = DTB_ID_TURING2,
			.clk_group = QCOM_CLKS_TURING2,
			.map_type = MEM_AREA_IO_NSEC,
		},
		.ops = &nspss2_dtb_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
	{
		.data = {
			.pas_id = PAS_ID_TURING2,
			.base.pa = CDSP_2_BASE,
			.size = CDSP_2_SIZE,
			.clk_group = QCOM_CLKS_TURING2,
			.map_type = MEM_AREA_IO_NSEC,
		},
		.ops = &nspss2_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
	{
		.data = {
			.pas_id = DTB_ID_TURING3,
			.clk_group = QCOM_CLKS_TURING3,
			.map_type = MEM_AREA_IO_NSEC,
		},
		.ops = &nspss3_dtb_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
	{
		.data = {
			.pas_id = PAS_ID_TURING3,
			.base.pa = CDSP_3_BASE,
			.size = CDSP_3_SIZE,
			.clk_group = QCOM_CLKS_TURING3,
			.map_type = MEM_AREA_IO_NSEC,
		},
		.ops = &nspss3_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
};

struct qcom_pas_subsys *qcom_pas_platform_subsys(size_t *count)
{
	*count = ARRAY_SIZE(subsystems);

	return subsystems;
}
