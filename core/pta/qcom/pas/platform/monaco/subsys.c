// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <stddef.h>
#include <util.h>

#include "cdsp0.h"
#include "gpdsp0.h"
#include "lpass.h"
#include "pas_subsys.h"

static struct qcom_pas_subsys subsystems[] = {
	{
		.data = {
			.pas_id = PAS_ID_TURING,
			.base.pa = TURING_0_BASE,
			.size = TURING_0_SIZE,
			.clk_group = QCOM_CLKS_TURING,
		},
		.ops = &cdsp0_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
	{
		.data = {
			.pas_id = PAS_ID_QDSP6,
			.base.pa = LPASS_BASE,
			.size = LPASS_SIZE,
			.clk_group = QCOM_CLKS_LPASS,
		},
		.ops = &lpass_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
	{
		.data = {
			.pas_id = PAS_ID_GPDSP0,
			.base.pa = TURING_GDSP_0_BASE,
			.size = TURING_GDSP_0_SIZE,
			.clk_group = QCOM_CLKS_GPDSP0,
		},
		.ops = &gpdsp0_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
};

struct qcom_pas_subsys *qcom_pas_platform_subsys(size_t *count)
{
	*count = ARRAY_SIZE(subsystems);

	return subsystems;
}
