// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <stddef.h>
#include <util.h>

#include "cdsp.h"
#include "lpass.h"
#include "pas_subsys.h"
#include "venus.h"
#include "wpss.h"

static struct qcom_pas_subsys subsystems[] = {
	{
		.data = {
			.pas_id = PAS_ID_WPSS,
			.base.pa = WPSS_BASE,
			.size = WPSS_SIZE,
			.clk_group = QCOM_CLKS_WPSS,
		},
		.ops = &wpss_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
	{
		.data = {
			.pas_id = PAS_ID_TURING,
			.base.pa = TURING_BASE,
			.size = TURING_SIZE,
			.clk_group = QCOM_CLKS_TURING,
		},
		.ops = &cdsp_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
	{
		.data = {
			.pas_id = PAS_ID_QDSP6,
			.base.pa = LPASS_BASE,
			.size = LPASS_SIZE,
			.clk_group = QCOM_CLKS_LPASS,
		},
		.ops = &lpass_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
	{
		.data = {
			.pas_id = PAS_ID_VENUS,
			.base.pa = IRIS_BASE,
			.size = IRIS_SIZE,
		},
		.ops = &venus_ops,
		.reset_seq = QCOM_PAS_RESET_NONE,
	},
};

struct qcom_pas_subsys *qcom_pas_platform_subsys(size_t *count)
{
	*count = ARRAY_SIZE(subsystems);

	return subsystems;
}
