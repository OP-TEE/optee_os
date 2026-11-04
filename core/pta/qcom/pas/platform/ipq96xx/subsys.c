// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <stddef.h>
#include <util.h>

#include "cdsp.h"
#include "cdsp_dtb.h"
#include "pas_subsys.h"

/* CDSP needs its DTB blob authenticated and loaded before it boots. */
static const uint32_t cdsp_deps[] = { PAS_ID_TURING_DTB, 0 };

static struct qcom_pas_subsys subsystems[] = {
	{
		.data = {
			.pas_id = PAS_ID_TURING_DTB,
		},
		.ops = &cdsp_dtb_ops,
		.reset_seq = QCOM_PAS_RESET_NONE,
	},
	{
		.data = {
			.pas_id = PAS_ID_TURING,
			.depends_on = cdsp_deps,
			.base.pa = TURING_BASE,
			.size = TURING_SIZE,
			.clk_group = QCOM_CLKS_TURING,
			.map_type = MEM_AREA_IO_SEC,
		},
		.ops = &cdsp_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
};

struct qcom_pas_subsys *qcom_pas_platform_subsys(size_t *count)
{
	*count = ARRAY_SIZE(subsystems);

	return subsystems;
}
