// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <stddef.h>
#include <util.h>

#include "lmcu.h"
#include "cdsp.h"
#include "pas_subsys.h"

static struct qcom_pas_subsys subsystems[] = {
	{
		.data = {
			.pas_id = DTB_ID_LMCU,
			.clk_group = QCOM_CLKS_LMCU,
		},
		.ops = &lmcu_dtb_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_ENABLE,
	},
	{
		.data = {
			.pas_id = PAS_ID_LMCU,
			.base.pa = MCU_MCU_CNOC_MASTER_BASE,
			.size = MCU_MCU_CNOC_MASTER_SIZE,
			.clk_group = QCOM_CLKS_LMCU,
			.map_type = MEM_AREA_IO_NSEC
		},
		.ops = &lmcu_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
	{
		.data = {
			.pas_id = PAS_ID_TURING,
			.base.pa = TURING_BASE,
			.size = TURING_SIZE,
			.clk_group = QCOM_CLKS_TURING,
			.map_type = MEM_AREA_IO_NSEC
		},
		.ops = &cdsp_ops,
		.reset_seq = QCOM_PAS_RESET_CLK_FULL,
	},
};

struct qcom_pas_subsys *qcom_pas_platform_subsys(size_t *count)
{
	*count = ARRAY_SIZE(subsystems);

	return subsystems;
}
