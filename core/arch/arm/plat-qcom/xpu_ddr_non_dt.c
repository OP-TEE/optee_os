// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/xpuv4.h>
#include <platform_config.h>
#include <qcom_common.h>
#include <util.h>

/* The DRAM, from the target's macros: two windows */
static const struct xpu4_guard ddr_guards[] = {
	{
		.start = DRAM0_BASE,
		.size = DRAM0_SIZE,
	},
	{
		.start = DRAM1_BASE,
		.size = DRAM1_SIZE,
	},
};

TEE_Result qcom_xpu_get_ddr_guards(const struct xpu4_guard **guards,
				   size_t *count)
{
	*guards = ddr_guards;
	*count = ARRAY_SIZE(ddr_guards);

	return TEE_SUCCESS;
}
