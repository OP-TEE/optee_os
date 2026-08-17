// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <stddef.h>
#include <util.h>

#include "iris.h"
#include "pas_subsys.h"

static struct qcom_pas_subsys subsystems[] = {
	{
		.data = {
			.pas_id = PAS_ID_IRIS,
			.base.pa = IRIS_BASE,
			.size = IRIS_SIZE,
		},
		.ops = &iris_ops,
		.reset_seq = QCOM_PAS_RESET_NONE,
	},
};

struct qcom_pas_subsys *qcom_pas_platform_subsys(size_t *count)
{
	*count = ARRAY_SIZE(subsystems);

	return subsystems;
}
