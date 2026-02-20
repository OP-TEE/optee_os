// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stddef.h>

#include "rpmh_drv_config.h"
#include "rpmh_target_config.h"

/*
 * Common RPMh driver configuration describing TCS layout and limits
 * (AMC/SLEEP/WAKE mapping, command capacity, driver IDs, wake latencies)
 */

static const struct tcs_config tcs_config_tz = {
	.amcs = RPMH_TCS_SLEEP - RPMH_TCS_AMC,
	.sleep_start = RPMH_TCS_SLEEP,
	.wake_start = RPMH_TCS_WAKE,
};

static const struct drv_config_data optee_config_data = {
	.drvs_count = 1,
	.init_clks_count = 0,
	.init_clks = NULL,
	.sleep_clks_count = 0,
	.sleep_clks = NULL,

	.drvs = (struct drv_config[]) {
		{
			.drv_id = RSC_DRV_SECURE,
			.hw_drv = RSC_DRV_SECURE,
			.wake_set_latency = 0x7080, /* 1.5ms in 19.2MHz */
			.tcs_offset = 0,
			.tcs = RPMH_TCS_MAX,
			.cmds = RPMH_MAX_CMDS_PER_TCS,
			.modes_count = 1,
			.modes = (const struct tcs_config *[]) {
				&tcs_config_tz,
			}
		}
	}
};

const struct drv_config_data *const g_drv_config_data = &optee_config_data;
