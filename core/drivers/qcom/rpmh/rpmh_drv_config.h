/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMH_DRV_CONFIG_H__
#define __RPMH_DRV_CONFIG_H__

#include <drivers/qcom/rpmh/rpmh_client.h>
#include <stdint.h>

/* RPMH DRV Configuration */

struct tcs_config {
	uint32_t amcs;          /* Number of AMCs (active TCS) */
	uint32_t sleep_start;   /* Index where sleep TCS start */
	uint32_t wake_start;    /* Index where wake TCS start */
};

struct drv_config {
	enum rsc_drv_id drv_id;
	enum rsc_drv_id hw_drv;
	uint32_t wake_set_latency;
	uint32_t tcs_offset;
	uint32_t tcs;
	uint32_t cmds;
	uint32_t modes_count;
	const struct tcs_config **modes;
};

struct drv_config_data {
	uint32_t drvs_count;
	uint32_t init_clks_count;
	char **init_clks;
	uint32_t sleep_clks_count;
	char **sleep_clks;
	struct drv_config *drvs;
};

extern const struct drv_config_data *const g_drv_config_data;

#endif /* __RPMH_DRV_CONFIG_H__ */
