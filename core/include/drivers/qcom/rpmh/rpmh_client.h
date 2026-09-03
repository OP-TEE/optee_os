/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMH_CLIENT_H__
#define __RPMH_CLIENT_H__

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

enum rpmh_set {
	RPMH_SET_ACTIVE = 0,
	RPMH_SET_SLEEP = 1,
	RPMH_SET_WAKE = 2,
	RPMH_NUM_SETS = 3,
};

enum rsc_drv_id {
	RSC_DRV_SECURE = 0,
};

struct rpmh_command {
	uint32_t address;
	uint32_t data;
	bool completion;
};

struct rpmh_client;

/* Create RPMH client handle */
struct rpmh_client *rpmh_create_handle(enum rsc_drv_id drv_id,
				       const char *name);

/* Issue command to RPMH resource */
TEE_Result rpmh_send_command(struct rpmh_client *handle,
			     enum rpmh_set set,
			     bool completion, uint32_t address,
			     uint32_t data, uint32_t *req_id);

#endif /* __RPMH_CLIENT_H__ */
