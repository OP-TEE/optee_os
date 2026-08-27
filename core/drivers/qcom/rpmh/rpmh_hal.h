/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMH_HAL_H__
#define __RPMH_HAL_H__

#include <rpmh_target.h>
#include <stdbool.h>
#include <stdint.h>
#include <util.h>

enum hal_status {
	HAL_STATUS_SUCCESS = 0,
	HAL_STATUS_ERROR = 1,
	HAL_STATUS_INVALID_PARAM = 2,
};

enum hal_status hal_rpmh_init(vaddr_t rsc_base);
enum hal_status hal_rpmh_is_tcs_idle(uint32_t tcs_id, bool *idle);
enum hal_status hal_rpmh_enable_amc_status(uint32_t tcs_id);
enum hal_status hal_rpmh_clear_amc_status(uint32_t tcs_id);
enum hal_status hal_rpmh_get_amc_status(uint32_t tcs_id, bool *finished);
enum hal_status hal_rpmh_send_tcs(uint32_t tcs_id, uint32_t enable_mask,
				  uint32_t wait_mask);
enum hal_status hal_rpmh_write_cmd(uint32_t tcs_id, uint32_t cmd_idx,
				   uint32_t addr, uint32_t data,
				   bool completion);

#endif /* __RPMH_HAL_H__ */
