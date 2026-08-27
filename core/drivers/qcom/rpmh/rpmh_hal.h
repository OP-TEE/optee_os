/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMH_HAL_H__
#define __RPMH_HAL_H__

#include <stdbool.h>
#include <stdint.h>
#include <util.h>

enum hal_status {
	HAL_STATUS_SUCCESS = 0,
	HAL_STATUS_ERROR = 1,
	HAL_STATUS_INVALID_PARAM = 2,
};

#define RSC_DRV_IRQ_ENABLE		0x0d00
#define RSC_DRV_IRQ_STATUS		0x0d04
#define RSC_DRV_IRQ_CLEAR		0x0d08

#define TCS_BASE_OFFSET			0x0D10
#define TCS_STRIDE			0x2A0

#define TCS_CMD_WAIT_FOR_CMPL_OFFSET	0x00
#define TCS_CONTROL_OFFSET		0x04
#define TCS_STATUS_OFFSET		0x08
#define TCS_CMD_ENABLE_OFFSET		0x0C

#define TCS_CMD_BASE_OFFSET		0x20
#define TCS_CMDn_MSGID_OFFSET		0x00
#define TCS_CMDn_ADDR_OFFSET		0x04
#define TCS_CMDn_DATA_OFFSET		0x08
#define TCS_CMD_STRIDE			0x14

#define TCS_CONTROL_AMC_MODE_TRIGGER	BIT(24)
#define TCS_CONTROL_AMC_MODE_EN	BIT(16)

#define TCS_STATUS_CONTROLLER_IDLE	BIT(0)

#define MSGID_READ_OR_WRITE_SHIFT	0x10
#define MSGID_RES_REQ_SHIFT		0x8
#define MSGID_MSG_LENGTH_SHIFT		0x0

#define ADDR_SLV_ID_SHIFT		0x10
#define ADDR_OFFSET_SHIFT		0x0

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
