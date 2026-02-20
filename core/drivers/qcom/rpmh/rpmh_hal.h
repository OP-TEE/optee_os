/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMH_HAL_H__
#define __RPMH_HAL_H__

#include <stdbool.h>
#include <stdint.h>
#include <util.h>
#include <drivers/qcom/rpmh/rpmh_client.h>

enum hal_status {
	HAL_STATUS_SUCCESS = 0,
	HAL_STATUS_ERROR = 1,
	HAL_STATUS_INVALID_PARAM = 2,
};

#define DRV_STRIDE			0x10000
#define RSC_DRV_IRQ_ENABLE		0x0d00
#define RSC_DRV_IRQ_STATUS		0x0d04
#define RSC_DRV_IRQ_CLEAR		0x0d08

#define RSC_DRV_TCS_CONFIG		0x0C
#define TCS_BASE_OFFSET			0x0D10  /* CMD_WAIT_FOR_CMPL base */
#define TCS_STRIDE			0x2A0

#define TCS_CONTROL_OFFSET		0x04
#define TCS_STATUS_OFFSET		0x08
#define TCS_CMD_ENABLE_OFFSET		0x0C

#define TCS_CMD_BASE_OFFSET		0x20
#define TCS_CMDn_MSGID_OFFSET		0x00
#define TCS_CMDn_ADDR_OFFSET		0x04
#define TCS_CMDn_DATA_OFFSET		0x08
#define TCS_CMD_STRIDE			0x14

#define TCS_CONTROL_AMC_MODE_TRIGGER	BIT(24)
#define TCS_CONTROL_AMC_MODE_EN		BIT(16)

#define TCS_STATUS_CONTROLLER_IDLE	BIT(0)

#define RSC_DRV_ERROR_IRQ_STATUS	0xD0
#define RSC_DRV_ERROR_IRQ_ENABLE	0xD8
#define RSC_DRV_ERROR_IRQ_CLEAR		0xD4

#define EPCB_TIMEOUT_IRQ_EN_MASK	BIT(20)
#define EPCB_TIMEOUT_THRESHOLD_SHIFT	0x0
#define EPCB_TIMEOUT_THRESHOLD_MASK	0xFFFF

#define MSGID_READ_OR_WRITE_SHIFT	0x10
#define MSGID_RES_REQ_SHIFT		0x8
#define MSGID_MSG_LENGTH_SHIFT		0x0

#define ADDR_SLV_ID_SHIFT		0x10
#define ADDR_OFFSET_SHIFT		0x0

enum hal_status hal_rpmh_init(vaddr_t rsc_base);
enum hal_status hal_rpmh_register_drv(enum rsc_drv_id drv_id);
enum hal_status hal_rpmh_read_config(enum rsc_drv_id drv_id,
				     uint32_t *tcs, uint32_t *cmds);
enum hal_status hal_rpmh_convert_to_amc(enum rsc_drv_id drv_id,
					uint32_t tcs_id);
enum hal_status hal_rpmh_convert_to_tcs(enum rsc_drv_id drv_id,
					uint32_t tcs_id);
enum hal_status hal_rpmh_enable_amc_status(enum rsc_drv_id drv_id,
					   uint32_t tcs_id);
enum hal_status hal_rpmh_clear_amc_status(enum rsc_drv_id drv_id,
					  uint32_t tcs_id);
enum hal_status hal_rpmh_is_tcs_idle(enum rsc_drv_id drv_id,
				     uint32_t tcs_id, bool *idle);
enum hal_status hal_rpmh_get_amc_status(enum rsc_drv_id drv_id,
					uint32_t tcs_id,
					bool *finished);
enum hal_status hal_rpmh_send_tcs(enum rsc_drv_id drv_id,
				  uint32_t tcs_id,
				  uint32_t enable_mask);
enum hal_status hal_rpmh_write_cmd(enum rsc_drv_id drv_id,
				   uint32_t tcs_id, uint32_t cmd_idx,
				   uint32_t addr, uint32_t data,
				   bool completion);
enum hal_status hal_rpmh_update_epcb_timeout(enum rsc_drv_id drv_id,
					     uint32_t threshold);
enum hal_status hal_rpmh_toggle_epcb_timeout(enum rsc_drv_id drv_id,
					     bool enable);

#endif /* __RPMH_HAL_H__ */
