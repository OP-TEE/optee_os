/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMH_TARGET_H__
#define __RPMH_TARGET_H__

#include <util.h>

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
#define ADDR_SLV_ID_MASK		0x7
#define ADDR_OFFSET_SHIFT		0x0
#define ADDR_OFFSET_MASK		0xFFFF

#endif /* __RPMH_TARGET_H__ */
