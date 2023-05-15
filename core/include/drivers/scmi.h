/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 */
#ifndef SCMI_MSG_SCMI_H
#define SCMI_MSG_SCMI_H

#define SCMI_PROTOCOL_ID_BASE			0x10
#define SCMI_PROTOCOL_ID_POWER_DOMAIN		0x11
#define SCMI_PROTOCOL_ID_SYS_POWER		0x12
#define SCMI_PROTOCOL_ID_PERF			0x13
#define SCMI_PROTOCOL_ID_CLOCK			0x14
#define SCMI_PROTOCOL_ID_SENSOR			0x15
#define SCMI_PROTOCOL_ID_RESET_DOMAIN		0x16
#define SCMI_PROTOCOL_ID_VOLTAGE_DOMAIN		0x17

/* SCMI error codes reported to agent through server-to-agent messages */
#define SCMI_SUCCESS			0
#define SCMI_NOT_SUPPORTED		(-1)
#define SCMI_INVALID_PARAMETERS		(-2)
#define SCMI_DENIED			(-3)
#define SCMI_NOT_FOUND			(-4)
#define SCMI_OUT_OF_RANGE		(-5)
#define SCMI_BUSY			(-6)
#define SCMI_COMMS_ERROR		(-7)
#define SCMI_GENERIC_ERROR		(-8)
#define SCMI_HARDWARE_ERROR		(-9)
#define SCMI_PROTOCOL_ERROR		(-10)

#endif /* SCMI_MSG_SCMI_H */
