/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __RPMI_H
#define __RPMI_H

#ifndef __ASSEMBLER__

#include <compiler.h>
#include <stdint.h>

/* RPMI error codes */
enum rpmi_error_codes {
	RPMI_SUCCESS			= 0,
	RPMI_ERR_FAILED			= -1,
	RPMI_ERR_NOTSUPP		= -2,
	RPMI_ERR_INVALID_PARAM		= -3,
	RPMI_ERR_DENIED			= -4,
	RPMI_ERR_INVALID_ADDR		= -5,
	RPMI_ERR_ALREADY		= -6,
	RPMI_ERR_EXTENSION		= -7,
	RPMI_ERR_HW_FAULT		= -8,
	RPMI_ERR_BUSY			= -9,
	RPMI_ERR_INVALID_STATE		= -10,
	RPMI_ERR_BAD_RANGE		= -11,
	RPMI_ERR_TIMEOUT		= -12,
	RPMI_ERR_IO			= -13,
	RPMI_ERR_NO_DATA		= -14,
	RPMI_ERR_RESERVED_START		= -15,
	RPMI_ERR_RESERVED_END		= -127,
	RPMI_ERR_VENDOR_START		= -128,
};

/* RPMI message header */
struct rpmi_message_header {
	/* Service group ID */
	uint16_t servicegroup_id;
	/* Service ID */
	uint8_t service_id;
	/* Message flags */
	uint8_t flags;
	/* Message data length */
	uint16_t datalen;
	/* Message token */
	uint16_t token;
} __packed;

/* RPMI message */
struct rpmi_message {
	/* Message header */
	struct rpmi_message_header header;
	/* Message data */
	uint8_t data[];
} __packed;

/* RPMI notification event */
struct rpmi_notification_event {
	/*  Event data size in bytes */
	uint16_t event_datalen;
	/* Unique identifier for an event in a service group */
	uint8_t event_id;
	/* Reserved  */
	uint8_t reserved;
	/* Event data */
	uint8_t event_data[];
};

/* RPMI Messages Types */
enum rpmi_message_type {
	/* Normal request backed with ack */
	RPMI_MSG_NORMAL_REQUEST = 0x0,
	/* Request without any ack */
	RPMI_MSG_POSTED_REQUEST = 0x1,
	/* Acknowledgment for normal request message */
	RPMI_MSG_ACKNOWLEDGEMENT = 0x2,
	/* Notification message */
	RPMI_MSG_NOTIFICATION = 0x3,
};

/* RPMI ServiceGroups IDs */
enum rpmi_servicegroup_id {
	RPMI_SRVGRP_ID_MIN = 0,
	RPMI_SRVGRP_BASE = 0x0001,
	RPMI_SRVGRP_SYSTEM_MSI = 0x0002,
	RPMI_SRVGRP_SYSTEM_RESET = 0x0003,
	RPMI_SRVGRP_SYSTEM_SUSPEND = 0x0004,
	RPMI_SRVGRP_HSM = 0x0005,
	RPMI_SRVGRP_CPPC = 0x0006,
	RPMI_SRVGRP_VOLTAGE = 0x0007,
	RPMI_SRVGRP_CLOCK = 0x0008,
	RPMI_SRVGRP_DEVICE_POWER = 0x0009,
	RPMI_SRVGRP_PERFORMANCE = 0x000A,
	RPMI_SRVGRP_MANAGEMENT_MODE = 0x000B,
	RPMI_SRVGRP_RAS_AGENT = 0x000C,
	RPMI_SRVGRP_REQUEST_FORWARD = 0x000D,
	RPMI_SRVGRP_ID_MAX_COUNT,

	/* Reserved range for service groups */
	RPMI_SRVGRP_RESERVED_START = RPMI_SRVGRP_ID_MAX_COUNT,
	RPMI_SRVGRP_RESERVED_END = 0x7BFF,

	/* Experimental service groups range */
	RPMI_SRVGRP_EXPERIMENTAL_START = 0x7C00,
	RPMI_SRVGRP_EXPERIMENTAL_END = 0x7FFF,

	/* Vendor/Implementation-specific service groups range */
	RPMI_SRVGRP_VENDOR_START = 0x8000,
	RPMI_SRVGRP_VENDOR_END = 0xFFFF,
};

#endif /*__ASSEMBLER__*/
#endif /*__RPMI_H*/
