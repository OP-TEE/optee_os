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

/*
 * struct rpmi_message_header - Header of an RPMI message
 * @servicegroup_id:  Identifier for the service group
 * @service_id:       Identifier for the service within the group
 * @flags:            Message flags (e.g., request/response indicators)
 * @datalen:          Length of the message data in bytes
 * @token:            Message token used for matching responses
 */
struct rpmi_message_header {
	uint16_t servicegroup_id;
	uint8_t service_id;
	uint8_t flags;
	uint16_t datalen;
	uint16_t token;
} __packed;

/*
 * struct rpmi_message - RPMI message including header and payload
 * @header:           RPMI message header
 * @data:             Payload of the message (variable length)
 *
 * This structure represents a full RPMI message. The @data buffer
 * follows immediately after the header and its size is defined by
 * @header.datalen.
 */
struct rpmi_message {
	struct rpmi_message_header header;
	uint8_t data[];
} __packed;

/*
 * struct rpmi_notification_event - Notification message for events
 * @event_datalen:    Size of the event data payload in bytes
 * @event_id:         Identifier for the event type within the service group
 * @reserved:         Reserved byte (must be zero)
 * @event_data:       Event-specific payload (variable length)
 *
 * This structure defines the format of a notification event sent
 * by RPMI-enabled services through MPXY.
 */
struct rpmi_notification_event {
	uint16_t event_datalen;
	uint8_t event_id;
	uint8_t reserved;
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
