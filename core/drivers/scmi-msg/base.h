/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef SCMI_MSG_BASE_H
#define SCMI_MSG_BASE_H

#include <stdint.h>
#include <types_ext.h>

#include "common.h"

#define SCMI_PROTOCOL_VERSION_BASE	0x20000

#define SCMI_DEFAULT_STRING_LENGTH	16

enum scmi_base_message_id {
	SCMI_BASE_DISCOVER_VENDOR		= 0x003,
	SCMI_BASE_DISCOVER_SUB_VENDOR		= 0x004,
	SCMI_BASE_DISCOVER_IMPLEMENTATION_VERSION = 0x005,
	SCMI_BASE_DISCOVER_LIST_PROTOCOLS	= 0x006,
	SCMI_BASE_DISCOVER_AGENT		= 0x007,
	SCMI_BASE_NOTIFY_ERRORS			= 0x008,
};

/*
 * PROTOCOL_ATTRIBUTES
 */

#define SCMI_BASE_PROTOCOL_ATTRS_NUM_PROTOCOLS_POS	0
#define SCMI_BASE_PROTOCOL_ATTRS_NUM_AGENTS_POS		8

#define SCMI_BASE_PROTOCOL_ATTRS_NUM_PROTOCOLS_MASK	0xFF
#define SCMI_BASE_PROTOCOL_ATTRS_NUM_AGENTS_MASK	0xFF00

#define SCMI_BASE_PROTOCOL_ATTRIBUTES(NUM_PROTOCOLS, NUM_AGENTS) \
	((((NUM_PROTOCOLS) << SCMI_BASE_PROTOCOL_ATTRS_NUM_PROTOCOLS_POS) & \
	  SCMI_BASE_PROTOCOL_ATTRS_NUM_PROTOCOLS_MASK) | \
	(((NUM_AGENTS) << SCMI_BASE_PROTOCOL_ATTRS_NUM_AGENTS_POS) & \
	 SCMI_BASE_PROTOCOL_ATTRS_NUM_AGENTS_MASK))

/*
 * BASE_DISCOVER_VENDOR
 */
struct scmi_base_discover_vendor_p2a {
	int32_t status;
	char vendor_identifier[SCMI_DEFAULT_STRING_LENGTH];
};

/*
 * BASE_DISCOVER_SUB_VENDOR
 */
struct scmi_base_discover_sub_vendor_p2a {
	int32_t status;
	char sub_vendor_identifier[SCMI_DEFAULT_STRING_LENGTH];
};

/*
 * BASE_DISCOVER_IMPLEMENTATION_VERSION
 * No special structure right now, see protocol_version.
 */

/*
 * BASE_DISCOVER_LIST_PROTOCOLS
 */
struct scmi_base_discover_list_protocols_a2p {
	uint32_t skip;
};

struct scmi_base_discover_list_protocols_p2a {
	int32_t status;
	uint32_t num_protocols;
	uint32_t protocols[];
};

/*
 * scmi_msg_get_base_handler - Return a handler for a base message
 * @msg - message to process
 * Return a function handler for the message or NULL
 */
scmi_msg_handler_t scmi_msg_get_base_handler(struct scmi_msg *msg);

#endif /* SCMI_MSG_BASE_H */
