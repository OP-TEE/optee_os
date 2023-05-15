/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Linaro Limited
 */
#ifndef SCMI_MSG_RESET_DOMAIN_H
#define SCMI_MSG_RESET_DOMAIN_H

#include <compiler.h>
#include <stdbool.h>
#include <stdint.h>
#include <types_ext.h>
#include <util.h>

#include "common.h"

#define SCMI_PROTOCOL_VERSION_RESET_DOMAIN	0x10000

#define SCMI_RESET_STATE_ARCH			BIT(31)
#define SCMI_RESET_STATE_IMPL			0

/*
 * Identifiers of the SCMI Reset Domain Management Protocol commands
 */
enum scmi_reset_domain_command_id {
	SCMI_RESET_DOMAIN_ATTRIBUTES = 0x03,
	SCMI_RESET_DOMAIN_REQUEST = 0x04,
	SCMI_RESET_DOMAIN_NOTIFY = 0x05,
};

/*
 * Identifiers of the SCMI Reset Domain Management Protocol responses
 */
enum scmi_reset_domain_response_id {
	SCMI_RESET_ISSUED = 0x00,
	SCMI_RESET_COMPLETE = 0x04,
};

/*
 * PROTOCOL_ATTRIBUTES
 */

#define SCMI_RESET_DOMAIN_COUNT_MASK		GENMASK_32(15, 0)

struct scmi_reset_domain_protocol_attributes_p2a {
	int32_t status;
	uint32_t attributes;
};

/* Value for scmi_reset_domain_attributes_p2a:flags */
#define SCMI_RESET_DOMAIN_ATTR_ASYNC		BIT(31)
#define SCMI_RESET_DOMAIN_ATTR_NOTIF		BIT(30)

/* Value for scmi_reset_domain_attributes_p2a:latency */
#define SCMI_RESET_DOMAIN_ATTR_UNK_LAT		0x7fffffff
#define SCMI_RESET_DOMAIN_ATTR_MAX_LAT		0x7ffffffe

/* Macro for scmi_reset_domain_attributes_p2a:name */
#define SCMI_RESET_DOMAIN_ATTR_NAME_SZ		16

struct scmi_reset_domain_attributes_a2p {
	uint32_t domain_id;
};

struct scmi_reset_domain_attributes_p2a {
	int32_t status;
	uint32_t flags;
	uint32_t latency;
	char name[SCMI_RESET_DOMAIN_ATTR_NAME_SZ];
};

/*
 * RESET
 */

/* Values for scmi_reset_domain_request_a2p:flags */
#define SCMI_RESET_DOMAIN_ASYNC			BIT(2)
#define SCMI_RESET_DOMAIN_EXPLICIT		BIT(1)
#define SCMI_RESET_DOMAIN_AUTO			BIT(0)

struct scmi_reset_domain_request_a2p {
	uint32_t domain_id;
	uint32_t flags;
	uint32_t reset_state;
};

struct scmi_reset_domain_request_p2a {
	int32_t status;
};

/*
 * RESET_NOTIFY
 */

/* Values for scmi_reset_notify_p2a:flags */
#define SCMI_RESET_DOMAIN_DO_NOTIFY		BIT(0)

struct scmi_reset_domain_notify_a2p {
	uint32_t domain_id;
	uint32_t notify_enable;
};

struct scmi_reset_domain_notify_p2a {
	int32_t status;
};

/*
 * RESET_COMPLETE
 */

struct scmi_reset_domain_complete_p2a {
	int32_t status;
	uint32_t domain_id;
};

/*
 * RESET_ISSUED
 */

struct scmi_reset_domain_issued_p2a {
	uint32_t domain_id;
	uint32_t reset_state;
};

#ifdef CFG_SCMI_MSG_RESET_DOMAIN
/*
 * scmi_msg_get_rd_handler - Return a handler for a reset domain message
 * @msg - message to process
 * Return a function handler for the message or NULL
 */
scmi_msg_handler_t scmi_msg_get_rd_handler(struct scmi_msg *msg);
#else
static inline
scmi_msg_handler_t scmi_msg_get_rd_handler(struct scmi_msg *msg __unused)
{
	return NULL;
}
#endif
#endif /* SCMI_MSG_RESET_DOMAIN_H */
