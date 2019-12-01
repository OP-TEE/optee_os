/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Linaro Limited
 */
#ifndef SCMI_MSG_COMMON_H
#define SCMI_MSG_COMMON_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <types_ext.h>

#include "base.h"

#define SCMI_VERSION			0x20000
#define SCMI_IMPL_VERSION		0

#define SCMI_PLAYLOAD_MAX		92

/* Common command identifiers shared by all procotols */
enum scmi_common_message_id {
	SCMI_PROTOCOL_VERSION = 0x000,
	SCMI_PROTOCOL_ATTRIBUTES = 0x001,
	SCMI_PROTOCOL_MESSAGE_ATTRIBUTES = 0x002
};

/* Common platform-to-agent (p2a) PROTOCOL_VERSION structure */
struct scmi_protocol_version_p2a {
	int32_t status;
	uint32_t version;
} __packed;

/* Generic platform-to-agent (p2a) PROTOCOL_ATTRIBUTES structure */
struct scmi_protocol_attributes_p2a {
	int32_t status;
	uint32_t attributes;
} __packed;

/* Generic agent-to-platform (a2p) PROTOCOL_MESSAGE_ATTRIBUTES structure */
struct scmi_protocol_message_attributes_a2p {
	uint32_t message_id;
} __packed;

/* Generic platform-to-agent (p2a) PROTOCOL_MESSAGE_ATTRIBUTES structure */
struct scmi_protocol_message_attributes_p2a {
	int32_t status;
	uint32_t attributes;
} __packed;

/*
 * struct scmi_msg - SCMI message context
 *
 * @agent_id: SCMI agent ID, safely set from secure world
 * @protocol_id: SCMI protocol ID for the related message, set by caller agent
 * @message_id: SCMI message ID for the related message, set by caller agent
 * @in: Address of the incoming message payload copied in secure memory
 * @in_size: Byte length of the incoming message payload, set by caller agent
 * @out: Address of of the output message payload message in non-secure memory
 * @out_size: Byte length of the provisionned output buffer
 * @out_size_out: Byte length of the output message payload
 */
struct scmi_msg {
	unsigned int agent_id;
	unsigned int protocol_id;
	unsigned int message_id;
	char *in;
	size_t in_size;
	char *out;
	size_t out_size;
	size_t out_size_out;
};

/*
 * Type scmi_msg_handler_t is used by procotol drivers to safely find
 * the handler function for the incoming message ID.
 */
typedef void (*scmi_msg_handler_t)(struct scmi_msg *msg);

extern const scmi_msg_handler_t scmi_base_handler_table[];
extern const size_t scmi_base_payload_size_table[];
extern const size_t scmi_base_handler_count;

/*
 * Call handler related to message ID from a handler table.
 * Sanitize message ID and payload size, fill return message if invalid.
 * Called handler is responsible for filling output message.
 *
 * @msg: SCMI message context
 * @handler_array: Message handler array
 * @payload_size_array: Expected input payload size array
 * @elt_count: Number of elements @handler_array
 * Return handler or NULL for message found and input paremters size is valid
 */
void scmi_call_msg_handler(struct scmi_msg *msg,
			   const scmi_msg_handler_t *handler_table,
			   const size_t *payload_size_table,
			   size_t elt_count);

/*
 * Get handler related to message ID from a handler table.
 *
 * @message_id: SCMI message ID
 * @handler_array: Message handler array
 * @elt_count: Number of elements @handler_array
 * Return handler or NULL for message found and input paremters size is valid
 */
scmi_msg_handler_t scmi_get_msg_handler(unsigned int message_id,
					const scmi_msg_handler_t *handler_table,
					size_t elt_count);

/*
 * Process Read, process and write response for input SCMI message
 *
 * @msg: SCMI message context
 */
void scmi_process_message(struct scmi_msg *msg);

/*
 * Write SCMI response payload to output message shared memory
 *
 * @msg: SCMI message context
 * @payload: Output message payload
 * @size: Byte size of output message payload
 */
static inline void scmi_write_response(struct scmi_msg *msg,
				       void *payload, size_t size)
{
	/*
	 * Output payload shall be at least the size of the status
	 * Output buffer shall be at least be the size of the status
	 * Output paylaod shall fit in output buffer
	 **/
	assert(payload && size >= sizeof(int32_t) && size <= msg->out_size &&
	       msg->out && msg->out_size >= sizeof(int32_t));

	memcpy(msg->out, payload, size);
	msg->out_size_out = size;
}

/*
 * Write status only SCMI response payload to output message shared memory
 *
 * @msg: SCMI message context
 * @status: SCMI status value returned to caller
 */
static inline void scmi_status_response(struct scmi_msg *msg,
					int32_t status)
{
	assert(msg->out && msg->out_size >= sizeof(int32_t));

	memcpy(msg->out, &status, sizeof(int32_t));
	msg->out_size_out = sizeof(int32_t);
}
#endif /* SCMI_MSG_COMMON_H */
