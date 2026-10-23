/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef __DRIVERS_RPMI_MAILBOX_H
#define __DRIVERS_RPMI_MAILBOX_H

#include <drivers/mailbox.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_defines.h>

/* Local mailbox attribute IDs, not firmware wire values. */
enum rpmi_mbox_attribute_id {
	RPMI_MBOX_ATTR_SPEC_VERSION,
	RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE,
	RPMI_MBOX_ATTR_SERVICEGROUP_ID,
	RPMI_MBOX_ATTR_SERVICEGROUP_VERSION,
	RPMI_MBOX_ATTR_IMPL_ID,
	RPMI_MBOX_ATTR_IMPL_VERSION,
};

enum rpmi_mbox_message_type {
	RPMI_MBOX_MSG_TYPE_GET_ATTRIBUTE,
	RPMI_MBOX_MSG_TYPE_SEND_WITH_RESPONSE,
	RPMI_MBOX_MSG_TYPE_SEND_WITHOUT_RESPONSE,
};

/**
 * struct rpmi_mbox_message - RPMI mailbox transaction
 * @type: Operation requested from the provider
 * @attr: Attribute identifier and returned value
 * @data: Service identifier, request and response buffers and their lengths
 * @error: Transaction TEE_Result, separate from firmware service status
 *
 * out_response_len contains the received byte count after a successful send.
 * Firmware service status remains in the response buffer.
 */
struct rpmi_mbox_message {
	enum rpmi_mbox_message_type type;
	union {
		struct {
			enum rpmi_mbox_attribute_id id;
			uint32_t value;
		} attr;

		struct {
			uint32_t service_id;
			void *request;
			size_t request_len;
			void *response;
			size_t max_response_len;
			size_t out_response_len;
		} data;
	};

	TEE_Result error;
};

static inline void
rpmi_mbox_init_get_attribute(struct rpmi_mbox_message *msg,
			     enum rpmi_mbox_attribute_id id)
{
	msg->type = RPMI_MBOX_MSG_TYPE_GET_ATTRIBUTE;
	msg->attr.id = id;
	msg->attr.value = 0;
	msg->error = TEE_SUCCESS;
}

static inline void
rpmi_mbox_init_send_with_response(struct rpmi_mbox_message *msg,
				  uint32_t service_id, void *request,
				  size_t request_len, void *response,
				  size_t max_response_len)
{
	msg->type = RPMI_MBOX_MSG_TYPE_SEND_WITH_RESPONSE;
	msg->data.service_id = service_id;
	msg->data.request = request;
	msg->data.request_len = request_len;
	msg->data.response = response;
	msg->data.max_response_len = max_response_len;
	msg->data.out_response_len = 0;
	msg->error = TEE_SUCCESS;
}

static inline void
rpmi_mbox_init_send_without_response(struct rpmi_mbox_message *msg,
				     uint32_t service_id, void *request,
				     size_t request_len)
{
	msg->type = RPMI_MBOX_MSG_TYPE_SEND_WITHOUT_RESPONSE;
	msg->data.service_id = service_id;
	msg->data.request = request;
	msg->data.request_len = request_len;
	msg->data.response = NULL;
	msg->data.max_response_len = 0;
	msg->data.out_response_len = 0;
	msg->error = TEE_SUCCESS;
}

/* Report mailbox failures before the provider's transaction result. */
static inline TEE_Result
rpmi_mbox_send_message_sync(struct mbox_chan *chan,
			    struct rpmi_mbox_message *msg)
{
	TEE_Result res = TEE_SUCCESS;

	res = mbox_send_message_sync(chan, msg);
	if (res)
		return res;

	return msg->error;
}

static inline TEE_Result
rpmi_mbox_get_attribute(struct mbox_chan *chan,
			enum rpmi_mbox_attribute_id id, uint32_t *value)
{
	struct rpmi_mbox_message msg = {};
	TEE_Result res = TEE_SUCCESS;

	if (!value)
		return TEE_ERROR_BAD_PARAMETERS;

	rpmi_mbox_init_get_attribute(&msg, id);
	res = rpmi_mbox_send_message_sync(chan, &msg);
	if (res)
		return res;

	*value = msg.attr.value;

	return TEE_SUCCESS;
}

#endif /* __DRIVERS_RPMI_MAILBOX_H */
