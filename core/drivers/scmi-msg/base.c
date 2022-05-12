// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Linaro Limited
 */
#include <assert.h>
#include <confine_array_index.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "base.h"
#include "common.h"

static bool message_id_is_supported(unsigned int message_id);

static void report_version(struct scmi_msg *msg)
{
	struct scmi_protocol_version_p2a return_values = {
		.status = SCMI_SUCCESS,
		.version = SCMI_PROTOCOL_VERSION_BASE,
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void report_attributes(struct scmi_msg *msg)
{
	size_t protocol_count = plat_scmi_protocol_count();
	struct scmi_protocol_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
		/* Null agent count since agent discovery is not supported */
		.attributes = SCMI_BASE_PROTOCOL_ATTRIBUTES(protocol_count, 0),
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void report_message_attributes(struct scmi_msg *msg)
{
	struct scmi_protocol_message_attributes_a2p *in_args = (void *)msg->in;
	struct scmi_protocol_message_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
		/* For this protocol, attributes shall be zero */
		.attributes = 0,
	};

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (!message_id_is_supported(in_args->message_id)) {
		scmi_status_response(msg, SCMI_NOT_FOUND);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void discover_vendor(struct scmi_msg *msg)
{
	const char *name = plat_scmi_vendor_name();
	struct scmi_base_discover_vendor_p2a return_values = {
		.status = SCMI_SUCCESS,
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	COPY_NAME_IDENTIFIER(return_values.vendor_identifier, name);

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void discover_sub_vendor(struct scmi_msg *msg)
{
	const char *name = plat_scmi_sub_vendor_name();
	struct scmi_base_discover_sub_vendor_p2a return_values = {
		.status = SCMI_SUCCESS,
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	COPY_NAME_IDENTIFIER(return_values.sub_vendor_identifier, name);

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void discover_implementation_version(struct scmi_msg *msg)
{
	struct scmi_protocol_version_p2a return_values = {
		.status = SCMI_SUCCESS,
		.version = SCMI_IMPL_VERSION,
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static unsigned int count_protocols_in_list(const uint8_t *protocol_list)
{
	unsigned int count = 0;

	if (protocol_list)
		while (protocol_list[count])
			count++;

	return count;
}

#define MAX_PROTOCOL_IN_LIST		8u

static void discover_list_protocols(struct scmi_msg *msg)
{
	const struct scmi_base_discover_list_protocols_a2p *a2p = NULL;
	struct scmi_base_discover_list_protocols_p2a p2a = {
		.status = SCMI_SUCCESS,
	};
	uint8_t outargs[sizeof(p2a) + MAX_PROTOCOL_IN_LIST] = { };
	const uint8_t *list = NULL;
	unsigned int count = 0;

	if (msg->in_size != sizeof(*a2p)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	assert(msg->out_size > sizeof(outargs));

	a2p = (void *)msg->in;

	list = plat_scmi_protocol_list(msg->channel_id);
	count = count_protocols_in_list(list);
	if (count > a2p->skip)
		count = MIN(count - a2p->skip, MAX_PROTOCOL_IN_LIST);
	else
		count = 0;

	p2a.num_protocols = count;

	memcpy(outargs, &p2a, sizeof(p2a));
	memcpy(outargs + sizeof(p2a), list + a2p->skip, count);

	scmi_write_response(msg, outargs,
			    sizeof(p2a) + ROUNDUP(count, sizeof(uint32_t)));
}

static const scmi_msg_handler_t scmi_base_handler_table[] = {
	[SCMI_PROTOCOL_VERSION] = report_version,
	[SCMI_PROTOCOL_ATTRIBUTES] = report_attributes,
	[SCMI_PROTOCOL_MESSAGE_ATTRIBUTES] = report_message_attributes,
	[SCMI_BASE_DISCOVER_VENDOR] = discover_vendor,
	[SCMI_BASE_DISCOVER_SUB_VENDOR] = discover_sub_vendor,
	[SCMI_BASE_DISCOVER_IMPLEMENTATION_VERSION] =
					discover_implementation_version,
	[SCMI_BASE_DISCOVER_LIST_PROTOCOLS] = discover_list_protocols,
};

static bool message_id_is_supported(unsigned int message_id)
{
	return message_id < ARRAY_SIZE(scmi_base_handler_table) &&
	       scmi_base_handler_table[message_id];
}

scmi_msg_handler_t scmi_msg_get_base_handler(struct scmi_msg *msg)
{
	const size_t array_size = ARRAY_SIZE(scmi_base_handler_table);
	unsigned int message_id = 0;

	if (msg->message_id >= array_size) {
		DMSG("Base handle not found %u", msg->message_id);
		return NULL;
	}

	message_id = confine_array_index(msg->message_id, array_size);

	return scmi_base_handler_table[message_id];
}
