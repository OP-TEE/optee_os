// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Linaro Limited
 */
#include <assert.h>
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

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void report_message_attributes(struct scmi_msg *msg)
{
	struct scmi_protocol_message_attributes_a2p *inargs = (void *)msg->in;
	struct scmi_protocol_message_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
		.attributes = 0,
	};

	if (!message_id_is_supported(inargs->message_id))
		scmi_status_response(msg, SCMI_NOT_FOUND);
	else
		scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void discover_vendor(struct scmi_msg *msg)
{
	const char *name = plat_scmi_vendor_name();
	struct scmi_base_discover_vendor_p2a return_values = {
		.status = SCMI_SUCCESS,
	};

	memcpy(&return_values, name,
	       strnlen(name, SCMI_DEFAULT_STRING_LENGTH));

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void discover_sub_vendor(struct scmi_msg *msg)
{
	const char *name = plat_scmi_sub_vendor_name();
	struct scmi_base_discover_sub_vendor_p2a return_values = {
		.status = SCMI_SUCCESS,
	};

	memcpy(&return_values, name,
	       strnlen(name, SCMI_DEFAULT_STRING_LENGTH));

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void discover_implementation_version(struct scmi_msg *msg)
{
	struct scmi_protocol_version_p2a return_values = {
		.status = SCMI_SUCCESS,
		.version = SCMI_IMPL_VERSION,
	};

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static unsigned int count_protocols_in_list(const uint8_t *protocol_list)
{
	unsigned int count = 0;

	while (protocol_list && protocol_list[count])
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
	uint8_t outargs[sizeof(p2a) + MAX_PROTOCOL_IN_LIST];
	const uint8_t *list = NULL;
	unsigned int count = 0;

	assert(msg->out_size > sizeof(outargs));

	a2p = (void *)msg->in;

	list = plat_scmi_protocol_list(msg->agent_id);
	count = count_protocols_in_list(list);
	if (count > a2p->skip)
		count = MIN(count - a2p->skip, MAX_PROTOCOL_IN_LIST);
	else
		count = 0;

	p2a.num_protocols = count;

	memcpy(&outargs[0], &p2a, sizeof(p2a));
	memcpy(&outargs[sizeof(p2a)], list + a2p->skip, count);

	scmi_write_response(msg, &outargs, sizeof(outargs));
}

const scmi_msg_handler_t scmi_base_handler_table[] = {
	[SCMI_PROTOCOL_VERSION] = report_version,
	[SCMI_PROTOCOL_ATTRIBUTES] = report_attributes,
	[SCMI_PROTOCOL_MESSAGE_ATTRIBUTES] = report_message_attributes,
	[SCMI_BASE_DISCOVER_VENDOR] = discover_vendor,
	[SCMI_BASE_DISCOVER_SUB_VENDOR] = discover_sub_vendor,
	[SCMI_BASE_DISCOVER_IMPLEMENTATION_VERSION] =
					discover_implementation_version,
	[SCMI_BASE_DISCOVER_LIST_PROTOCOLS] = discover_list_protocols,
};

const size_t scmi_base_payload_size_table[] = {
	[SCMI_PROTOCOL_VERSION] = 0,
	[SCMI_PROTOCOL_ATTRIBUTES] = 0,
	[SCMI_PROTOCOL_MESSAGE_ATTRIBUTES] =
			sizeof(struct scmi_protocol_message_attributes_a2p),
	[SCMI_BASE_DISCOVER_VENDOR] = 0,
	[SCMI_BASE_DISCOVER_SUB_VENDOR] = 0,
	[SCMI_BASE_DISCOVER_IMPLEMENTATION_VERSION] = 0,
	[SCMI_BASE_DISCOVER_LIST_PROTOCOLS] =
			sizeof(struct scmi_base_discover_list_protocols_a2p),
};

const size_t scmi_base_handler_count = ARRAY_SIZE(scmi_base_handler_table);

static bool message_id_is_supported(unsigned int message_id)
{
	COMPILE_TIME_ASSERT(ARRAY_SIZE(scmi_base_handler_table) ==
			    ARRAY_SIZE(scmi_base_payload_size_table));

	return scmi_get_msg_handler(message_id, scmi_base_handler_table,
				    ARRAY_SIZE(scmi_base_handler_table));
}
