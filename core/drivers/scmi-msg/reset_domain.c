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
#include <util.h>

#include "common.h"
#include "reset_domain.h"

static bool message_id_is_supported(unsigned int message_id);

size_t __weak plat_scmi_rd_count(unsigned int channel_id __unused)
{
	return 0;
}

const char __weak *plat_scmi_rd_get_name(unsigned int channel_id __unused,
					 unsigned int scmi_id __unused)
{
	return NULL;
}

int32_t __weak plat_scmi_rd_autonomous(unsigned int channel_id __unused,
				       unsigned int scmi_id __unused,
				       unsigned int state __unused)
{
	return SCMI_NOT_SUPPORTED;
}

int32_t __weak plat_scmi_rd_set_state(unsigned int channel_id __unused,
				      unsigned int scmi_id __unused,
				      bool assert_not_deassert __unused)
{
	return SCMI_NOT_SUPPORTED;
}

static void report_version(struct scmi_msg *msg)
{
	struct scmi_protocol_version_p2a return_values = {
		.status = SCMI_SUCCESS,
		.version = SCMI_PROTOCOL_VERSION_RESET_DOMAIN,
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void report_attributes(struct scmi_msg *msg)
{
	struct scmi_protocol_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
		.attributes = plat_scmi_rd_count(msg->channel_id),
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

static void reset_domain_attributes(struct scmi_msg *msg)
{
	struct scmi_reset_domain_attributes_a2p *in_args = (void *)msg->in;
	struct scmi_reset_domain_attributes_p2a return_values = { };
	const char *name = NULL;
	unsigned int domain_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->domain_id >= plat_scmi_rd_count(msg->channel_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	domain_id = confine_array_index(in_args->domain_id,
					plat_scmi_rd_count(msg->channel_id));

	name = plat_scmi_rd_get_name(msg->channel_id, domain_id);
	if (!name) {
		scmi_status_response(msg, SCMI_NOT_FOUND);
		return;
	}

	COPY_NAME_IDENTIFIER(return_values.name, name);
	return_values.status = SCMI_SUCCESS;
	return_values.flags = 0; /* Async and Notif are not supported */
	return_values.latency = SCMI_RESET_DOMAIN_ATTR_UNK_LAT;

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void reset_request(struct scmi_msg *msg)
{
	struct scmi_reset_domain_request_a2p *in_args = (void *)msg->in;
	struct scmi_reset_domain_request_p2a out_args = {
		.status = SCMI_SUCCESS,
	};
	unsigned int domain_id = 0;

	domain_id = confine_array_index(in_args->domain_id,
					plat_scmi_rd_count(msg->channel_id));

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->domain_id >= plat_scmi_rd_count(msg->channel_id)) {
		scmi_status_response(msg, SCMI_NOT_FOUND);
		return;
	}

	if (in_args->flags & SCMI_RESET_DOMAIN_AUTO)
		out_args.status = plat_scmi_rd_autonomous(msg->channel_id,
							  domain_id,
							  in_args->reset_state);
	else if (in_args->flags & SCMI_RESET_DOMAIN_EXPLICIT)
		out_args.status = plat_scmi_rd_set_state(msg->channel_id,
							 domain_id, true);
	else
		out_args.status = plat_scmi_rd_set_state(msg->channel_id,
							 domain_id, false);

	if (out_args.status)
		scmi_status_response(msg, out_args.status);
	else
		scmi_write_response(msg, &out_args, sizeof(out_args));
}

static const scmi_msg_handler_t scmi_rd_handler_table[] = {
	[SCMI_PROTOCOL_VERSION] = report_version,
	[SCMI_PROTOCOL_ATTRIBUTES] = report_attributes,
	[SCMI_PROTOCOL_MESSAGE_ATTRIBUTES] = report_message_attributes,
	[SCMI_RESET_DOMAIN_ATTRIBUTES] = reset_domain_attributes,
	[SCMI_RESET_DOMAIN_REQUEST] = reset_request,
};

static bool message_id_is_supported(unsigned int message_id)
{
	return message_id < ARRAY_SIZE(scmi_rd_handler_table) &&
	       scmi_rd_handler_table[message_id];
}

scmi_msg_handler_t scmi_msg_get_rd_handler(struct scmi_msg *msg)
{
	const size_t array_size = ARRAY_SIZE(scmi_rd_handler_table);
	unsigned int message_id = 0;

	if (msg->message_id >= array_size) {
		DMSG("Reset domain handle not found %u", msg->message_id);
		return NULL;
	}

	message_id = confine_array_index(msg->message_id, array_size);

	return scmi_rd_handler_table[message_id];
}
