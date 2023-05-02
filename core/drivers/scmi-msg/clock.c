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

#include "clock.h"
#include "common.h"

static bool message_id_is_supported(unsigned int message_id);

size_t __weak plat_scmi_clock_count(unsigned int channel_id __unused)
{
	return 0;
}

const char __weak *plat_scmi_clock_get_name(unsigned int channel_id __unused,
					    unsigned int scmi_id __unused)
{
	return NULL;
}

int32_t __weak plat_scmi_clock_rates_array(unsigned int channel_id __unused,
					   unsigned int scmi_id __unused,
					   size_t start_index __unused,
					   unsigned long *rates __unused,
					   size_t *nb_elts __unused)
{
	return SCMI_NOT_SUPPORTED;
}

int32_t __weak plat_scmi_clock_rates_by_step(unsigned int channel_id __unused,
					     unsigned int scmi_id __unused,
					     unsigned long *steps __unused)
{
	return SCMI_NOT_SUPPORTED;
}

unsigned long __weak plat_scmi_clock_get_rate(unsigned int channel_id __unused,
					      unsigned int scmi_id __unused)
{
	return 0;
}

int32_t __weak plat_scmi_clock_set_rate(unsigned int channel_id __unused,
					unsigned int scmi_id __unused,
					unsigned long rate __unused)
{
	return SCMI_NOT_SUPPORTED;
}

int32_t __weak plat_scmi_clock_get_state(unsigned int channel_id __unused,
					 unsigned int scmi_id __unused)
{
	return SCMI_NOT_SUPPORTED;
}

int32_t __weak plat_scmi_clock_set_state(unsigned int channel_id __unused,
					 unsigned int scmi_id __unused,
					 bool enable_not_disable __unused)
{
	return SCMI_NOT_SUPPORTED;
}

static void report_version(struct scmi_msg *msg)
{
	struct scmi_protocol_version_p2a return_values = {
		.status = SCMI_SUCCESS,
		.version = SCMI_PROTOCOL_VERSION_CLOCK,
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void report_attributes(struct scmi_msg *msg)
{
	size_t clk_count = plat_scmi_clock_count(msg->channel_id);
	struct scmi_protocol_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
		.attributes = SCMI_CLOCK_PROTOCOL_ATTRIBUTES(1, clk_count),
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

static void scmi_clock_attributes(struct scmi_msg *msg)
{
	const struct scmi_clock_attributes_a2p *in_args = (void *)msg->in;
	struct scmi_clock_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
	};
	const char *name = NULL;
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->channel_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->channel_id));

	name = plat_scmi_clock_get_name(msg->channel_id, clock_id);
	if (!name) {
		scmi_status_response(msg, SCMI_NOT_FOUND);
		return;
	}

	COPY_NAME_IDENTIFIER(return_values.clock_name, name);

	return_values.attributes = plat_scmi_clock_get_state(msg->channel_id,
							     clock_id);

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void scmi_clock_rate_get(struct scmi_msg *msg)
{
	const struct scmi_clock_rate_get_a2p *in_args = (void *)msg->in;
	unsigned long rate = 0;
	struct scmi_clock_rate_get_p2a return_values = { };
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->channel_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->channel_id));

	rate = plat_scmi_clock_get_rate(msg->channel_id, clock_id);

	reg_pair_from_64(rate, return_values.rate + 1, return_values.rate);

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void scmi_clock_rate_set(struct scmi_msg *msg)
{
	const struct scmi_clock_rate_set_a2p *in_args = (void *)msg->in;
	uint64_t rate_64 = 0;
	unsigned long rate = 0;
	int32_t status = 0;
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->channel_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->channel_id));

	rate_64 = reg_pair_to_64(in_args->rate[1], in_args->rate[0]);
	rate = rate_64;

	status = plat_scmi_clock_set_rate(msg->channel_id, clock_id, rate);

	scmi_status_response(msg, status);
}

static void scmi_clock_config_set(struct scmi_msg *msg)
{
	const struct scmi_clock_config_set_a2p *in_args = (void *)msg->in;
	int32_t status = SCMI_GENERIC_ERROR;
	bool enable = false;
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->channel_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->channel_id));

	enable = in_args->attributes & SCMI_CLOCK_CONFIG_SET_ENABLE_MASK;

	status = plat_scmi_clock_set_state(msg->channel_id, clock_id, enable);

	scmi_status_response(msg, status);
}

#define SCMI_RATES_BY_ARRAY(_nb_rates, _rem_rates) \
	SCMI_CLOCK_DESCRIBE_RATES_NUM_RATES_FLAGS((_nb_rates), \
						SCMI_CLOCK_RATE_FORMAT_LIST, \
						(_rem_rates))
#define SCMI_RATES_BY_STEP \
	SCMI_CLOCK_DESCRIBE_RATES_NUM_RATES_FLAGS(3, \
						SCMI_CLOCK_RATE_FORMAT_RANGE, \
						0)

#define RATE_DESC_SIZE		sizeof(struct scmi_clock_rate)

static void write_rate_desc_array_in_buffer(char *dest, unsigned long *rates,
					    size_t nb_elt)
{
	uint32_t *out = NULL;
	size_t n = 0;

	assert(IS_ALIGNED_WITH_TYPE(dest, uint32_t));
	out = (uint32_t *)(uintptr_t)dest;

	for (n = 0; n < nb_elt; n++) {
		uint64_t rate = rates[n];

		reg_pair_from_64(rate, out + 2 * n + 1, out + 2 * n);
	}
}

static void scmi_clock_describe_rates(struct scmi_msg *msg)
{
	const struct scmi_clock_describe_rates_a2p *in_args = (void *)msg->in;
	struct scmi_clock_describe_rates_p2a p2a = { };
	size_t nb_rates = 0;
	int32_t status = SCMI_GENERIC_ERROR;
	unsigned int clock_id = 0;
	unsigned int out_count = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->channel_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->channel_id));

	/* Platform may support array rate description */
	status = plat_scmi_clock_rates_array(msg->channel_id, clock_id, 0, NULL,
					     &nb_rates);
	if (status == SCMI_SUCCESS) {
		unsigned int rate_index = in_args->rate_index;
		unsigned int remaining = 0;
		size_t avail_sz = msg->out_size - sizeof(p2a);
		char *out_rates = msg->out + sizeof(p2a);

		if (avail_sz < RATE_DESC_SIZE && nb_rates) {
			status = SCMI_PROTOCOL_ERROR;
			goto out;
		}

		while (avail_sz >= RATE_DESC_SIZE && rate_index < nb_rates) {
			unsigned long rate = 0;
			size_t cnt = 1;

			status = plat_scmi_clock_rates_array(msg->channel_id,
							     clock_id,
							     rate_index,
							     &rate, &cnt);
			if (status)
				goto out;

			write_rate_desc_array_in_buffer(out_rates, &rate, cnt);
			avail_sz -= RATE_DESC_SIZE;
			out_rates += RATE_DESC_SIZE;
			rate_index++;
		}

		out_count = rate_index - in_args->rate_index;
		remaining = nb_rates - in_args->rate_index;
		p2a.num_rates_flags = SCMI_RATES_BY_ARRAY(out_count, remaining);
	} else if (status == SCMI_NOT_SUPPORTED) {
		unsigned long triplet[3] = { 0, 0, 0 };

		if (msg->out_size < sizeof(p2a) + 3 * RATE_DESC_SIZE) {
			status = SCMI_PROTOCOL_ERROR;
			goto out;
		}

		/* Platform may support min/max/step triplet description */
		status =  plat_scmi_clock_rates_by_step(msg->channel_id,
							clock_id, triplet);
		if (status)
			goto out;

		write_rate_desc_array_in_buffer(msg->out + sizeof(p2a),
						triplet, 3);

		out_count = 3;
		p2a.num_rates_flags = SCMI_RATES_BY_STEP;
	} else {
		/* Fallthrough generic exit sequence below with error status */
	}

out:
	if (status) {
		scmi_status_response(msg, status);
	} else {
		p2a.status = SCMI_SUCCESS;
		memcpy(msg->out, &p2a, sizeof(p2a));
		msg->out_size_out = sizeof(p2a) + out_count * RATE_DESC_SIZE;
	}
}

static const scmi_msg_handler_t scmi_clock_handler_table[] = {
	[SCMI_PROTOCOL_VERSION] = report_version,
	[SCMI_PROTOCOL_ATTRIBUTES] = report_attributes,
	[SCMI_PROTOCOL_MESSAGE_ATTRIBUTES] = report_message_attributes,
	[SCMI_CLOCK_ATTRIBUTES] = scmi_clock_attributes,
	[SCMI_CLOCK_DESCRIBE_RATES] = scmi_clock_describe_rates,
	[SCMI_CLOCK_RATE_SET] = scmi_clock_rate_set,
	[SCMI_CLOCK_RATE_GET] = scmi_clock_rate_get,
	[SCMI_CLOCK_CONFIG_SET] = scmi_clock_config_set,
};

static bool message_id_is_supported(unsigned int message_id)
{
	return message_id < ARRAY_SIZE(scmi_clock_handler_table) &&
	       scmi_clock_handler_table[message_id];
}

scmi_msg_handler_t scmi_msg_get_clock_handler(struct scmi_msg *msg)
{
	const size_t array_size = ARRAY_SIZE(scmi_clock_handler_table);
	unsigned int message_id = 0;

	if (msg->message_id >= array_size) {
		DMSG("Clock handle not found %u", msg->message_id);
		return NULL;
	}

	message_id = confine_array_index(msg->message_id, array_size);

	return scmi_clock_handler_table[message_id];
}
