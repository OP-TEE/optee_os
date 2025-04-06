// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2020, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2024, STMicroelectronics
 */
#include <assert.h>
#include <confine_array_index.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <util.h>

#include "common.h"
#include "perf_domain.h"

#define VERBOSE_MSG(...)		FMSG(__VA_ARGS__)

static bool message_id_is_supported(unsigned int message_id);

/* Weak handlers platform shall override on purpose */
size_t __weak plat_scmi_perf_count(unsigned int channel_id __unused)
{
	return 0;
}

void __weak *plat_scmi_perf_statistics_buf(unsigned int channel_id __unused,
					   size_t *stats_len)
{
	*stats_len = 0;

	return NULL;
}

const char __weak *plat_scmi_perf_domain_name(unsigned int channel_id __unused,
					      unsigned int domain_id __unused)
{
	return NULL;
}

int32_t __weak plat_scmi_perf_sustained_freq(unsigned int channel_id __unused,
					     unsigned int domain_id __unused,
					     unsigned int *freq __unused)
{
	return SCMI_NOT_SUPPORTED;
}

int32_t __weak plat_scmi_perf_levels_array(unsigned int channel_id __unused,
					   unsigned int domain_id __unused,
					   size_t start_index __unused,
					   unsigned int *elt __unused,
					   size_t *nb_elts __unused)
{
	return SCMI_NOT_SUPPORTED;
}

int32_t __weak plat_scmi_perf_level_latency(unsigned int channel_id __unused,
					    unsigned int domain_id __unused,
					    unsigned int level __unused,
					    unsigned int *latency)
{
	/* Use 1 microsecond because the Linux kernel treats 0 as eternal */
	*latency = 1;

	return SCMI_SUCCESS;
}

int32_t __weak plat_scmi_perf_level_power_cost(unsigned int channel_id __unused,
					       unsigned int domain_id __unused,
					       unsigned int level __unused,
					       unsigned int *cost __unused)
{
	*cost = 0;

	return SCMI_SUCCESS;
}

int32_t __weak plat_scmi_perf_level_get(unsigned int channel_id __unused,
					unsigned int domain_id __unused,
					unsigned int *level __unused)
{
	return SCMI_NOT_SUPPORTED;
}

int32_t __weak plat_scmi_perf_level_set(unsigned int channel_id __unused,
					unsigned int domain_id __unused,
					unsigned int level __unused)
{
	return SCMI_NOT_SUPPORTED;
}

static void protocol_version(struct scmi_msg *msg)
{
	struct scmi_protocol_version_p2a return_values = {
		.status = SCMI_SUCCESS,
		.version = SCMI_PROTOCOL_VERSION_PERF_DOMAIN,
	};

	VERBOSE_MSG("SCMI perf %#"PRIx32, SCMI_PROTOCOL_VERSION_PERF_DOMAIN);

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void protocol_attributes(struct scmi_msg *msg)
{
	unsigned int channel_id = msg->channel_id;
	size_t count = plat_scmi_perf_count(channel_id);
	uint32_t power_in_mw = 0;
	struct scmi_perf_protocol_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
		.attributes = SCMI_PERF_PROTOCOL_ATTRIBUTES(power_in_mw, count),
	};
	void *stats_buf = NULL;
	size_t stats_len = 0;

	VERBOSE_MSG("channel %u: %zu performance domains", channel_id, count);

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	stats_buf = plat_scmi_perf_statistics_buf(channel_id, &stats_len);
	if (stats_len) {
		paddr_t stats_pa = virt_to_phys(stats_buf);

		if (stats_pa && tee_vbuf_is_non_sec(stats_buf, stats_len)) {
			return_values.statistics_len = stats_len;
			reg_pair_from_64((uint64_t)stats_pa,
					 &return_values.statistics_address_high,
					 &return_values.statistics_address_low);
		} else {
			IMSG("Disable SCMI perf statistics: invalid buffer");
			DMSG("Stats buffer va %p, pa %#"PRIxPA", size %zu",
			     stats_buf, stats_pa, stats_len);
		}
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void protocol_message_attributes(struct scmi_msg *msg)
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

static int32_t sanitize_message(struct scmi_msg *msg, unsigned int *domain_id,
				size_t exp_in_size)
{
	size_t domain_count = plat_scmi_perf_count(msg->channel_id);

	*domain_id = confine_array_index(*domain_id, domain_count);

	if (msg->in_size != exp_in_size)
		return SCMI_PROTOCOL_ERROR;

	if (*domain_id >= domain_count)
		return SCMI_INVALID_PARAMETERS;

	return SCMI_SUCCESS;
}

static void scmi_perf_domain_attributes(struct scmi_msg *msg)
{
	const struct scmi_perf_attributes_a2p *in_args = (void *)msg->in;
	/* It is safe to read in_args->domain_id before sanitize_message() */
	unsigned int domain_id = in_args->domain_id;
	int32_t res = SCMI_GENERIC_ERROR;
	struct scmi_perf_attributes_p2a return_values = {
		.attributes = SCMI_PERF_DOMAIN_ATTRIBUTES_CAN_SET_LEVEL,
		.status = SCMI_SUCCESS,
	};
	const char *name = NULL;

	FMSG("channel %u: domain %u", msg->channel_id, domain_id);

	res = sanitize_message(msg, &domain_id, sizeof(*in_args));
	if (res) {
		scmi_status_response(msg, res);
		return;
	}

	name = plat_scmi_perf_domain_name(msg->channel_id, domain_id);
	if (!name) {
		scmi_status_response(msg, SCMI_NOT_FOUND);
		return;
	}

	res = plat_scmi_perf_sustained_freq(msg->channel_id, domain_id,
					    &return_values.sustained_freq);
	if (res) {
		scmi_status_response(msg, res);
		return;
	}

	COPY_NAME_IDENTIFIER(return_values.name, name);

	/*
	 * .rate_limit and .sustained_perf_level are
	 * implicitly set to 0.
	 */

	VERBOSE_MSG("channel %u: domain %u: name \"%s\"", msg->channel_id,
		    domain_id, name);

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void scmi_perf_level_get(struct scmi_msg *msg)
{
	const struct scmi_perf_level_get_a2p *in_args = (void *)msg->in;
	/* It is safe to read in_args->domain_id before sanitize_message() */
	unsigned int domain_id = in_args->domain_id;
	int32_t res = SCMI_GENERIC_ERROR;
	unsigned int level = 0;
	struct scmi_perf_level_get_p2a return_values = {
		.status = SCMI_SUCCESS,
	};

	VERBOSE_MSG("channel %u, domain %u", msg->channel_id, domain_id);

	res = sanitize_message(msg, &domain_id, sizeof(*in_args));
	if (res) {
		scmi_status_response(msg, res);
		return;
	}

	res = plat_scmi_perf_level_get(msg->channel_id, domain_id, &level);
	if (res) {
		scmi_status_response(msg, res);
		return;
	}

	assert(level <= UINT32_MAX);
	return_values.performance_level = level;

	VERBOSE_MSG("channel %u, domain %u: level %u", msg->channel_id,
		    domain_id, level);

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void scmi_perf_level_set(struct scmi_msg *msg)
{
	const struct scmi_perf_level_set_a2p *in_args = (void *)msg->in;
	unsigned int channel_id = msg->channel_id;
	/* It is safe to read in in_args before sanitize_message() */
	unsigned int domain_id = in_args->domain_id;
	unsigned int level = in_args->performance_level;
	int32_t res = SCMI_GENERIC_ERROR;

	VERBOSE_MSG("channel %u, domain %u: set level %u", channel_id,
		    domain_id, level);

	res = sanitize_message(msg, &domain_id, sizeof(*in_args));
	if (res == SCMI_SUCCESS)
		res = plat_scmi_perf_level_set(channel_id, domain_id, level);

	scmi_status_response(msg, res);
}

/* List levels array by small chunks fitting in SCMI message max payload size */
#define LEVELS_ARRAY_SIZE \
	((SCMI_SEC_PAYLOAD_SIZE - \
	  sizeof(struct scmi_perf_describe_levels_a2p)) / \
	 sizeof(struct scmi_perf_level))

static void scmi_perf_describe_levels(struct scmi_msg *msg)
{
	const struct scmi_perf_describe_levels_a2p *in_args = (void *)msg->in;
	size_t nb_levels = 0;
	/* It is safe to read in_args->domain_id before sanitize_message() */
	unsigned int domain_id = in_args->domain_id;
	int32_t res = SCMI_GENERIC_ERROR;
	/* Use the stack to get the returned a portion of the level array */
	unsigned int plat_levels[LEVELS_ARRAY_SIZE] = { 0 };
	size_t ret_nb = 0;
	size_t rem_nb = 0;

	VERBOSE_MSG("channel %u, domain %u", msg->channel_id, domain_id);

	res = sanitize_message(msg, &domain_id, sizeof(*in_args));
	if (res)
		goto err;

	res = plat_scmi_perf_levels_array(msg->channel_id, domain_id, 0,
					  NULL, &nb_levels);
	if (res)
		goto err;

	if (in_args->level_index >= nb_levels) {
		res = SCMI_INVALID_PARAMETERS;
		goto err;
	}

	ret_nb = MIN(ARRAY_SIZE(plat_levels), nb_levels - in_args->level_index);
	rem_nb = nb_levels - in_args->level_index - ret_nb;

	res =  plat_scmi_perf_levels_array(msg->channel_id, domain_id,
					   in_args->level_index, plat_levels,
					   &ret_nb);

	if (res == SCMI_SUCCESS) {
		struct scmi_perf_describe_levels_p2a p2a = {
			.status = SCMI_SUCCESS,
			.num_levels = SCMI_PERF_NUM_LEVELS(ret_nb, rem_nb),
		};
		struct scmi_perf_level *levels = NULL;
		size_t n = 0;

		memcpy(msg->out, &p2a, sizeof(p2a));

		/* By construction these values are 32bit aligned */
		levels = (void *)(uintptr_t)(msg->out + sizeof(p2a));

		for (n = 0; n < ret_nb; n++) {
			unsigned int latency = 0;
			unsigned int power_cost = 0;

			res = plat_scmi_perf_level_latency(msg->channel_id,
							   domain_id,
							   plat_levels[n],
							   &latency);
			if (res != SCMI_SUCCESS)
				goto err;

			assert(latency <= UINT16_MAX);
			latency &= SCMI_PERF_LEVEL_ATTRIBUTES_LATENCY_US_MASK;

			res = plat_scmi_perf_level_power_cost(msg->channel_id,
							      domain_id,
							      plat_levels[n],
							      &power_cost);
			if (res != SCMI_SUCCESS)
				goto err;

			levels[n] = (struct scmi_perf_level){
				.performance_level = plat_levels[n],
				.power_cost = power_cost,
				.attributes = latency,
			};
		}

		msg->out_size_out =
			sizeof(p2a) + ret_nb * sizeof(struct scmi_perf_level);

		return;
	}

err:
	assert(res);
	scmi_status_response(msg, res);
}

static const scmi_msg_handler_t scmi_perf_handler_table[] = {
	[SCMI_PROTOCOL_VERSION] = protocol_version,
	[SCMI_PROTOCOL_ATTRIBUTES] = protocol_attributes,
	[SCMI_PROTOCOL_MESSAGE_ATTRIBUTES] = protocol_message_attributes,
	[SCMI_PERF_DOMAIN_ATTRIBUTES] = scmi_perf_domain_attributes,
	[SCMI_PERF_DESCRIBE_LEVELS] = scmi_perf_describe_levels,
	[SCMI_PERF_LEVEL_SET] = scmi_perf_level_set,
	[SCMI_PERF_LEVEL_GET] = scmi_perf_level_get,
};

static bool message_id_is_supported(size_t message_id)
{
	return message_id < ARRAY_SIZE(scmi_perf_handler_table) &&
	       scmi_perf_handler_table[message_id];
}

scmi_msg_handler_t scmi_msg_get_perf_handler(struct scmi_msg *msg)
{
	const size_t array_size = ARRAY_SIZE(scmi_perf_handler_table);
	unsigned int message_id = 0;

	if (msg->message_id >= array_size) {
		DMSG("handle not found %u", msg->message_id);
		return NULL;
	}

	message_id = confine_array_index(msg->message_id, array_size);

	return scmi_perf_handler_table[message_id];
}
