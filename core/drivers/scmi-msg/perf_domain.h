/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2015-2020, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2024, STMicroelectronics
 */
#ifndef SCMI_MSG_PERF_DOMAIN_H
#define SCMI_MSG_PERF_DOMAIN_H

#include <stdint.h>
#include <util.h>

#include "common.h"

#define SCMI_PROTOCOL_VERSION_PERF_DOMAIN	0x10000

/*
 * Identifiers of the SCMI Performance Domain Management Protocol commands
 */
enum scmi_perf_domain_command_id {
	SCMI_PERF_DOMAIN_ATTRIBUTES = 0x3,
	SCMI_PERF_DESCRIBE_LEVELS = 0x4,
	SCMI_PERF_LIMITS_SET = 0x5,		/* Not supported */
	SCMI_PERF_LIMITS_GET = 0x6,		/* Not supported */
	SCMI_PERF_LEVEL_SET = 0x7,
	SCMI_PERF_LEVEL_GET = 0x8,
	SCMI_PERF_NOTIFY_LIMITS = 0x9,		/* Not supported */
	SCMI_PERF_NOTIFY_LEVEL = 0xa,		/* Not supported */
};

/*
 * Payloads for SCMI_PROTOCOL_ATTRIBUTES for Performance Domains
 */
#define SCMI_PERF_ATTRIBUTES_POWER_MW_BIT	BIT(16)
#define SCMI_PERF_ATTRIBUTES_NUM_DOMAINS_MASK	GENMASK_32(15, 0)

#define SCMI_PERF_PROTOCOL_ATTRIBUTES(_power_mw, _num_domains) \
	(((_power_mw) ? SCMI_PERF_ATTRIBUTES_POWER_MW_BIT : 0) | \
	 ((_num_domains) & SCMI_PERF_ATTRIBUTES_NUM_DOMAINS_MASK))

struct scmi_perf_protocol_attributes_p2a {
	int32_t status;
	uint32_t attributes;
	uint32_t statistics_address_low;
	uint32_t statistics_address_high;
	uint32_t statistics_len;
};

/*
 * Payloads for SCMI_PERF_DOMAIN_ATTRIBUTES
 */
struct scmi_perf_attributes_a2p {
	uint32_t domain_id;
};

/* Macro for scmi_perf_domain_attributes_p2a:attributes */
#define SCMI_PERF_DOMAIN_ATTRIBUTES_CAN_SET_LEVEL	BIT(30)

/* Macro for scmi_perf_domain_attributes_p2a:rate_limit */
#define SCMI_PERF_DOMAIN_RATE_LIMIT_MASK	GENMASK_32(15, 0)

/* Macro for scmi_perf_domain_attributes_p2a:name */
#define SCMI_PERF_DOMAIN_ATTR_NAME_SZ		16

struct scmi_perf_attributes_p2a {
	int32_t status;
	uint32_t attributes;
	uint32_t rate_limit;
	uint32_t sustained_freq;
	uint32_t sustained_perf_level;
	char name[SCMI_PERF_DOMAIN_ATTR_NAME_SZ];
};

/*
 * Payloads for SCMI_PERF_DESCRIBE_LEVELS
 */
#define SCMI_PERF_LEVEL_ATTRIBUTES_LATENCY_US_MASK	GENMASK_32(15, 0)

struct scmi_perf_level {
	uint32_t performance_level;
	uint32_t power_cost;
	uint32_t attributes;
};

struct scmi_perf_describe_levels_a2p {
	uint32_t domain_id;
	uint32_t level_index;
};

#define SCMI_PERF_NUM_LEVELS_NUM_LEVELS_MASK		GENMASK_32(11, 0)
#define SCMI_PERF_NUM_LEVELS_REMAINING_LEVELS_MASK	GENMASK_32(31, 16)
#define SCMI_PERF_NUM_LEVELS_REMAINING_LEVELS_POS	16

#define SCMI_PERF_NUM_LEVELS(_num_levels, _rem_levels) \
	(((_num_levels) & SCMI_PERF_NUM_LEVELS_NUM_LEVELS_MASK) | \
	 (((_rem_levels) << SCMI_PERF_NUM_LEVELS_REMAINING_LEVELS_POS) & \
	  SCMI_PERF_NUM_LEVELS_REMAINING_LEVELS_MASK))

struct scmi_perf_describe_levels_p2a {
	int32_t status;
	uint32_t num_levels;
	struct scmi_perf_level perf_levels[];
};

/* Payloads for SCMI_PERF_LEVEL_SET */
struct scmi_perf_level_set_a2p {
	uint32_t domain_id;
	uint32_t performance_level;
};

struct scmi_perf_level_set_p2a {
	int32_t status;
};

/* Payloads for SCMI_PERF_LEVEL_GET */
struct scmi_perf_level_get_a2p {
	uint32_t domain_id;
};

struct scmi_perf_level_get_p2a {
	int32_t status;
	uint32_t performance_level;
};

#ifdef CFG_SCMI_MSG_PERF_DOMAIN
/*
 * scmi_msg_get_perf_handler - Return a handler for a performance domain message
 * @msg - message to process
 * Return a function handler for the message or NULL
 */
scmi_msg_handler_t scmi_msg_get_perf_handler(struct scmi_msg *msg);
#else
static inline
scmi_msg_handler_t scmi_msg_get_perf_handler(struct scmi_msg *msg __unused)
{
	return NULL;
}
#endif
#endif /* SCMI_MSG_PERF_DOMAIN_H */
