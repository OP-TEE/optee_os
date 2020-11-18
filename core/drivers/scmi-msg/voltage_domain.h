/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef SCMI_MSG_VOLTAGE_DOMAIN_H
#define SCMI_MSG_VOLTAGE_DOMAIN_H

#include <stdint.h>
#include <util.h>

#include "common.h"

#define SCMI_PROTOCOL_VERSION_VOLTAGE_DOMAIN	0x30000

/*
 * Identifiers of the SCMI Clock Management Protocol commands
 */
enum scmi_voltd_command_id {
	SCMI_VOLTAGE_DOMAIN_ATTRIBUTES = 0x3,
	SCMI_VOLTAGE_DESCRIBE_LEVELS = 0x4,
	SCMI_VOLTAGE_CONFIG_SET = 0x5,
	SCMI_VOLTAGE_CONFIG_GET = 0x6,
	SCMI_VOLTAGE_LEVEL_SET = 0x7,
	SCMI_VOLTAGE_LEVEL_GET = 0x8,
};

#define SCMI_VOLTAGE_DOMAIN_COUNT_MASK		GENMASK_32(15, 0)

struct scmi_voltd_protocol_attrs_p2a {
	int32_t status;
	uint32_t attributes;
};

struct scmi_voltd_attributes_a2p {
	uint32_t domain_id;
};

#define SCMI_VOLTAGE_DOMAIN_NAME_MAX		16

struct scmi_voltd_attributes_p2a {
	int32_t status;
	uint32_t attributes;
	char name[SCMI_VOLTAGE_DOMAIN_NAME_MAX];
};

struct scmi_voltd_describe_levels_a2p {
	uint32_t domain_id;
	uint32_t level_index;
};

#define SCMI_VOLTD_LEVELS_REMAINING_MASK	GENMASK_32(31, 16)
#define SCMI_VOLTD_LEVELS_REMAINING_POS		16

#define SCMI_VOLTD_LEVELS_FORMAT_RANGE		1
#define SCMI_VOLTD_LEVELS_FORMAT_LIST		0
#define SCMI_VOLTD_LEVELS_FORMAT_MASK		BIT(12)
#define SCMI_VOLTD_LEVELS_FORMAT_POS		12

#define SCMI_VOLTD_LEVELS_COUNT_MASK		GENMASK_32(11, 0)

#define SCMI_VOLTAGE_DOMAIN_LEVELS_FLAGS(_count, _fmt, _rem_rates) \
	( \
		((_count) & SCMI_VOLTD_LEVELS_COUNT_MASK) | \
		(((_rem_rates) << SCMI_VOLTD_LEVELS_REMAINING_POS) & \
		 SCMI_VOLTD_LEVELS_REMAINING_MASK) | \
		(((_fmt) << SCMI_VOLTD_LEVELS_FORMAT_POS) & \
		 SCMI_VOLTD_LEVELS_FORMAT_MASK) \
	)

struct scmi_voltd_level {
	int32_t mircovolt;
};

struct scmi_voltd_describe_levels_p2a {
	int32_t status;
	uint32_t flags;
	struct scmi_voltd_level voltage[];
};

struct scmi_voltd_level_set_a2p {
	uint32_t domain_id;
	uint32_t flags;
	int32_t voltage_level;
};

struct scmi_voltd_level_set_p2a {
	uint32_t status;
};

struct scmi_voltd_level_get_a2p {
	uint32_t domain_id;
};

struct scmi_voltd_level_get_p2a {
	int32_t status;
	int32_t voltage_level;
};

#define SCMI_VOLTAGE_DOMAIN_CONFIG_MASK		GENMASK_32(3, 0)

struct scmi_voltd_config_set_a2p {
	uint32_t domain_id;
	uint32_t config;
};

struct scmi_voltd_config_set_p2a {
	uint32_t status;
};

struct scmi_voltd_config_get_a2p {
	uint32_t domain_id;
};

struct scmi_voltd_config_get_p2a {
	int32_t status;
	uint32_t config;
};

#ifdef CFG_SCMI_MSG_VOLTAGE_DOMAIN
/*
 * scmi_msg_get_voltd_handler - Return a handler for a voltage domain message
 * @msg - message to process
 * Return a function handler for the message or NULL
 */
scmi_msg_handler_t scmi_msg_get_voltd_handler(struct scmi_msg *msg);
#else
static inline
scmi_msg_handler_t scmi_msg_get_voltd_handler(struct scmi_msg *msg __unused)
{
	return NULL;
}
#endif
#endif /* SCMI_MSG_CLOCK_H */
