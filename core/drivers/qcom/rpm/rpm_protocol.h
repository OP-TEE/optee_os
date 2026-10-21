/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Classic RPM wire protocol: GLink command IDs, the RPM message
 * packet header, and the MSG RAM table-of-contents (ToC) layout.
 */

#ifndef __RPM_PROTOCOL_H__
#define __RPM_PROTOCOL_H__

#include <assert.h>
#include <compiler.h>
#include <stdint.h>
#include <util.h>

#define RPM_GLINK_CMD_VERSION_REQ	0x0
#define RPM_GLINK_CMD_VERSION_ACK	0x1
#define RPM_GLINK_CMD_OPEN_CHANNEL	0x2
#define RPM_GLINK_CMD_CLOSE_CHANNEL	0x3 
#define RPM_GLINK_CMD_OPEN_CHANNEL_ACK	0x4
#define RPM_GLINK_CMD_TX_DATA		0x9
#define RPM_GLINK_CMD_CLOSE_CHANNEL_ACK	0xB
#define RPM_GLINK_CMD_TX_SIGNALS	0xF

/* cmd = cmd_id | (channel_id << 16); only channel 0 ("rpm") is used. */
#define RPM_GLINK_CHANNEL_ID_SHIFT	16
#define RPM_GLINK_CMD_ID_MASK		0xFFFF

static inline uint32_t rpm_glink_make_cmd(uint32_t cmd_id,
					   uint32_t channel_id)
{
	return (cmd_id & RPM_GLINK_CMD_ID_MASK) |
	       (channel_id << RPM_GLINK_CHANNEL_ID_SHIFT);
}

static inline uint32_t rpm_glink_cmd_id(uint32_t cmd)
{
	return cmd & RPM_GLINK_CMD_ID_MASK;
}

static inline uint32_t rpm_glink_channel_id(uint32_t cmd)
{
	return cmd >> RPM_GLINK_CHANNEL_ID_SHIFT;
}

/*
 * The one and only channel/remote host this driver talks to. Must NOT
 * be 0: the reference GLink core reserves lcid 0 as
 * GLINK_INVALID_CID and starts real allocation at 1
 * (glink_core_internal.c's free_lcid init), so RPM firmware rejects
 * (silently drops, no ACK) an OPEN_CHANNEL naming lcid 0. This port
 * never implements a real allocator -- 1 is the fixed value the
 * reference allocator would assign to the first (and only) channel.
 */
#define RPM_GLINK_CHANNEL_ID		1

#define RPM_GLINK_VERSION_SHIFT		16

static inline uint32_t rpm_glink_make_version_cmd(uint32_t cmd_id,
						   uint32_t version)
{
	return (cmd_id & RPM_GLINK_CMD_ID_MASK) |
	       (version << RPM_GLINK_VERSION_SHIFT);
}

static inline uint32_t rpm_glink_version(uint32_t cmd)
{
	return cmd >> RPM_GLINK_VERSION_SHIFT;
}

#define RPM_TOC_SIZE			0x100
#define RPM_TOC_MAGIC			0x67727430 /* "grt0" */

#define RPM_TOC_MAGIC_IDX		0
#define RPM_TOC_LENGTH_IDX		1
#define RPM_TOC_ENTRIES_IDX		2

struct rpm_toc_entry {
	uint32_t fifo_id;
	uint32_t fifo_offset;
	uint32_t fifo_size;
};

#define RPM_FIFO_ID_TZ2R		0x747A3272 /* TZ -> RPM (tx) */
#define RPM_FIFO_ID_R2TZ		0x7232747A /* RPM -> TZ (rx) */

struct rpm_pkt_header {
	uint32_t service;
	uint32_t size;
	uint32_t msg_id;
	uint32_t set;
	uint32_t resource_type;
	uint32_t resource_id;
	uint32_t data_len;
} __packed;

static_assert(sizeof(struct rpm_pkt_header) == 7 * sizeof(uint32_t));

enum rpm_set {
	RPM_SET_ACTIVE = 0,
	RPM_SET_SLEEP = 1, /* unused, listed for completeness */
};

enum rpm_service {
	RPM_SERVICE_REQUEST = 0x00716572,  /* "req\0" */
	RPM_SERVICE_SYSTEMDB = 0x00626473, /* "sdb\0", unused */
};

#define RPM_KVP_KEY_REQ			0x00716572 /* "req" */
#define RPM_KVP_KEY_MSG_ID		0x2367736d /* "msg$g" ("MSG__KEY") */
#define RPM_KVP_KEY_ERR			0x00727265 /* "err" */

#define RPM_GLINK_LOCAL_VERSION		1
#define RPM_GLINK_LOCAL_FEATURES	0

#endif /* __RPM_PROTOCOL_H__ */
