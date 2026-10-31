/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QTI_ICBUARBI_H
#define QTI_ICBUARBI_H

#ifdef CFG_QCOM_ICB_RPM
#include "icbuarbi_rpm.h"
#else

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <util.h>

#include <drivers/qcom/icb/icbid.h>
#include <drivers/qcom/icb/icbuarb.h>

struct icb_client;

struct icb_hw_request {
	struct icb_bw_req	*req;
	uint32_t		width;
	uint32_t		ports;
};

struct icb_hw_request_list {
	uint32_t		num_entries;
	uint32_t		list_size;
	struct icb_hw_request	*requests;
};

enum icb_hw_node_kind {
	ICB_HW_NODE_KIND_BANDWIDTH = 0,
	ICB_HW_NODE_KIND_LATENCY,
	ICB_HW_NODE_KIND_VECTOR,
	ICB_HW_NODE_KIND_COUNT,
	ICB_HW_NODE_KIND_SIZE = 0x7FFFFFF
};

struct icb_hw_node {
	struct icb_hw_node		*next;
	const char			*name;
	enum icb_hw_node_kind		type;
	uint32_t			hw_id;
	uint32_t			width;
	uint32_t			bw_unit;
	uint32_t			clk_id;
	bool				is_dirty;
	uint32_t			vote;
	struct icb_bw_req		state;
	struct icb_hw_request_list	request_list;
	uint32_t			output;
};

struct icb_bw_request_list {
	uint32_t		num_entries;
	uint32_t		list_size;
	struct icb_bw_req	**requests;
};

struct icb_master {
	enum icbid_master		id;
	uint32_t			width;
	uint32_t			ports;
	struct icb_bw_req		state;
	struct icb_bw_request_list	request_list;
	uint32_t			num_hw_nodes;
	struct icb_hw_node		**hw_nodes;
};

struct icb_slave {
	enum icbid_slave		id;
	uint32_t			width;
	uint32_t			ports;
	struct icb_bw_req		state;
	struct icb_bw_request_list	request_list;
	uint32_t			num_hw_nodes;
	struct icb_hw_node		**hw_nodes;
};

struct icb_pair {
	struct icb_master	*master;
	struct icb_slave	*slave;
};

struct icb_route {
	enum icbid_master	master;
	enum icbid_slave	slave;
	uint32_t		num_hops;
	struct icb_pair		*hops;
};

struct icb_info {
	uint32_t		 num_routes;
	struct icb_route	**routes;
	uint32_t		 num_masters;
	struct icb_master	**masters;
	uint32_t		 num_slaves;
	struct icb_slave	**slaves;
	uint32_t		 num_hw_nodes;
	struct icb_hw_node	**hw_nodes;
};

struct icb_client {
	bool			in_use;
	enum icbid_master	master;
	enum icbid_slave	slave;
	struct icb_route	*route;
	struct icb_bw_req	curr_req;
};

struct icb_info *icbuarb_target_get_info(void);
bool icbuarb_target_init(struct icb_info *info);

#endif /* CFG_QCOM_ICB_RPM */
#endif /* QTI_ICBUARBI_H */
