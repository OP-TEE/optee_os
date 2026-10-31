/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef QTI_ICBUARBI_RPM_H
#define QTI_ICBUARBI_RPM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <drivers/qcom/icb/icbid_rpm.h>
#include <drivers/qcom/icb/icbuarb_rpm.h>

#include <drivers/clk_qcom.h>

struct icb_clock {
	const char				*name;
	const struct qcom_clk_rpm_resource	*id;
	bool					 dirty;
	uint32_t				 state;	/* Current clock request in KHz */
	uint32_t				 num_requests;
	uint32_t				*requests;
};

struct icb_clock_handle {
	struct icb_clock	*clock;
	uint32_t		 index;
};

struct icb_master {
	enum icbid_master	  id;
	struct icb_bw_req	  curr_req;
	bool			  remote;
	uint32_t		  width;
	uint32_t		  num_clocks;
	struct icb_clock_handle	 *clocks;
};

struct icb_slave {
	enum icbid_slave	  id;
	struct icb_bw_req	  curr_req;
	bool			  remote;
	uint32_t		  width;
	uint32_t		  num_clocks;
	struct icb_clock_handle	 *clocks;
};

struct icb_pair {
	struct icb_master	*master;
	struct icb_slave	*slave;
};

struct icb_route {
	enum icbid_master	 master;
	enum icbid_slave	 slave;
	uint32_t		 num_hops;
	struct icb_pair		*hops;
};

struct icb_info {
	uint32_t		  num_routes;
	struct icb_route	**routes;
	uint32_t		  num_clocks;
	struct icb_clock	**clocks;
};

struct icb_client {
	bool			 in_use;
	enum icbid_master	 master;
	enum icbid_slave	 slave;
	struct icb_route	*route;
	struct icb_bw_req	 curr_req;
};

struct icb_info *icbuarb_target_get_info(void);
bool icbuarb_target_init(struct icb_info *info);

#endif /* QTI_ICBUARBI_RPM_H */
