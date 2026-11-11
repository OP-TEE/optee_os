// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stdint.h>
#include <string.h>

#include <initcall.h>
#include <kernel/mutex.h>
#include <trace.h>
#include <util.h>

#include <drivers/qcom/icb/icbuarb.h>

#include "icb_rpm_types.h"
#include "icbuarbi.h"

#include <drivers/qcom/rpm/rpm_client.h>

static inline uint32_t bw_to_clk_freq_khz(uint64_t bw, uint32_t width)
{
	uint64_t khz;

	if (!width)
		return 0;

	khz = DIV_ROUND_UP(bw, (uint64_t)width * 1000);

	return (khz <= UINT32_MAX) ? (uint32_t)khz : UINT32_MAX;
}

/* Override via CFG_QCOM_ICB_MAX_CLIENTS in platform.mk */
#ifndef ICB_MAX_CLIENTS
#define ICB_MAX_CLIENTS		CFG_QCOM_ICB_MAX_CLIENTS
#endif

/* RPM message structure. */
struct icb_rpm_msg {
	uint32_t	key;
	uint32_t	size;
	uint64_t	value;
};

static struct icb_client icb_client_backing[ICB_MAX_CLIENTS];

static struct icb_client *icb_client_pool_alloc(void)
{
	uint32_t i;

	for (i = 0; i < ICB_MAX_CLIENTS; i++) {
		if (!icb_client_backing[i].in_use) {
			icb_client_backing[i].in_use = true;
			return &icb_client_backing[i];
		}
	}

	return NULL;
}

static struct icb_info *info;
static struct mutex icb_lock = MUTEX_INITIALIZER;

static bool init_clocks(void)
{
	uint32_t i;

	for (i = 0; i < info->num_clocks; i++) {
		struct icb_clock *clock = info->clocks[i];

		if (qcom_clk_rpm_get_id(clock->name, &clock->id)) {
			return false;
		}
	}

	return true;
}

static void issue_clock_request(struct icb_clock_handle *handle,
				  uint32_t request)
{
	struct icb_clock *clock = handle->clock;

	clock->requests[handle->index] = request;
	clock->dirty = true;
}

static bool process_clocks(void)
{
	uint32_t clk, i;
	bool ret = true;

	for (clk = 0; clk < info->num_clocks; clk++) {
		struct icb_clock *clock = info->clocks[clk];

		if (clock->dirty) {
			uint32_t max_req = 0;

			for (i = 0; i < clock->num_requests; i++) {
				max_req = MAX(max_req, clock->requests[i]);
			}
			clock->state = max_req;
			if (qcom_clk_rpm_request(clock->id, clock->state))
				ret = false;

			clock->dirty = false;
		}
	}

	return ret;
}

static TEE_Result qti_icbuarb_init(void)
{
	info = icbuarb_target_get_info();
	if (!info) {
		IMSG("ICB: micro-arbiter initialization error");
		return TEE_SUCCESS;
	}

	if (!(init_clocks() && icbuarb_target_init(info))) {
		IMSG("ICB: micro-arbiter initialization error");
		info = NULL;
	}

	return TEE_SUCCESS;
}
driver_init(qti_icbuarb_init);

struct icb_client *icbuarb_create_client(enum icbid_master master,
					 enum icbid_slave slave)
{
	uint32_t i;
	struct icb_client *handle = NULL;

	if (!info) {
		return NULL;
	}

	for (i = 0; i < info->num_routes; i++) {
		if (info->routes[i] &&
		    info->routes[i]->master == master &&
		    info->routes[i]->slave  == slave) {
			break;
		}
	}

	if (i >= info->num_routes) {
		return NULL;
	}

	mutex_lock(&icb_lock);

	handle = icb_client_pool_alloc();

	mutex_unlock(&icb_lock);

	if (!handle) {
		return NULL;
	}

	handle->master = master;
	handle->slave  = slave;
	handle->route  = info->routes[i];
	memset(&handle->curr_req, 0, sizeof(struct icb_bw_req));

	return handle;
}

static void rpm_update_master(struct icb_master *master,
			      struct icb_client *client,
			      struct icb_bw_req *req, bool *ok)
{
	master->curr_req.ab -= client->curr_req.ab;
	master->curr_req.ab += req->ab;

	if (master->remote) {
		struct icb_rpm_msg rpm_msg = {
			.key   = ICB_MASTER_FIELD_BW,
			.size  = sizeof(rpm_msg.value),
			.value = master->curr_req.ab,
		};

		if (ubsp_rpm_send(QCOM_RPM_BUS_MASTER_REQ, master->id,
				  QCOM_RPM_ACTIVE_SET, (uint8_t *)&rpm_msg,
				  sizeof(rpm_msg)))
			*ok = false;
	}

	if (master->num_clocks > 0) {
		uint32_t request = bw_to_clk_freq_khz(master->curr_req.ab,
						       master->width);
		uint32_t clk;

		for (clk = 0; clk < master->num_clocks; clk++)
			issue_clock_request(&master->clocks[clk], request);
	}
}

static void rpm_update_slave(struct icb_slave *slave,
			     struct icb_client *client,
			     struct icb_bw_req *req, bool *ok)
{
	slave->curr_req.ab -= client->curr_req.ab;
	slave->curr_req.ab += req->ab;

	if (slave->remote) {
		struct icb_rpm_msg rpm_msg = {
			.key   = ICB_SLAVE_FIELD_BW,
			.size  = sizeof(rpm_msg.value),
			.value = slave->curr_req.ab,
		};

		if (ubsp_rpm_send(QCOM_RPM_BUS_SLAVE_REQ, slave->id,
				  QCOM_RPM_ACTIVE_SET, (uint8_t *)&rpm_msg,
				  sizeof(rpm_msg)))
			*ok = false;
	}

	if (slave->num_clocks > 0) {
		uint32_t request = bw_to_clk_freq_khz(slave->curr_req.ab,
						       slave->width);
		uint32_t clk;

		for (clk = 0; clk < slave->num_clocks; clk++)
			issue_clock_request(&slave->clocks[clk], request);
	}
}

bool icbuarb_issue_request(struct icb_client *handle, struct icb_bw_req *req)
{
	bool ret = false;
	struct icb_client *client = handle;
	struct icb_route *route;

	if (!info || !handle || !req) {
		return false;
	}

	mutex_lock(&icb_lock);

	route = client->route;

	if (route) {
		uint32_t i;
		bool ok = true;

		for (i = 0; i < route->num_hops; i++) {
			if (route->hops[i].master)
				rpm_update_master(route->hops[i].master,
						  client, req, &ok);

			if (route->hops[i].slave)
				rpm_update_slave(route->hops[i].slave,
						 client, req, &ok);

			if (!process_clocks())
				ok = false;
		}

		client->curr_req = *req;
		ret = ok;
	}

	mutex_unlock(&icb_lock);

	return ret;
}

bool icbuarb_destroy_client(struct icb_client *handle)
{
	struct icb_bw_req req;

	if (!handle) {
		return false;
	}

	memset(&req, 0, sizeof(req));

	if (!icbuarb_issue_request(handle, &req)) {
		return false;
	}

	mutex_lock(&icb_lock);
	handle->in_use = false;
	mutex_unlock(&icb_lock);

	return true;
}
