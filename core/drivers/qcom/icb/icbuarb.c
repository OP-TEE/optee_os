// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <string.h>

#include <initcall.h>
#include <kernel/spinlock.h>
#include <trace.h>
#include <util.h>

#include <drivers/qcom/cmd_db/cmd_db.h>
#include <drivers/qcom/rpmh/rpmh_client.h>

#include <drivers/qcom/icb/icbuarb.h>
#include "icbuarbi.h"

#define BCM_VOTETABLE_COMMIT_BMSK		0x40000000
#define BCM_VOTETABLE_VOTE_VALID_BMSK		0x20000000
#define BCM_VOTETABLE_VOTE_X_SHFT		0xe
#define BCM_VOTETABLE_VOTE_X_MAX		0x3fff
#define BCM_VOTETABLE_VOTE_Y_SHFT		0x0
#define BCM_VOTETABLE_VOTE_Y_MAX		0x3fff

#define ICB_REQUEST_LIST_SIZE			10

/* Commands a single RPMH TCS can hold; must flush at this boundary. */
#define ICB_RPMH_MAX_TCS_SIZE			16

#ifndef ICB_MAX_CLIENTS
#define ICB_MAX_CLIENTS				CFG_QCOM_ICB_MAX_CLIENTS
#endif

#ifndef ICB_REQ_POOL_ENTRIES
#define ICB_REQ_POOL_ENTRIES	(ICB_MAX_CLIENTS * ICB_REQUEST_LIST_SIZE)
#endif

static struct icb_client   icb_client_backing[ICB_MAX_CLIENTS];
static struct icb_bw_req  *icb_req_backing[ICB_REQ_POOL_ENTRIES];

static uint32_t icb_req_pool_next;

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

static struct icb_bw_req **icb_req_pool_alloc_n(uint32_t count)
{
	struct icb_bw_req **slice;

	if (icb_req_pool_next + count > ICB_REQ_POOL_ENTRIES)
		return NULL;

	slice = &icb_req_backing[icb_req_pool_next];
	icb_req_pool_next += count;
	return slice;
}

static inline uint64_t bw_scale(uint64_t bw, uint64_t dividend,
				uint64_t divisor)
{
	return DIV_ROUND_UP(bw * dividend, divisor);
}

/* BCM auxiliary data layout in the Command DB. */
struct cmd_db_bcm_aux {
	uint32_t	bw_unit;
	uint16_t	bcm_port;
	uint8_t		clk_id;
};

static struct icb_info *info;

static struct rpmh_client *rpmh_handle;
static struct icb_hw_node *commit_queue;
static unsigned int icb_lock;

static bool add_hw_node_request(struct icb_hw_request_list *req_list,
				struct icb_bw_req *req,
				uint32_t width,
				uint32_t ports)
{
	if (req_list->num_entries >= req_list->list_size)
		return false;

	req_list->requests[req_list->num_entries].req   = req;
	req_list->requests[req_list->num_entries].width = width;
	req_list->requests[req_list->num_entries].ports = ports;
	req_list->num_entries++;
	return true;
}

static bool add_sw_node_request(struct icb_bw_request_list *req_list,
				struct icb_bw_req *req)
{
	if (req_list->num_entries == req_list->list_size) {
		struct icb_bw_req **old_list = req_list->requests;
		struct icb_bw_req **new_list;
		uint32_t new_count = req_list->list_size +
				     ICB_REQUEST_LIST_SIZE;

		/* A node's list can never need more entries than there are clients. */
		if (new_count > ICB_MAX_CLIENTS)
			new_count = ICB_MAX_CLIENTS;

		if (new_count == req_list->list_size)
			return false;

		new_list = icb_req_pool_alloc_n(new_count);
		if (!new_list)
			return false;

		EMSG("ICB: req pool grown: %u -> %u entries",
		     req_list->list_size, new_count);

		if (old_list) {
			memcpy(new_list, old_list,
			       req_list->list_size *
			       sizeof(struct icb_bw_req *));
		}
		req_list->requests = new_list;
		req_list->list_size = new_count;
	}

	req_list->requests[req_list->num_entries++] = req;
	return true;
}

static void remove_sw_node_request(struct icb_bw_request_list *req_list,
				   struct icb_bw_req *req)
{
	uint32_t i;

	for (i = 0; i < req_list->num_entries; i++) {
		if (req_list->requests[i] == req)
			break;
	}

	if (i >= req_list->num_entries)
		return;

	if (i < (req_list->num_entries - 1)) {
		memmove(&req_list->requests[i],
			&req_list->requests[i + 1],
			(req_list->num_entries - i - 1) *
			sizeof(struct icb_bw_req *));
	}

	req_list->num_entries--;
}

static void remove_client_requests(struct icb_client *handle)
{
	uint32_t i;
	struct icb_route *route = handle->route;

	for (i = 0; i < route->num_hops; i++) {
		struct icb_pair *pair = &route->hops[i];

		if (pair->master) {
			remove_sw_node_request(&pair->master->request_list,
					       &handle->curr_req);
		}
		if (pair->slave) {
			remove_sw_node_request(&pair->slave->request_list,
					       &handle->curr_req);
		}
	}
}

static void aggregate_sw_node(struct icb_bw_request_list *req_list,
			      struct icb_bw_req *state)
{
	uint32_t i;
	uint64_t ib = 0, ab = 0;

	for (i = 0; i < req_list->num_entries; i++) {
		ib = MAX(ib, req_list->requests[i]->ib);
		ab += req_list->requests[i]->ab;
	}

	state->ib = ib;
	state->ab = ab;
}

static void aggregate_hw_node(struct icb_hw_node *hw_node)
{
	uint32_t i;
	uint64_t ib = 0, ab = 0;

	for (i = 0; i < hw_node->request_list.num_entries; i++) {
		struct icb_hw_request *request =
			&hw_node->request_list.requests[i];

		if (hw_node->type == ICB_HW_NODE_KIND_BANDWIDTH) {
			ib = MAX(ib, bw_scale(request->req->ib,
					      hw_node->width,
					      request->width));
			ab = MAX(ab, bw_scale(request->req->ab,
					      hw_node->width,
					      request->width * request->ports));
		} else {
			ib = MAX(ib, request->req->ib);
			ab = MAX(ab, request->req->ab);
		}
	}

	hw_node->state.ib = ib;
	hw_node->state.ab = ab;

	if (hw_node->type == ICB_HW_NODE_KIND_BANDWIDTH) {
		uint64_t scaled_ab = DIV_ROUND_UP(hw_node->state.ab,
						  hw_node->bw_unit);
		uint64_t scaled_ib = DIV_ROUND_UP(hw_node->state.ib,
						  hw_node->bw_unit);
		uint64_t ceil_ab = (scaled_ab <=
				    (uint64_t)BCM_VOTETABLE_VOTE_X_MAX) ?
				   scaled_ab :
				   (uint64_t)BCM_VOTETABLE_VOTE_X_MAX;
		uint64_t ceil_ib = (scaled_ib <=
				    (uint64_t)BCM_VOTETABLE_VOTE_Y_MAX) ?
				   scaled_ib :
				   (uint64_t)BCM_VOTETABLE_VOTE_Y_MAX;

		hw_node->vote = (uint32_t)
			((ceil_ab << BCM_VOTETABLE_VOTE_X_SHFT) |
			 (ceil_ib << BCM_VOTETABLE_VOTE_Y_SHFT));
	} else {
		if (hw_node->state.ab || hw_node->state.ib)
			hw_node->vote = hw_node->output;
		else
			hw_node->vote = 0;
	}

	if (hw_node->vote)
		hw_node->vote |= BCM_VOTETABLE_VOTE_VALID_BMSK;
}

static void queue_hw_node_request(struct icb_hw_node *hw_node)
{
	struct icb_hw_node *iter, *prev;

	for (iter = commit_queue, prev = NULL;
	     iter;
	     prev = iter, iter = iter->next) {
		if (hw_node->clk_id < iter->clk_id)
			break;
	}

	if (iter == commit_queue) {
		hw_node->next = commit_queue;
		commit_queue  = hw_node;
	} else {
		prev->next    = hw_node;
		hw_node->next = iter;
	}
}

static void commit_hw_requests(void)
{
	struct icb_hw_node *bcm;
	uint32_t num_cmds = 0;

	if (!commit_queue)
		return;

	while (commit_queue) {
		uint32_t address, data, msg_id = 0;
		bool completion = false;

		bcm = commit_queue;
		commit_queue = bcm->next;
		bcm->next = NULL;

		num_cmds++;
		address = bcm->hw_id;
		data    = bcm->vote;

		if (!commit_queue ||
		    bcm->clk_id != commit_queue->clk_id ||
		    num_cmds == ICB_RPMH_MAX_TCS_SIZE) {
			data      |= BCM_VOTETABLE_COMMIT_BMSK;
			completion = true;
			num_cmds   = 0;
		}

		rpmh_send_command(rpmh_handle, RPMH_SET_ACTIVE, completion,
				  address, data, &msg_id);
	}
}

static bool icbuarb_hw_init(void)
{
	uint32_t i, node;

	for (i = 0; i < info->num_hw_nodes; i++) {
		struct icb_hw_node *hw_node = info->hw_nodes[i];
		struct cmd_db_bcm_aux bcm_aux;
		size_t len = sizeof(bcm_aux);

		if (cmd_db_get_aux(hw_node->name, (uint8_t *)&bcm_aux,
				   &len) != TEE_SUCCESS) {
			return false;
		}

		if (cmd_db_get_addr(hw_node->name, &hw_node->hw_id) !=
		    TEE_SUCCESS) {
			return false;
		}

		hw_node->width   = bcm_aux.bcm_port;
		hw_node->bw_unit = bcm_aux.bw_unit;
		hw_node->clk_id  = bcm_aux.clk_id;
		hw_node->is_dirty = false;
	}

	rpmh_handle = rpmh_create_handle(RSC_DRV_SECURE, "ICB");
	if (!rpmh_handle)
		return false;

	for (i = 0; i < info->num_masters; i++) {
		struct icb_master *master = info->masters[i];

		for (node = 0; node < master->num_hw_nodes; node++) {
			struct icb_hw_node *bcm = master->hw_nodes[node];

			add_hw_node_request(&bcm->request_list,
					    &master->state,
					    master->width,
					    master->ports);
		}
	}

	for (i = 0; i < info->num_slaves; i++) {
		struct icb_slave *slave = info->slaves[i];

		for (node = 0; node < slave->num_hw_nodes; node++) {
			struct icb_hw_node *bcm = slave->hw_nodes[node];

			add_hw_node_request(&bcm->request_list,
					    &slave->state,
					    slave->width,
					    slave->ports);
		}
	}

	return true;
}

static void icbuarb_destroy_client_internal(struct icb_client *handle)
{
	remove_client_requests(handle);
	handle->in_use = false;
}

static TEE_Result qti_icbuarb_init(void)
{
	info = icbuarb_target_get_info();
	if (!info) {
		IMSG("ICB: micro-arbiter initialization error");
		return TEE_SUCCESS;
	}

	if (info->num_routes > ICB_MAX_CLIENTS) {
		EMSG("ICB: num_routes (%u) exceeds ICB_MAX_CLIENTS (%u)",
		     info->num_routes, (uint32_t)ICB_MAX_CLIENTS);
		IMSG("ICB: micro-arbiter initialization error");
		return TEE_SUCCESS;
	}

	if (!(icbuarb_hw_init() && icbuarb_target_init(info)))
		IMSG("ICB: micro-arbiter initialization error");

	return TEE_SUCCESS;
}
driver_init(qti_icbuarb_init);

struct icb_client *icbuarb_create_client(enum icbid_master master,
					 enum icbid_slave slave)
{
	uint32_t i;
	struct icb_client *handle = NULL;

	if (!info)
		return NULL;

	for (i = 0; i < info->num_routes; i++) {
		if (info->routes[i] &&
		    info->routes[i]->master == master &&
		    info->routes[i]->slave  == slave) {
			break;
		}
	}

	if (i >= info->num_routes)
		return NULL;

	handle = icb_client_pool_alloc();
	if (!handle)
		return NULL;

	handle->master = master;
	handle->slave  = slave;
	handle->route  = info->routes[i];
	memset(&handle->curr_req, 0, sizeof(struct icb_bw_req));

	cpu_spin_lock(&icb_lock);

	for (i = 0; i < handle->route->num_hops; i++) {
		if (handle->route->hops[i].master) {
			struct icb_master *m = handle->route->hops[i].master;

			if (!add_sw_node_request(&m->request_list,
						 &handle->curr_req)) {
				break;
			}
		}
		if (handle->route->hops[i].slave) {
			struct icb_slave *s = handle->route->hops[i].slave;

			if (!add_sw_node_request(&s->request_list,
						 &handle->curr_req)) {
				break;
			}
		}
	}

	if (i < handle->route->num_hops) {
		EMSG("ICB: create_client failed: master %u slave %u ran out of req pool entries",
		     (unsigned int)master, (unsigned int)slave);
		icbuarb_destroy_client_internal(handle);
		handle = NULL;
	}

	cpu_spin_unlock(&icb_lock);

	return handle;
}

bool icbuarb_issue_request(struct icb_client *handle, struct icb_bw_req *req)
{
	uint32_t i, node;
	struct icb_route *route;
	bool ret = false;

	if (!handle || !req || !info)
		return false;

	if (!handle->route)
		return false;

	cpu_spin_lock(&icb_lock);

	handle->curr_req = *req;
	route = handle->route;

	for (i = 0; i < route->num_hops; i++) {
		if (route->hops[i].master) {
			struct icb_master *m = route->hops[i].master;

			aggregate_sw_node(&m->request_list, &m->state);
			for (node = 0; node < m->num_hw_nodes; node++)
				m->hw_nodes[node]->is_dirty = true;
		}
		if (route->hops[i].slave) {
			struct icb_slave *s = route->hops[i].slave;

			aggregate_sw_node(&s->request_list, &s->state);
			for (node = 0; node < s->num_hw_nodes; node++)
				s->hw_nodes[node]->is_dirty = true;
		}
	}

	for (node = 0; node < info->num_hw_nodes; node++) {
		struct icb_hw_node *hw_node = info->hw_nodes[node];

		if (hw_node->is_dirty) {
			aggregate_hw_node(hw_node);
			queue_hw_node_request(hw_node);
			hw_node->is_dirty = false;
		}
	}

	commit_hw_requests();
	ret = true;

	cpu_spin_unlock(&icb_lock);

	return ret;
}

bool icbuarb_destroy_client(struct icb_client *handle)
{
	struct icb_bw_req req;
	bool ret = false;

	if (!handle)
		return false;

	memset(&req, 0, sizeof(req));
	if (!icbuarb_issue_request(handle, &req))
		return false;

	cpu_spin_lock(&icb_lock);
	icbuarb_destroy_client_internal(handle);
	ret = true;
	cpu_spin_unlock(&icb_lock);

	return ret;
}
