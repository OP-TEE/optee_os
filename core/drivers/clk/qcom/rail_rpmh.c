// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/cmd_db/cmd_db.h>
#include <drivers/qcom/rpmh/rpmh_client.h>
#include <kernel/mutex.h>
#include <tee_api_types.h>

#include "rail_vote.h"

#define RPMH_RAIL_HLVL_MAX	32

#define RPMH_RAIL_HLVL_INVALID	0xFFFFFFFF

/*
 * A rail's own hlvl table and last-applied hlvl -- cx and mx never
 * share a mapping.
 */
struct rpmh_rail_hlvl {
	uint32_t addr;
	uint16_t corners[RPMH_RAIL_HLVL_MAX];	/* ascending */
	size_t num_hlvls;
	uint32_t voted_hlvl;	/* hlvl applied; INVALID if unknown/partial */
};

struct rpmh_rail {
	struct mutex lock;	/* serialises the vote + tracking state */
	struct rpmh_client *rpmh;
	bool ready;
	struct rpmh_rail_hlvl cx;
	struct rpmh_rail_hlvl mx;	/* .addr stays 0 if none */
	/*
	 * Refcount per corner requested, indexed via cx's table (always
	 * present, unlike mx). Demand tracking only -- both rails are still
	 * voted independently in rpmh_rail_apply().
	 */
	uint16_t votes[RPMH_RAIL_HLVL_MAX];
};

static struct rpmh_rail rpmh_rail = {
	.lock = MUTEX_INITIALIZER,
};

/* Loads one rail's own hlvl table; @hlvl->addr stays 0 on any failure. */
static TEE_Result rpmh_hlvl_load(const char *res_id,
				 struct rpmh_rail_hlvl *hlvl)
{
	size_t len = sizeof(hlvl->corners);
	TEE_Result res = TEE_SUCCESS;

	hlvl->addr = 0;

	res = cmd_db_get_addr(res_id, &hlvl->addr);
	if (res)
		return res;

	res = cmd_db_get_aux(res_id, (uint8_t *)hlvl->corners, &len);
	if (res) {
		hlvl->addr = 0;
		return res;
	}

	hlvl->num_hlvls = len / sizeof(hlvl->corners[0]);

	while (hlvl->num_hlvls > 1 && hlvl->corners[hlvl->num_hlvls - 1] == 0)
		hlvl->num_hlvls--;

	if (!hlvl->num_hlvls) {
		hlvl->addr = 0;
		return TEE_ERROR_BAD_STATE;
	}

	hlvl->voted_hlvl = RPMH_RAIL_HLVL_INVALID;

	return TEE_SUCCESS;
}

/*
 * Called once from clocks_register(); early_init() has already
 * brought up cmd_db/rpmh by driver_init time.
 */
TEE_Result rail_vote_init(void)
{
	struct rpmh_rail *r = &rpmh_rail;
	TEE_Result res = TEE_SUCCESS;

	if (r->ready)
		return TEE_SUCCESS;

	if (!r->rpmh) {
		r->rpmh = rpmh_create_handle(RSC_DRV_SECURE, "rail");
		if (!r->rpmh)
			return TEE_ERROR_GENERIC;
	}

	res = rpmh_hlvl_load("cx.lvl", &r->cx);
	if (res)
		return res;

	/* MX is optional; some chips have none. */
	rpmh_hlvl_load("mx.lvl", &r->mx);

	r->ready = true;

	return TEE_SUCCESS;
}

/* Ceiling match against @hlvl's own table; requires corners[] ascending. */
static TEE_Result rpmh_vlvl_to_hlvl(struct rpmh_rail_hlvl *hlvl,
				    uint16_t corner, uint32_t *out)
{
	size_t i = 0;

	for (i = 0; i < hlvl->num_hlvls; i++) {
		if (hlvl->corners[i] >= corner) {
			*out = i;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

/* Resolves @corner against this rail's own table and applies it if changed. */
static TEE_Result rpmh_hlvl_apply(struct rpmh_client *rpmh,
				  struct rpmh_rail_hlvl *hlvl,
				  uint16_t corner)
{
	uint32_t new_hlvl = 0;
	uint32_t req_id = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!hlvl->addr)
		return TEE_SUCCESS;

	res = rpmh_vlvl_to_hlvl(hlvl, corner, &new_hlvl);
	if (res)
		return res;

	if (new_hlvl == hlvl->voted_hlvl)
		return TEE_SUCCESS;

	hlvl->voted_hlvl = RPMH_RAIL_HLVL_INVALID;

	res = rpmh_send_command(rpmh, RPMH_SET_ACTIVE, true, hlvl->addr,
				new_hlvl, &req_id);
	if (res)
		return res;
	rpmh_barrier_single(rpmh, req_id);

	hlvl->voted_hlvl = new_hlvl;

	return TEE_SUCCESS;
}

static TEE_Result rpmh_rail_apply(uint16_t corner)
{
	struct rpmh_rail *r = &rpmh_rail;
	TEE_Result res = TEE_SUCCESS;

	res = rpmh_hlvl_apply(r->rpmh, &r->cx, corner);
	if (res)
		return res;

	return rpmh_hlvl_apply(r->rpmh, &r->mx, corner);
}

/* Highest corner (from cx's own table) any voter currently needs. */
static uint16_t rpmh_rail_peak(void)
{
	struct rpmh_rail *r = &rpmh_rail;
	size_t peak = 0;
	size_t i = 0;

	for (i = 0; i < r->cx.num_hlvls; i++)
		if (r->votes[i])
			peak = i;

	return r->cx.corners[peak];
}

static TEE_Result rpmh_rail_move(uint16_t old_corner, uint16_t new_corner)
{
	struct rpmh_rail *r = &rpmh_rail;
	uint32_t old_hlvl = 0;
	uint32_t new_hlvl = 0;
	TEE_Result res = TEE_SUCCESS;

	if (new_corner) {
		res = rpmh_vlvl_to_hlvl(&r->cx, new_corner, &new_hlvl);
		if (res)
			return res;
	}

	if (old_corner) {
		res = rpmh_vlvl_to_hlvl(&r->cx, old_corner, &old_hlvl);
		if (res)
			return res;

		if (!r->votes[old_hlvl])
			return TEE_ERROR_BAD_STATE;
	}

	if (new_corner)
		r->votes[new_hlvl]++;
	if (old_corner)
		r->votes[old_hlvl]--;

	res = rpmh_rail_apply(rpmh_rail_peak());
	if (res) {
		if (new_corner)
			r->votes[new_hlvl]--;
		if (old_corner)
			r->votes[old_hlvl]++;
	}

	return res;
}

TEE_Result rail_vote(uint16_t old_corner, uint16_t new_corner)
{
	struct rpmh_rail *r = &rpmh_rail;
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&r->lock);
	if (r->ready)
		res = rpmh_rail_move(old_corner, new_corner);
	else
		res = TEE_ERROR_BAD_STATE;
	mutex_unlock(&r->lock);

	return res;
}
