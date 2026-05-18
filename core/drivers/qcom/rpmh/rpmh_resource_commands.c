// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <drivers/qcom/cmd_db/cmd_db.h>
#include <malloc.h>
#include <string.h>

#include "rpmh_drv_config.h"
#include "rpmh_resource_commands.h"
#include "rpmh_tcs.h"

static struct rpmh_resource_command *resources;
static uint32_t resources_count;

static void
reconcile_vote_state(struct rpmh_resource_command __maybe_unused *rc,
		     struct drv_votes *drv, bool completion)
{
	struct rpmh_vote *active;
	struct rpmh_vote *sleep;
	struct rpmh_vote *wake;

	if (!drv)
		return;

	sleep = &drv->local_votes[RPMH_SET_SLEEP];
	active = &drv->local_votes[RPMH_SET_ACTIVE];
	wake = &drv->local_votes[RPMH_SET_WAKE];

	if (active->valid &&
	    (!drv->vote_at_rpmh.valid ||
	     active->data != drv->vote_at_rpmh.data ||
	     (completion && !active->completion))) {
		active->dirty = RPMH_RC_DIRTY;
	} else {
		active->dirty = RPMH_RC_CLEAN;
	}

	if (sleep->dirty != RPMH_RC_CLEAN_EXPLICIT_VOTE) {
		if (sleep->valid &&
		    (!active->valid ||
		     (active->valid && active->data != sleep->data))) {
			sleep->dirty = RPMH_RC_DIRTY;
		} else {
			sleep->dirty = RPMH_RC_CLEAN;
		}
	}

	if (wake->dirty != RPMH_RC_CLEAN_EXPLICIT_VOTE) {
		if (wake->valid &&
		    ((active->valid && wake->data != active->data) ||
		     (sleep->valid && wake->data != sleep->data))) {
			wake->dirty = RPMH_RC_DIRTY;
		} else if (!wake->valid &&
			   (active->valid && sleep->valid) &&
			   active->data != sleep->data &&
			   sleep->dirty != RPMH_RC_CLEAN_EXPLICIT_VOTE) {
			wake->dirty = RPMH_RC_DIRTY_USE_ACTIVE;
		} else {
			wake->dirty = RPMH_RC_CLEAN;
		}
	}
}

void rpmh_resource_command_init(struct rpmh_resource_command *rc,
				uint32_t address)
{
	if (!rc)
		return;

	memset(rc, 0, sizeof(*rc));
	rc->address = address;
}

static struct drv_votes *
rpmh_resource_command_get_voter(struct rpmh_resource_command *rc,
				enum rsc_drv_id drv_id)
{
	struct drv_votes *drv = rc->drv_votes;
	struct drv_votes *prev = NULL;

	if (!rc)
		return NULL;

	while (drv) {
		if (drv->drv_id == drv_id)
			break;
		prev = drv;
		drv = drv->next;
	}

	if (!drv) {
		const struct drv_config *config;
		uint32_t priority = 0;
		uint32_t drv_index;
		TEE_Result res;

		drv = calloc(1, sizeof(struct drv_votes));
		if (!drv)
			return NULL;

		drv->drv_id = drv_id;

		if (rpmh_tcs_find_drv_index(drv_id, &drv_index) !=
		    TEE_SUCCESS) {
			free(drv);
			return NULL;
		}

		config = &g_drv_config_data->drvs[drv_index];

		res = cmd_db_get_priority(rc->address,
					  (uint8_t)config->hw_drv,
					  &priority);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to query priority for addr 0x%x",
			     rc->address);
			free(drv);
			return NULL;
		}

		drv->priority = (enum rpmh_rc_priority)priority;

		if (!rc->drv_votes)
			rc->drv_votes = drv;
		else if (prev)
			prev->next = drv;
		else
			return NULL;
	}

	return drv;
}

struct rpmh_resource_command *rpmh_find_resource_command(uint32_t address)
{
	uint32_t high = resources_count - 1;
	uint32_t low = 0;

	if (resources_count == 0)
		return NULL;

	while (high >= low) {
		uint32_t mid = (low + high) / 2;
		uint32_t addr = resources[mid].address;

		if (high >= resources_count)
			break;

		if (addr < address)
			low = mid + 1;
		else if (addr > address)
			high = mid - 1;
		else
			return &resources[mid];
	}

	return NULL;
}

bool rpmh_resource_command_update(struct rpmh_resource_command *rc,
				  enum rpmh_set set, uint32_t data,
				  bool completion,
				  enum rsc_drv_id drv_id,
				  bool explicit_cmd)
{
	struct drv_votes *drv = rpmh_resource_command_get_voter(rc, drv_id);

	drv->local_votes[set].data = data;
	drv->local_votes[set].valid = true;

	if (explicit_cmd && set != RPMH_SET_ACTIVE)
		drv->local_votes[set].dirty = RPMH_RC_CLEAN_EXPLICIT_VOTE;

	reconcile_vote_state(rc, drv,
			     completion && set == RPMH_SET_ACTIVE);

	drv->local_votes[set].completion = completion;

	return (drv->local_votes[set].dirty > RPMH_RC_LAST_CLEAN);
}
