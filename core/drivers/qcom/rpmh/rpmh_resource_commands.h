/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMH_RESOURCE_COMMANDS_H__
#define __RPMH_RESOURCE_COMMANDS_H__

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <drivers/qcom/rpmh/rpmh_client.h>

enum rpmh_rc_state {
	RPMH_RC_STATE_IDLE = 0,
	RPMH_RC_STATE_IN_PROGRESS,
	RPMH_RC_STATE_MAX
};

enum rpmh_rc_dirty {
	RPMH_RC_CLEAN = 0,
	RPMH_RC_CLEAN_EXPLICIT_VOTE = 1,
	RPMH_RC_LAST_CLEAN = 1,
	RPMH_RC_DIRTY = 2,
	RPMH_RC_DIRTY_MOL = 3,
	RPMH_RC_DIRTY_USE_ACTIVE = 4,
	RPMH_RC_DIRTY_MAX
};

struct rpmh_vote {
	uint32_t data;
	bool valid;
	bool completion;
	enum rpmh_rc_dirty dirty;
};

enum rpmh_rc_priority {
	RPMH_RC_PRIORITY_USE_CASE = 0,
	RPMH_RC_PRIORITY_SUBSYSTEM,
	RPMH_RC_PRIORITY_MAX
};

struct drv_votes {
	enum rsc_drv_id drv_id;
	enum rpmh_rc_state state;
	enum rpmh_rc_priority priority;
	struct rpmh_vote vote_at_rpmh;
	struct rpmh_vote local_votes[RPMH_NUM_SETS];
	struct drv_votes *next;
};

struct rpmh_resource_command {
	uint32_t address;
	struct drv_votes *drv_votes;
};

/* Initialize resource command */
void rpmh_resource_command_init(struct rpmh_resource_command *rc,
				uint32_t address);

/* Update resource command vote, returns true if set is dirty */
bool rpmh_resource_command_update(struct rpmh_resource_command *rc,
				  enum rpmh_set set,
				  uint32_t data, bool completion,
				  enum rsc_drv_id drv_id,
				  bool explicit_cmd);

/* Find resource command by address */
struct rpmh_resource_command *rpmh_find_resource_command(uint32_t address);

#endif /* __RPMH_RESOURCE_COMMANDS_H__ */
