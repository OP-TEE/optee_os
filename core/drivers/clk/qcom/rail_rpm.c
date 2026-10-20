// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/rpm/rpm_client.h>
#include <kernel/mutex.h>
#include <tee_api_types.h>
#include <util.h>

#include "rail_vote.h"

#define RPM_RAIL_TIMEOUT_US	10000

#define RPM_RAIL_RWCX_REQ	QCOM_RPM_FOURCC('r', 'w', 'c', 'x')
#define RPM_RAIL_KEY_VLVL	QCOM_RPM_FOURCC('v', 'l', 'v', 'l')
#define RPM_RAIL_RWCX_ID	0

static const uint16_t rpm_rail_corners[] = {
	RAIL_VOLTAGE_LEVEL_LOW_SVS,
	RAIL_VOLTAGE_LEVEL_SVS,
	RAIL_VOLTAGE_LEVEL_NOM,
};

static struct rpm_rail {
	struct mutex lock; /* Serializes RPM rail vote state */
	uint16_t votes[ARRAY_SIZE(rpm_rail_corners)];
	uint16_t applied_corner;
	bool ready;
} rpm_rail = {
	.lock = MUTEX_INITIALIZER,
};

static TEE_Result rpm_rail_corner_idx(uint16_t corner, size_t *idx)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(rpm_rail_corners); i++) {
		if (rpm_rail_corners[i] == corner) {
			*idx = i;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

static uint16_t rpm_rail_peak(void)
{
	size_t i = ARRAY_SIZE(rpm_rail_corners);

	while (i--)
		if (rpm_rail.votes[i])
			return rpm_rail_corners[i];

	return RAIL_VOLTAGE_LEVEL_OFF;
}

static TEE_Result rpm_rail_apply(uint16_t corner)
{
	uint32_t vlvl = corner;
	struct qcom_rpm_kvp kvp = {
		.key = RPM_RAIL_KEY_VLVL,
		.data = &vlvl,
		.len = sizeof(vlvl),
	};
	uint32_t msg_id = 0;
	TEE_Result res = TEE_SUCCESS;

	if (corner == rpm_rail.applied_corner)
		return TEE_SUCCESS;

	res = qcom_rpm_post_request(QCOM_RPM_ACTIVE_SET, RPM_RAIL_RWCX_REQ,
				    RPM_RAIL_RWCX_ID, &kvp, 1, &msg_id);
	if (res)
		return res;

	res = qcom_rpm_barrier(msg_id, RPM_RAIL_TIMEOUT_US);
	if (!res)
		rpm_rail.applied_corner = corner;

	return res;
}

TEE_Result rail_vote_init(void)
{
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&rpm_rail.lock);
	if (!rpm_rail.ready) {
		res = qcom_rpm_init();
		if (!res)
			rpm_rail.ready = true;
	}
	mutex_unlock(&rpm_rail.lock);

	return res;
}

TEE_Result rail_vote(uint16_t old_corner, uint16_t new_corner)
{
	size_t old_idx = 0;
	size_t new_idx = 0;
	TEE_Result res = TEE_SUCCESS;

	if (old_corner == new_corner)
		return TEE_SUCCESS;

	mutex_lock(&rpm_rail.lock);
	if (!rpm_rail.ready) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (old_corner) {
		res = rpm_rail_corner_idx(old_corner, &old_idx);
		if (res)
			goto out;
		if (!rpm_rail.votes[old_idx]) {
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}
	}

	if (new_corner) {
		res = rpm_rail_corner_idx(new_corner, &new_idx);
		if (res)
			goto out;
	}

	if (new_corner)
		rpm_rail.votes[new_idx]++;
	if (old_corner)
		rpm_rail.votes[old_idx]--;

	res = rpm_rail_apply(rpm_rail_peak());
	if (res) {
		if (new_corner)
			rpm_rail.votes[new_idx]--;
		if (old_corner)
			rpm_rail.votes[old_idx]++;
	}

out:
	mutex_unlock(&rpm_rail.lock);
	return res;
}
