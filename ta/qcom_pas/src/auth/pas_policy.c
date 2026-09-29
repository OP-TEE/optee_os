// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_policy.h>
#include <pas_policy_platform.h>
#include <tee_api_types.h>
#include <util.h>

TEE_Result pas_policy_expected_swid(uint32_t pas_id, uint32_t *swid)
{
	size_t i = 0;

	if (!swid)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < ARRAY_SIZE(pas_swid_map); i++) {
		if (pas_swid_map[i].pas_id == pas_id) {
			*swid = pas_swid_map[i].swid;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_NOT_SUPPORTED;
}
