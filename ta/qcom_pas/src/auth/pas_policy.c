// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_policy.h>
#include <pas_policy_platform.h>
#include <tee_api_types.h>
#include <util.h>

static const struct pas_policy_entry *find_entry(uint32_t pas_id)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(pas_policy_map); i++)
		if (pas_policy_map[i].pas_id == pas_id)
			return &pas_policy_map[i];

	return NULL;
}

TEE_Result pas_policy_expected_swid(uint32_t pas_id, uint32_t *swid)
{
	const struct pas_policy_entry *e = find_entry(pas_id);

	if (!swid)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!e)
		return TEE_ERROR_NOT_SUPPORTED;

	*swid = e->swid;
	return TEE_SUCCESS;
}

TEE_Result pas_policy_expected_arb_bank(uint32_t pas_id,
					enum pas_arb_fuse_bank *bank)
{
	const struct pas_policy_entry *e = find_entry(pas_id);

	if (!bank)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!e)
		return TEE_ERROR_NOT_SUPPORTED;

	*bank = e->arb_bank;
	return TEE_SUCCESS;
}
