// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <fuseprov_v3.h>
#include <kernel/pseudo_ta.h>
#include <pta_qcom_fuseprov.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>

#define PTA_NAME "pta.qcom.fuseprov"

static TEE_Result blow_secelf(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	struct pta_qcom_fuseprov_region region = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || !params[0].memref.size ||
	    !params[1].memref.buffer ||
	    params[1].memref.size != sizeof(region))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(&region, params[1].memref.buffer, sizeof(region));
	if (region.end <= region.start)
		return TEE_ERROR_BAD_PARAMETERS;

	res = fuseprov_v3_blow_secelf(params[0].memref.buffer,
				      params[0].memref.size, region.start,
				      region.end - region.start);
	if (res)
		EMSG("Fuse provisioning failed: %#"PRIx32, res);

	params[2].value.a = res;

	return res;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_QCOM_FUSEPROV_BLOW_SECELF:
		return blow_secelf(param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

pseudo_ta_register(.uuid = PTA_QCOM_FUSEPROV_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
