// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <pta_gprof.h>
#include <string.h>
#include <tee_api.h>
#include "gprof_pta.h"

static TEE_TASessionHandle sess = TEE_HANDLE_NULL;

static TEE_Result invoke_gprof_pta(uint32_t cmd_id, uint32_t param_types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	static const TEE_UUID core_uuid = PTA_GPROF_UUID;
	TEE_Result res;

	if (!sess) {
		res = TEE_OpenTASession(&core_uuid, TEE_TIMEOUT_INFINITE,
					0, NULL, &sess, NULL);
		if (res != TEE_SUCCESS)
			return res;
	}
	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, cmd_id,
				  param_types, params, NULL);
	return res;
}

TEE_Result __pta_gprof_send(void *buf, size_t len, uint32_t *id)
{
	TEE_Param params[TEE_NUM_PARAMS];
	uint32_t param_types;
	TEE_Result res;

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
				      TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));
	params[0].value.a = *id;
	params[1].memref.buffer = buf;
	params[1].memref.size = len;
	res = invoke_gprof_pta(PTA_GPROF_SEND, param_types, params);
	if (res == TEE_SUCCESS)
		*id = params[0].value.a;
	return res;
}

TEE_Result __pta_gprof_pc_sampling_start(void *buf, size_t len, size_t offset,
					 size_t scale)
{
	TEE_Param params[TEE_NUM_PARAMS];
	uint32_t param_types;

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				      TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));
	params[0].memref.buffer = buf;
	params[0].memref.size = len;
	params[1].value.a = offset;
	params[1].value.b = scale;
	return invoke_gprof_pta(PTA_GPROF_START_PC_SAMPLING, param_types,
				params);
}

TEE_Result __pta_gprof_pc_sampling_stop(uint32_t *rate)
{
	TEE_Param params[TEE_NUM_PARAMS];
	uint32_t param_types;
	TEE_Result res;

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));
	res = invoke_gprof_pta(PTA_GPROF_STOP_PC_SAMPLING, param_types,
				params);
	if (res != TEE_SUCCESS)
		return res;
	if (rate)
		*rate = params[0].value.a;
	return res;
}

void __pta_gprof_fini(void)
{
	if (sess)
		TEE_CloseTASession(sess);
}
