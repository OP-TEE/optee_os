/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
		res = TEE_OpenTASession(&core_uuid, 0, 0, NULL, &sess, NULL);
		if (res != TEE_SUCCESS)
			return res;
	}
	res = TEE_InvokeTACommand(sess, 0, cmd_id, param_types, params, NULL);
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
