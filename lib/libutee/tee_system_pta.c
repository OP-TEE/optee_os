// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <pta_system.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <types_ext.h>
#include <util.h>

static TEE_Result invoke_system_pta(uint32_t cmd_id, uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	static TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	static const TEE_UUID uuid = PTA_SYSTEM_UUID;

	if (sess == TEE_HANDLE_NULL) {
		TEE_Result res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE,
						   0, NULL, &sess, NULL);

		if (res)
			return res;
	}

	return TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, cmd_id,
				   param_types, params, NULL);
}

void *tee_map_zi(size_t len, uint32_t flags)
{
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_VALUE_INOUT,
					       TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_SUCCESS;

	params[0].value.a = len;
	if (params[0].value.a != len)
		return NULL;
	switch (flags) {
	case 0:
		break;
	case TEE_MEMORY_ACCESS_ANY_OWNER:
		params[0].value.b = PTA_SYSTEM_MAP_FLAG_SHAREABLE;
		break;
	default:
		return NULL;
	}

	res = invoke_system_pta(PTA_SYSTEM_MAP_ZI, param_types, params);
	if (res)
		return NULL;

	return (void *)(vaddr_t)reg_pair_to_64(params[1].value.a,
					       params[1].value.b);
}

TEE_Result tee_unmap(void *buf, size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS] = { };

	params[0].value.a = len;
	reg_pair_from_64((vaddr_t)buf, &params[1].value.a, &params[1].value.b);

	res = invoke_system_pta(PTA_SYSTEM_UNMAP, param_types, params);
	if (res)
		EMSG("Invoke PTA_SYSTEM_UNMAP: buf %p, len %#zx", buf, len);

	return res;
}

TEE_Result tee_invoke_supp_plugin(const TEE_UUID *uuid, uint32_t cmd,
				  uint32_t sub_cmd, void *buf, size_t len,
				  size_t *outlen)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INOUT,
					       TEE_PARAM_TYPE_VALUE_OUTPUT);
	TEE_Param params[TEE_NUM_PARAMS] = { };

	if (!uuid || (len && !buf) || (!len && buf))
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].memref.buffer = (void *)uuid;
	params[0].memref.size = sizeof(TEE_UUID);
	params[1].value.a = cmd;
	params[1].value.b = sub_cmd;
	params[2].memref.buffer = buf;
	params[2].memref.size = len;

	res = invoke_system_pta(PTA_SYSTEM_SUPP_PLUGIN_INVOKE, param_types,
				params);
	if (res)
		EMSG("Invoke tee-supplicant's plugin failed: %#"PRIx32, res);

	if (outlen)
		*outlen = params[3].value.a;

	return res;
}
