// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019 Linaro limited
 */

#include <ctype.h>
#include <dlfcn.h>
#include <pta_system.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api.h>
#include <tee_internal_api_extensions.h>
#include <user_ta_header.h>

static TEE_TASessionHandle sess = TEE_HANDLE_NULL;
static size_t hcount;

static TEE_Result invoke_system_pta(uint32_t cmd_id, uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	const TEE_UUID core_uuid = PTA_SYSTEM_UUID;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (sess == TEE_HANDLE_NULL) {
		res = TEE_OpenTASession(&core_uuid, TEE_TIMEOUT_INFINITE,
					0, NULL, &sess, NULL);
		if (res)
			return res;
	}
	return TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				   cmd_id, param_types, params, NULL);
}

struct dl_handle {
	TEE_UUID uuid;
};

void *dlopen(const char *filename, int flags)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	struct dl_handle *h = NULL;
	uint32_t param_types = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_UUID uuid = { };

	h = malloc(sizeof(*h));
	if (!h)
		return NULL;

	if (filename) {
		res = tee_uuid_from_str(&uuid, filename);
		if (res)
			goto err;

		param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					      TEE_PARAM_TYPE_VALUE_INPUT,
					      TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE);

		params[0].memref.buffer = (void *)&uuid;
		params[0].memref.size = sizeof(uuid);
		params[1].value.a = flags;

		res = invoke_system_pta(PTA_SYSTEM_DLOPEN, param_types, params);
		if (res)
			goto err;

		__utee_tcb_init();
		__utee_call_elf_init_fn();
	}

	hcount++;
	h->uuid = uuid;
	return (void *)h;
err:
	free(h);
	return NULL;
}

int dlclose(void *handle)
{
	free(handle);
	hcount--;
	if (!hcount && sess != TEE_HANDLE_NULL) {
		TEE_CloseTASession(sess);
		sess = TEE_HANDLE_NULL;
	}
	return 0;
}

void *dlsym(void *handle, const char *symbol)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Param params[TEE_NUM_PARAMS] = { };
	struct dl_handle *h = handle;
	uint32_t param_types = 0;
	void *ptr = NULL;

	if (!handle || !symbol)
		return NULL;

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_VALUE_OUTPUT,
				      TEE_PARAM_TYPE_NONE);

	params[0].memref.buffer = &h->uuid;
	params[0].memref.size = sizeof(h->uuid);
	params[1].memref.buffer = (void *)symbol;
	params[1].memref.size = strlen(symbol) + 1;

	res = invoke_system_pta(PTA_SYSTEM_DLSYM, param_types, params);
	if (!res)
		ptr = (void *)(vaddr_t)reg_pair_to_64(params[2].value.a,
						      params[2].value.b);

	return ptr;
}

