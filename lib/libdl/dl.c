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

/* FIXME: duplicated from core/arch/arm/kernel/user_ta.c */

static int hex(char c)
{
	char lc = tolower(c);

	if (isdigit(lc))
		return lc - '0';
	if (isxdigit(lc))
		return lc - 'a' + 10;
	return -1;
}

static uint32_t parse_hex(const char *s, size_t nchars, uint32_t *res)
{
	uint32_t v = 0;
	size_t n;
	int c;

	for (n = 0; n < nchars; n++) {
		c = hex(s[n]);
		if (c == (char)-1) {
			*res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}
		v = (v << 4) + c;
	}
	*res = TEE_SUCCESS;
out:
	return v;
}

/*
 * Convert a UUID string @s into a TEE_UUID @uuid
 * Expected format for @s is: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 * 'x' being any hexadecimal digit (0-9a-fA-F)
 */
static TEE_Result parse_uuid(const char *s, TEE_UUID *uuid)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_UUID u = { 0 };
	const char *p = s;
	size_t i;

	if (strlen(p) != 36)
		return TEE_ERROR_BAD_FORMAT;
	if (p[8] != '-' || p[13] != '-' || p[18] != '-' || p[23] != '-')
		return TEE_ERROR_BAD_FORMAT;

	u.timeLow = parse_hex(p, 8, &res);
	if (res)
		goto out;
	p += 9;
	u.timeMid = parse_hex(p, 4, &res);
	if (res)
		goto out;
	p += 5;
	u.timeHiAndVersion = parse_hex(p, 4, &res);
	if (res)
		goto out;
	p += 5;
	for (i = 0; i < 8; i++) {
		u.clockSeqAndNode[i] = parse_hex(p, 2, &res);
		if (res)
			goto out;
		if (i == 1)
			p += 3;
		else
			p += 2;
	}
	*uuid = u;
out:
	return res;
}

static TEE_TASessionHandle sess = TEE_HANDLE_NULL;

static TEE_Result invoke_system_pta(uint32_t cmd_id, uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	static const TEE_UUID core_uuid = PTA_SYSTEM_UUID;
	TEE_Result res;

	if (!sess) {
		res = TEE_OpenTASession(&core_uuid, 0, 0, NULL, &sess, NULL);
		if (res)
			return res;
	}
	res = TEE_InvokeTACommand(sess, 0, cmd_id, param_types, params, NULL);
	return res;
}

static void *param_to_ptr(TEE_Param *param)
{
	vaddr_t va;

	va = param->value.a;
#ifdef ARM64
	va |= ((vaddr_t)param->value.b) << 32;
#endif
	return (void *)va;
}

struct dl_handle {
	TEE_UUID uuid;
};

void *dlopen(const char *filename, int flags)
{
	TEE_Param params[TEE_NUM_PARAMS];
	struct dl_handle *h = NULL;
	uint32_t param_types;
	void *ret = NULL;
	TEE_Result res;
	TEE_UUID uuid;

	if (flags != (RTLD_NOW | RTLD_GLOBAL))
		goto err;

	res = parse_uuid(filename, &uuid);
	if (res)
		goto err;

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE);

	memset(params, 0, sizeof(params));
	params[0].memref.buffer = (void *)&uuid;
	params[0].memref.size = sizeof(uuid);
	params[1].value.a = flags;

	res = invoke_system_pta(PTA_SYSTEM_DLOPEN, param_types, params);
	if (res)
		goto err;
	h = malloc(sizeof(*h));
	if (!h)
		goto err;
	h->uuid = uuid;
	ret = (void *)h;
err:
	return ret;
}

/* FIXME: (1) no reference counting (2) will never unmap the library */
int dlclose(void *handle)
{
	free(handle);
	return 0;
}

void *dlsym(void *handle, const char *symbol)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Param params[TEE_NUM_PARAMS];
	struct dl_handle *h = handle;
	uint32_t param_types;
	void *ptr = NULL;

	if (!symbol)
		return NULL;

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_VALUE_OUTPUT,
				      TEE_PARAM_TYPE_NONE);

	memset(params, 0, sizeof(params));
	if (h) {
		params[0].memref.buffer = (void *)&h->uuid;
		params[0].memref.size = sizeof(h->uuid);
	}
	params[1].memref.buffer = (void *)symbol;
	params[1].memref.size = strlen(symbol) + 1;

	res = invoke_system_pta(PTA_SYSTEM_DLSYM, param_types, params);
	if (!res)
		ptr = param_to_ptr(&params[2]);

	return ptr;
}

