// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <trace.h>
#include <utee_syscalls.h>
#include <pta_system.h>

#include "sys.h"

int trace_level = TRACE_LEVEL;
const char trace_ext_prefix[]  = "LD";

static uint32_t sess;

void __panic(const char *file __maybe_unused, const int line __maybe_unused,
	     const char *func __maybe_unused)
{
	if (!file && !func)
		EMSG_RAW("Panic");
	else
		EMSG_RAW("Panic at %s:%d %s%s%s",
			 file ? file : "?", file ? line : 0,
			 func ? "<" : "", func ? func : "", func ? ">" : "");

	utee_panic(1);
	/*NOTREACHED*/
	while (true)
		;
}

void sys_return_cleanup(void)
{
	if (sess) {
		if (utee_close_ta_session(sess))
			panic();
		sess = 0;
	}

	utee_return(0);
	/*NOTREACHED*/
	while (true)
		;
}

static TEE_Result invoke_sys_ta(uint32_t cmdid, struct utee_params *params)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t ret_orig = 0;

	if (!sess) {
		uint32_t s = 0;

		res = utee_open_ta_session(&(const TEE_UUID)PTA_SYSTEM_UUID,
					   0, NULL, &s, &ret_orig);
		if (res)
			return res;
		sess = s;
	}

	return utee_invoke_ta_command(sess, 0, cmdid, params, &ret_orig);
}

TEE_Result sys_map_zi(size_t num_bytes, uint32_t flags, vaddr_t *va,
		      size_t pad_begin, size_t pad_end)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_VALUE_INOUT,
					 TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_NONE),
	};
	uint32_t r[2] = { 0 };

	params.vals[0] = num_bytes;
	params.vals[1] = flags;
	reg_pair_from_64(*va, r, r + 1);
	params.vals[2] = r[0];
	params.vals[3] = r[1];
	params.vals[4] = pad_begin;
	params.vals[5] = pad_end;

	res = invoke_sys_ta(PTA_SYSTEM_MAP_ZI, &params);
	if (!res)
		*va = reg_pair_to_64(params.vals[2], params.vals[3]);
	return res;
}

TEE_Result sys_unmap(vaddr_t va, size_t num_bytes)
{
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_NONE,
					 TEE_PARAM_TYPE_NONE),
	};
	uint32_t r[2] = { 0 };

	params.vals[0] = num_bytes;
	reg_pair_from_64(va, r, r + 1);
	params.vals[2] = r[0];
	params.vals[3] = r[1];

	return invoke_sys_ta(PTA_SYSTEM_UNMAP, &params);
}

TEE_Result sys_open_ta_bin(const TEE_UUID *uuid, uint32_t *handle)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					 TEE_PARAM_TYPE_VALUE_OUTPUT,
					 TEE_PARAM_TYPE_NONE,
					 TEE_PARAM_TYPE_NONE),
	};

	params.vals[0] = (vaddr_t)uuid;
	params.vals[1] = sizeof(*uuid);

	res = invoke_sys_ta(PTA_SYSTEM_OPEN_TA_BINARY, &params);
	if (!res)
		*handle = params.vals[2];
	return res;
}

TEE_Result sys_close_ta_bin(uint32_t handle)
{
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_NONE,
					 TEE_PARAM_TYPE_NONE,
					 TEE_PARAM_TYPE_NONE),
	};

	params.vals[0] = handle;

	return invoke_sys_ta(PTA_SYSTEM_CLOSE_TA_BINARY, &params);
}

TEE_Result sys_map_ta_bin(vaddr_t *va, size_t num_bytes, uint32_t flags,
			  uint32_t handle, size_t offs, size_t pad_begin,
			  size_t pad_end)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_VALUE_INOUT,
					 TEE_PARAM_TYPE_VALUE_INPUT),
	};
	uint32_t r[2] = { 0 };

	params.vals[0] = handle;
	params.vals[1] = flags;
	params.vals[2] = offs;
	params.vals[3] = num_bytes;
	reg_pair_from_64(*va, r, r + 1);
	params.vals[4] = r[0];
	params.vals[5] = r[1];
	params.vals[6] = pad_begin;
	params.vals[7] = pad_end;

	res = invoke_sys_ta(PTA_SYSTEM_MAP_TA_BINARY, &params);
	if (!res)
		*va = reg_pair_to_64(params.vals[4], params.vals[5]);
	return res;
}


TEE_Result sys_copy_from_ta_bin(void *dst, size_t num_bytes, uint32_t handle,
				size_t offs)
{
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_MEMREF_OUTPUT,
					 TEE_PARAM_TYPE_NONE,
					 TEE_PARAM_TYPE_NONE),
	};

	params.vals[0] = handle;
	params.vals[1] = offs;
	params.vals[2] = (vaddr_t)dst;
	params.vals[3] = num_bytes;

	return invoke_sys_ta(PTA_SYSTEM_COPY_FROM_TA_BINARY, &params);
}

TEE_Result sys_set_prot(vaddr_t va, size_t num_bytes, uint32_t flags)
{
	struct utee_params params = {
		.types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_VALUE_INPUT,
					 TEE_PARAM_TYPE_NONE,
					 TEE_PARAM_TYPE_NONE),
	};
	uint32_t r[2] = { 0 };

	params.vals[0] = num_bytes;
	params.vals[1] = flags;
	reg_pair_from_64(va, r, r + 1);
	params.vals[2] = r[0];
	params.vals[3] = r[1];

	return invoke_sys_ta(PTA_SYSTEM_SET_PROT, &params);
}
