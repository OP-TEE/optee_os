/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <compiler.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <pta_invoke_tests.h>
#include <string.h>
#include <tee/cache.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>

#include "core_self_tests.h"

#define TA_NAME		"invoke_tests.pta"

static TEE_Result test_trace(uint32_t param_types __unused,
			TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	IMSG("pseudo TA \"%s\" says \"Hello world !\"", TA_NAME);

	return TEE_SUCCESS;
}

/*
 * Supported tests on parameters
 * (I, J, K, L refer to param index)
 *
 * Case 1: command parameters type are: 1 in/out value, 3 empty.
 *         => process outI.a = inI.a + inI.b
 * Case 2: command parameters type are: 3 input value, 1 output value
 *         => process = outI.a = inJ.a + inK.a + inL.a
 * Case 3: command parameters type are: 1 in/out memref, 3 empty.
 *         => process = outI[0] = sum(inI[0..len-1])
 */
static TEE_Result test_entry_params(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	size_t i;
	uint8_t d8, *in;

	/* case 1a: 1 input/output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		p[0].value.a = p[0].value.a + p[0].value.b;
		return TEE_SUCCESS;
	}
	/* case 1b: 1 input/output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		p[1].value.a = p[1].value.a + p[1].value.b;
		return TEE_SUCCESS;
	}
	/* case 1c: 1 input/output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		p[2].value.a = p[2].value.a + p[2].value.b;
		return TEE_SUCCESS;
	}
	/* case 1d: 1 input/output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_INOUT)) {
		p[3].value.a = p[3].value.a + p[3].value.b;
		return TEE_SUCCESS;
	}

	/* case 2a: 3 input value arguments, 1 output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_OUTPUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_INPUT)) {
		p[0].value.a = p[1].value.a + p[2].value.a + p[3].value.a;
		p[0].value.b = p[1].value.b + p[2].value.b + p[3].value.b;
		return TEE_SUCCESS;
	}
	/* case 2a: 3 input value arguments, 1 output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_OUTPUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_INPUT)) {
		p[1].value.a = p[0].value.a + p[2].value.a + p[3].value.a;
		p[1].value.b = p[0].value.b + p[2].value.b + p[3].value.b;
		return TEE_SUCCESS;
	}
	/* case 2a: 3 input value arguments, 1 output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_OUTPUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_INPUT)) {
		p[2].value.a = p[0].value.a + p[1].value.a + p[3].value.a;
		p[2].value.b = p[0].value.b + p[1].value.b + p[3].value.b;
		return TEE_SUCCESS;
	}
	/* case 2a: 3 input value arguments, 1 output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_OUTPUT)) {
		p[3].value.a = p[0].value.a + p[1].value.a + p[2].value.a;
		p[3].value.b = p[0].value.b + p[1].value.b + p[2].value.b;
		return TEE_SUCCESS;
	}

	DMSG("expect memref params: %p/%" PRIu32 " - %p/%" PRIu32 "zu - %p/%" PRIu32 "zu - %p/%" PRIu32 "zu",
			p[0].memref.buffer, p[0].memref.size,
			p[1].memref.buffer, p[1].memref.size,
			p[2].memref.buffer, p[2].memref.size,
			p[3].memref.buffer, p[3].memref.size);

	/* case 3a: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		in = (uint8_t *)p[0].memref.buffer;
		d8 = 0;
		for (i = 0; i < p[0].memref.size; i++)
			d8 += in[i];
		*(uint8_t *)p[0].memref.buffer = d8;
		return TEE_SUCCESS;
	}
	/* case 3b: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		in = (uint8_t *)p[1].memref.buffer;
		d8 = 0;
		for (i = 0; i < p[1].memref.size; i++)
			d8 += in[i];
		*(uint8_t *)p[1].memref.buffer = d8;
		return TEE_SUCCESS;
	}
	/* case 3c: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		in = (uint8_t *)p[2].memref.buffer;
		d8 = 0;
		for (i = 0; i < p[2].memref.size; i++)
			d8 += in[i];
		*(uint8_t *)p[2].memref.buffer = d8;
		return TEE_SUCCESS;
	}
	/* case 3d: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_MEMREF_INOUT)) {
		in = (uint8_t *)p[3].memref.buffer;
		d8 = 0;
		for (i = 0; i < p[3].memref.size; i++)
			d8 += in[i];
		*(uint8_t *)p[3].memref.buffer = d8;
		return TEE_SUCCESS;
	}

	EMSG("unexpected parameters");
	return TEE_ERROR_BAD_PARAMETERS;
}

/*
 * Test access to Secure Data Path memory from pseudo TAs
 */

static TEE_Result test_inject_sdp(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	char *src = p[0].memref.buffer;
	char *dst = p[1].memref.buffer;
	size_t sz = p[0].memref.size;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != type) {
		DMSG("bad parameter types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (p[1].memref.size < sz) {
		p[1].memref.size = sz;
		return TEE_ERROR_SHORT_BUFFER;
	}


	if (!core_vbuf_is(CORE_MEM_NSEC_SHM, src, sz) ||
	    !core_vbuf_is(CORE_MEM_SDP_MEM, dst, sz)) {
		DMSG("bad memref secure attribute");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cache_operation(TEE_CACHEFLUSH, dst, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	memcpy(dst, src, sz);

	if (cache_operation(TEE_CACHEFLUSH, dst, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result test_transform_sdp(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	char *buf = p[0].memref.buffer;
	size_t sz = p[0].memref.size;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != type) {
		DMSG("bad parameter types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!core_vbuf_is(CORE_MEM_SDP_MEM, buf, sz)) {
		DMSG("bad memref secure attribute");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cache_operation(TEE_CACHEFLUSH, buf, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	for (; sz; sz--, buf++)
		*buf = ~(*buf) + 1;

	if (cache_operation(TEE_CACHEFLUSH, buf, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result test_dump_sdp(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	char *src = p[0].memref.buffer;
	char *dst = p[1].memref.buffer;
	size_t sz = p[0].memref.size;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != type) {
		DMSG("bad parameter types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (p[1].memref.size < sz) {
		p[1].memref.size = sz;
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (!core_vbuf_is(CORE_MEM_SDP_MEM, src, sz) ||
	    !core_vbuf_is(CORE_MEM_NSEC_SHM, dst, sz)) {
		DMSG("bad memref secure attribute");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cache_operation(TEE_CACHEFLUSH, dst, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	memcpy(dst, src, sz);

	if (cache_operation(TEE_CACHEFLUSH, dst, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
	DMSG("create entry point for pseudo TA \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
	DMSG("destroy entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
		TEE_Param pParams[TEE_NUM_PARAMS] __unused,
		void **ppSessionContext __unused)
{
	DMSG("open entry point for pseudo ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result invoke_command(void *pSessionContext __unused,
		uint32_t nCommandID, uint32_t nParamTypes,
		TEE_Param pParams[TEE_NUM_PARAMS])
{
	DMSG("command entry point for pseudo ta \"%s\"", TA_NAME);

	switch (nCommandID) {
	case PTA_INVOKE_TESTS_CMD_TRACE:
		return test_trace(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_PARAMS:
		return test_entry_params(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_COPY_NSEC_TO_SEC:
		return test_inject_sdp(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_READ_MODIFY_SEC:
		return test_transform_sdp(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_COPY_SEC_TO_NSEC:
		return test_dump_sdp(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_SELF_TESTS:
		return core_self_tests(nParamTypes, pParams);
#if defined(CFG_WITH_USER_TA)
	case PTA_INVOKE_TESTS_CMD_FS_HTREE:
		return core_fs_htree_tests(nParamTypes, pParams);
#endif
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_INVOKE_TESTS_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_SECURE_DATA_PATH,
		   .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
