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
#include <types_ext.h>
#include <kernel/static_ta.h>
#include <trace.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include "core_self_tests.h"

#define TA_NAME		"sta_self_tests.ta"

#define STA_SELF_TEST_UUID \
		{ 0xd96a5b40, 0xc3e5, 0x21e3, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

#define CMD_TRACE	0
#define CMD_PARAMS	1
#define CMD_SELF_TESTS	2

static TEE_Result test_trace(uint32_t param_types __unused,
			TEE_Param params[4] __unused)
{
	IMSG("static TA \"%s\" says \"Hello world !\"", TA_NAME);

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
static TEE_Result test_entry_params(uint32_t type, TEE_Param p[4])
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
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
	DMSG("create entry point for static ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
	DMSG("destroy entry point for static ta \"%s\"", TA_NAME);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
		TEE_Param pParams[4] __unused, void **ppSessionContext __unused)
{
	DMSG("open entry point for static ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for static ta \"%s\"", TA_NAME);
}

static TEE_Result invoke_command(void *pSessionContext __unused,
		uint32_t nCommandID, uint32_t nParamTypes, TEE_Param pParams[4])
{
	DMSG("command entry point for static ta \"%s\"", TA_NAME);

	switch (nCommandID) {
	case CMD_TRACE:
		return test_trace(nParamTypes, pParams);
	case CMD_PARAMS:
		return test_entry_params(nParamTypes, pParams);
	case CMD_SELF_TESTS:
		return core_self_tests(nParamTypes, pParams);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static_ta_register(.uuid = STA_SELF_TEST_UUID, .name = TA_NAME,
		   .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
