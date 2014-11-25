/*
 * Copyright (c) 2014, Linaro Limited
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
#include <user_ta_header.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <kernel/tee_common_unpg.h>
#include <tee/se/manager.h>
#include <tee/se/reader.h>

#include <stdlib.h>
#include <string.h>


#define TA_NAME		"se_api_self_tests.ta"

#define MAX_READERS	10

#define CMD_SELF_TESTS	0

#define SE_API_SELF_TEST_UUID \
		{ 0xAEB79790, 0x6F03, 0x11E4,  \
			{ 0x98, 0x03, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66 } }

#define ASSERT(expr) \
	do { \
		if (!(expr)) { \
			EMSG("assertion '%s' failed at %s:%d (func '%s')", \
				#expr, __FILE__, __LINE__, __func__); \
			return TEE_ERROR_GENERIC; \
		} \
	} while (0)

#define CHECK(ret) \
	do { \
		if (ret != TEE_SUCCESS) \
			return ret; \
	} while (0)

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

static TEE_Result test_reader(struct tee_se_reader_handle **handle)
{
	TEE_Result ret;
	uint8_t cmd[] = { 0x0, 0x70 , 0x00, 0x00 };
	uint8_t resp[3];
	size_t resp_size = sizeof(resp);

	/* transmit should failed since no one attached to the reader */
	ret = tee_se_reader_transmit(handle[0], cmd, sizeof(cmd),
			resp, &resp_size);
	ASSERT(ret == TEE_ERROR_BAD_STATE);

	ret = tee_se_reader_attach(handle[0]);
	ASSERT(ret == TEE_SUCCESS);

	ret = tee_se_reader_attach(handle[0]);
	ASSERT(ret == TEE_SUCCESS);

	/* referenced by 2 owners */
	ASSERT(2 == tee_se_reader_get_refcnt(handle[0]));

	ret = tee_se_reader_transmit(handle[0], cmd, sizeof(cmd),
				resp, &resp_size);
	ASSERT(ret == TEE_SUCCESS);
	ASSERT(resp[0] == 0x1 && resp[1] == 0x90 && resp[2] == 0x0);

	tee_se_reader_detach(handle[0]);

	ASSERT(1 == tee_se_reader_get_refcnt(handle[0]));

	tee_se_reader_detach(handle[0]);

	return TEE_SUCCESS;
}

static TEE_Result se_api_self_tests(uint32_t nParamTypes __attribute__((__unused__)),
		TEE_Param pParams[TEE_NUM_PARAMS] __attribute__((__unused__)))
{
	size_t size = MAX_READERS;
	TEE_Result ret;
	struct tee_se_reader_handle **handles =
		malloc(sizeof(void *) * MAX_READERS);

	tee_se_manager_get_readers(handles, &size);

	ret = test_reader(handles);
	CHECK(ret);

	free(handles);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
		uint32_t nCommandID, uint32_t nParamTypes, TEE_Param pParams[4])
{
	DMSG("command entry point for static ta \"%s\"", TA_NAME);

	switch (nCommandID) {
	case CMD_SELF_TESTS:
		return se_api_self_tests(nParamTypes, pParams);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

__attribute__ ((section("ta_head_section")))
	const ta_static_head_t se_api_self_tests_head = {

	.uuid = SE_API_SELF_TEST_UUID,
	.name = (char *)TA_NAME,
	.create_entry_point = create_ta,
	.destroy_entry_point = destroy_ta,
	.open_session_entry_point = open_session,
	.close_session_entry_point = close_session,
	.invoke_command_entry_point = invoke_command,

};
