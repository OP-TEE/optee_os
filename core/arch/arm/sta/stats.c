/*
 * Copyright (c) 2015, Linaro Limited
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
#include <stdio.h>
#include <trace.h>
#include <user_ta_header.h>
#include <mm/tee_pager.h>
#include <string.h>

#define TA_NAME		"stats.ta"

#define STATS_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

#define STATS_CMD_PAGER_STATS		0

static TEE_Result get_pager_stats(uint32_t type, TEE_Param p[4])
{
	struct tee_pager_stats stats;

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_NONE) != type) {
		EMSG("expect 3 output values as argument");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_pager_get_stats(&stats);
	p[0].value.a = stats.npages;
	p[0].value.b = stats.npages_all;
	p[1].value.a = stats.ro_hits;
	p[1].value.b = stats.rw_hits;
	p[2].value.a = stats.hidden_hits;
	p[2].value.b = stats.zi_released;

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
}

static TEE_Result open_session(uint32_t ptype __unused,
			       TEE_Param params[4] __unused,
			       void **ppsess __unused)
{
	return TEE_SUCCESS;
}

static void close_session(void *psess __unused)
{
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[4])
{
	switch (cmd) {
	case STATS_CMD_PAGER_STATS:
		return get_pager_stats(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

__attribute__ ((section("ta_head_section")))
	const ta_static_head_t stats_head = {

	.uuid = STATS_UUID,
	.name = (char *)TA_NAME,
	.create_entry_point = create_ta,
	.destroy_entry_point = destroy_ta,
	.open_session_entry_point = open_session,
	.close_session_entry_point = close_session,
	.invoke_command_entry_point = invoke_command,
};
