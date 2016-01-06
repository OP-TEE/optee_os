/*
 * Copyright (c) 2016, Linaro Limied
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
#include <string.h>
#include <stdlib.h>

#include <kernel/tee_time.h>
#include <kernel/time_source.h>
#include <kernel/thread.h>
#include <optee_msg.h>
#include <mm/core_mmu.h>

struct time_source _time_source;

TEE_Result tee_time_get_sys_time(TEE_Time *time)
{
	return _time_source.get_sys_time(time);
}

uint32_t tee_time_get_sys_time_protection_level(void)
{
	return _time_source.protection_level;
}

void tee_time_wait(uint32_t milliseconds_delay)
{
	struct optee_msg_param params;

	memset(&params, 0, sizeof(params));
	params.attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	params.u.value.a = milliseconds_delay;
	thread_rpc_cmd(OPTEE_MSG_RPC_CMD_SUSPEND, 1, &params);
}

/*
 * tee_time_get_ree_time(): this function implements the GP Internal API
 * function TEE_GetREETime()
 * Goal is to get the time of the Rich Execution Environment
 * This is why this time is provided through the supplicant
 */
TEE_Result tee_time_get_ree_time(TEE_Time *time)
{
	TEE_Result res;
	struct optee_msg_param params;

	if (!time)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(&params, 0, sizeof(params));
	params.attr = OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT;
	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_GET_TIME, 1, &params);
	if (res == TEE_SUCCESS) {
		time->seconds = params.u.value.a;
		time->millis = params.u.value.b / 1000000;
	}

	return res;
}
