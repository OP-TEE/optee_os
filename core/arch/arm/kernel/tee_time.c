// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <compiler.h>
#include <initcall.h>
#include <kernel/tee_time.h>
#include <kernel/thread.h>
#include <kernel/time_source.h>
#include <mm/core_mmu.h>
#include <optee_rpc_cmd.h>
#include <stdlib.h>
#include <string.h>

struct time_source _time_source;

static TEE_Result register_time_source(void)
{
	time_source_init();

	return TEE_SUCCESS;
}
early_init(register_time_source);

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
	struct thread_param params =
		THREAD_PARAM_VALUE(IN, milliseconds_delay, 0, 0);

	thread_rpc_cmd(OPTEE_RPC_CMD_SUSPEND, 1, &params);
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

	if (!time)
		return TEE_ERROR_BAD_PARAMETERS;

	struct thread_param params = THREAD_PARAM_VALUE(OUT, 0, 0, 0);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_GET_TIME, 1, &params);
	if (res == TEE_SUCCESS) {
		time->seconds = params.u.value.a;
		time->millis = params.u.value.b / 1000000;
	}

	return res;
}
