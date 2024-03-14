// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <compiler.h>
#include <kernel/tee_time.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>
#include <optee_rpc_cmd.h>
#include <stdlib.h>

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
	struct thread_param params = THREAD_PARAM_VALUE(OUT, 0, 0, 0);
	TEE_Result res = TEE_SUCCESS;

	if (!time)
		return TEE_ERROR_BAD_PARAMETERS;

	res = thread_rpc_cmd(OPTEE_RPC_CMD_GET_TIME, 1, &params);
	if (res == TEE_SUCCESS) {
		time->seconds = params.u.value.a;
		time->millis = params.u.value.b / 1000000;
	}

	return res;
}
