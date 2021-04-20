// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Linaro Limited
 */

#include <kernel/notif.h>
#include <kernel/thread.h>
#include <optee_rpc_cmd.h>
#include <tee_api_types.h>
#include <types_ext.h>

static TEE_Result notif_rpc(uint32_t func, uint32_t value)
{
	struct thread_param params = THREAD_PARAM_VALUE(IN, func, value, 0);

	return thread_rpc_cmd(OPTEE_RPC_CMD_NOTIFICATION, 1, &params);
}

TEE_Result notif_wait(uint32_t value)
{
	return notif_rpc(OPTEE_RPC_NOTIFICATION_WAIT, value);
}

TEE_Result notif_send_sync(uint32_t value)
{
	return notif_rpc(OPTEE_RPC_NOTIFICATION_SEND, value);
}
