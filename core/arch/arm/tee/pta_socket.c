/*
 * Copyright (c) 2016-2017, Linaro Limited
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

#include <assert.h>
#include <mm/mobj.h>
#include <kernel/pseudo_ta.h>
#include <kernel/msg_param.h>
#include <optee_msg.h>
#include <optee_msg_supplicant.h>
#include <pta_socket.h>
#include <string.h>
#include <tee/tee_fs_rpc.h>

static uint32_t get_instance_id(struct tee_ta_session *sess)
{
	return sess->ctx->ops->get_instance_id(sess->ctx);
}

static TEE_Result socket_open(uint32_t instance_id, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	struct mobj *mobj;
	TEE_Result res;
	uint64_t cookie;
	void *va;
	struct optee_msg_param msg_params[4];
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(msg_params, 0, sizeof(msg_params));

	va = tee_fs_rpc_cache_alloc(params[1].memref.size, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	msg_params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[0].u.value.a = OPTEE_MRC_SOCKET_OPEN;
	msg_params[0].u.value.b = instance_id;

	msg_params[1].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[1].u.value.a = params[0].value.b; /* server port number */
	msg_params[1].u.value.b = params[2].value.a; /* protocol */
	msg_params[1].u.value.c = params[0].value.a; /* ip version */

	/* server address */
	if (!msg_param_init_memparam(msg_params + 2, mobj, 0,
				     params[1].memref.size, cookie,
				     MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;
	memcpy(va, params[1].memref.buffer, params[1].memref.size);

	/* socket handle */
	msg_params[3].attr = OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT;

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_SOCKET, 4, msg_params);

	if (res == TEE_SUCCESS)
		params[3].value.a = msg_params[3].u.value.a;

	return res;
}

static TEE_Result socket_close(uint32_t instance_id, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	struct optee_msg_param msg_params[1];
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(msg_params, 0, sizeof(msg_params));

	msg_params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[0].u.value.a = OPTEE_MRC_SOCKET_CLOSE;
	msg_params[0].u.value.b = instance_id;
	msg_params[0].u.value.c = params[0].value.a;

	return thread_rpc_cmd(OPTEE_MSG_RPC_CMD_SOCKET, 1, msg_params);
}

static TEE_Result socket_send(uint32_t instance_id, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	struct mobj *mobj;
	TEE_Result res;
	uint64_t cookie;
	void *va;
	struct optee_msg_param msg_params[3];
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(msg_params, 0, sizeof(msg_params));

	va = tee_fs_rpc_cache_alloc(params[1].memref.size, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	msg_params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[0].u.value.a = OPTEE_MRC_SOCKET_SEND;
	msg_params[0].u.value.b = instance_id;
	msg_params[0].u.value.c = params[0].value.a; /* handle */

	/* buffer */
	if (!msg_param_init_memparam(msg_params + 1, mobj, 0,
				     params[1].memref.size, cookie,
				     MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

	memcpy(va, params[1].memref.buffer, params[1].memref.size);

	msg_params[2].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INOUT;
	msg_params[2].u.value.a = params[0].value.b /* timeout */;


	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_SOCKET, 3, msg_params);
	params[2].value.a = msg_params[2].u.value.b; /* transmitted bytes */
	return res;
}

static TEE_Result socket_recv(uint32_t instance_id, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	struct mobj *mobj;
	TEE_Result res;
	uint64_t cookie;
	void *va;
	struct optee_msg_param msg_params[3];
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(msg_params, 0, sizeof(msg_params));

	va = tee_fs_rpc_cache_alloc(params[1].memref.size, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	msg_params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[0].u.value.a = OPTEE_MRC_SOCKET_RECV;
	msg_params[0].u.value.b = instance_id;
	msg_params[0].u.value.c = params[0].value.a; /* handle */

	/* buffer */
	if (!msg_param_init_memparam(msg_params + 1, mobj, 0,
				     params[1].memref.size, cookie,
				     MSG_PARAM_MEM_DIR_OUT))
		return TEE_ERROR_BAD_STATE;

	msg_params[2].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[2].u.value.a = params[0].value.b /* timeout */;


	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_SOCKET, 3, msg_params);
	params[1].memref.size = msg_param_get_buf_size(msg_params + 1);
	if (params[1].memref.size)
		memcpy(params[1].memref.buffer, va, params[1].memref.size);
	return res;
}

static TEE_Result socket_ioctl(uint32_t instance_id, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	struct mobj *mobj;
	TEE_Result res;
	uint64_t cookie;
	void *va;
	struct optee_msg_param msg_params[3];
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INOUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(msg_params, 0, sizeof(msg_params));

	va = tee_fs_rpc_cache_alloc(params[1].memref.size, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	msg_params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[0].u.value.a = OPTEE_MRC_SOCKET_IOCTL;
	msg_params[0].u.value.b = instance_id;
	msg_params[0].u.value.c = params[0].value.a; /* handle */

	/* buffer */
	if (!msg_param_init_memparam(msg_params + 1, mobj, 0,
				     params[1].memref.size, cookie,
				     MSG_PARAM_MEM_DIR_INOUT))
		return TEE_ERROR_BAD_STATE;

	memcpy(va, params[1].memref.buffer, params[1].memref.size);

	msg_params[2].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[2].u.value.a = params[0].value.b; /* ioctl command */

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_SOCKET, 3, msg_params);
	if (msg_param_get_buf_size(msg_params + 1) <= params[1].memref.size)
		memcpy(params[1].memref.buffer, va,
		       msg_param_get_buf_size(msg_params + 1));

	params[1].memref.size = msg_param_get_buf_size(msg_params + 1);
	return res;
}

typedef TEE_Result (*ta_func)(uint32_t instance_id, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS]);

static const ta_func ta_funcs[] = {
	[PTA_SOCKET_OPEN] = socket_open,
	[PTA_SOCKET_CLOSE] = socket_close,
	[PTA_SOCKET_SEND] = socket_send,
	[PTA_SOCKET_RECV] = socket_recv,
	[PTA_SOCKET_IOCTL] = socket_ioctl,
};

/*
 * Trusted Application Entry Points
 */

static TEE_Result pta_socket_open_session(uint32_t param_types __unused,
			TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			void **sess_ctx)
{
	struct tee_ta_session *s;

	/* Check that we're called from a TA */
	s = tee_ta_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;

	*sess_ctx = (void *)(vaddr_t)get_instance_id(s);

	return TEE_SUCCESS;
}

static void pta_socket_close_session(void *sess_ctx)
{
	TEE_Result res;
	struct optee_msg_param msg_params[1];

	memset(msg_params, 0, sizeof(msg_params));

	msg_params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	msg_params[0].u.value.a = OPTEE_MRC_SOCKET_CLOSE_ALL;
	msg_params[0].u.value.b = (vaddr_t)sess_ctx;

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_SOCKET, 1, msg_params);
	if (res != TEE_SUCCESS)
		DMSG("OPTEE_MRC_SOCKET_CLOSE_ALL failed: %#" PRIx32, res);
}

static TEE_Result pta_socket_invoke_command(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	if (cmd_id < ARRAY_SIZE(ta_funcs) && ta_funcs[cmd_id])
		return ta_funcs[cmd_id]((vaddr_t)sess_ctx, param_types, params);

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SOCKET_UUID, .name = "socket",
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = pta_socket_open_session,
		   .close_session_entry_point = pta_socket_close_session,
		   .invoke_command_entry_point = pta_socket_invoke_command);
