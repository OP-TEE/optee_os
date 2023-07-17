// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#include <assert.h>
#include <mm/mobj.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_access.h>
#include <optee_rpc_cmd.h>
#include <pta_socket.h>
#include <string.h>
#include <tee/tee_fs_rpc.h>

static uint32_t get_instance_id(struct ts_session *sess)
{
	return sess->ctx->ops->get_instance_id(sess->ctx);
}

static TEE_Result socket_open(uint32_t instance_id, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	struct thread_param tpm[4] = { };
	struct mobj *mobj = NULL;
	TEE_Result res = TEE_SUCCESS;
	void *va = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_SOCKET,
					THREAD_SHM_TYPE_APPLICATION,
					params[1].memref.size, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = copy_from_user(va, params[1].memref.buffer,
			     params[1].memref.size);
	if (res)
		return res;

	tpm[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_SOCKET_OPEN, instance_id, 0);
	tpm[1] = THREAD_PARAM_VALUE(IN,
				    params[0].value.b, /* server port number */
				    params[2].value.a, /* protocol */
				    params[0].value.a  /* ip version */);
	tpm[2] = THREAD_PARAM_MEMREF(IN, mobj, 0, params[1].memref.size);
	tpm[3] = THREAD_PARAM_VALUE(OUT, 0, 0, 0);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_SOCKET, 4, tpm);
	if (res == TEE_SUCCESS)
		params[3].value.a = tpm[3].u.value.a;

	return res;
}

static TEE_Result socket_close(uint32_t instance_id, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	struct thread_param tpm = { };
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tpm = THREAD_PARAM_VALUE(IN, OPTEE_RPC_SOCKET_CLOSE, instance_id,
				 params[0].value.a);

	return thread_rpc_cmd(OPTEE_RPC_CMD_SOCKET, 1, &tpm);
}

static TEE_Result socket_send(uint32_t instance_id, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	struct thread_param tpm[3] = { };
	struct mobj *mobj = NULL;
	TEE_Result res = TEE_SUCCESS;
	void *va = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_SOCKET,
					THREAD_SHM_TYPE_APPLICATION,
					params[1].memref.size, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = copy_from_user(va, params[1].memref.buffer,
			     params[1].memref.size);
	if (res)
		return res;

	tpm[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_SOCKET_SEND, instance_id,
				    params[0].value.a /* handle */);
	tpm[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, params[1].memref.size);
	tpm[2] = THREAD_PARAM_VALUE(INOUT, params[0].value.b, /* timeout */
				     0, 0);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_SOCKET, 3, tpm);
	params[2].value.a = tpm[2].u.value.b; /* transmitted bytes */

	return res;
}

static TEE_Result socket_recv(uint32_t instance_id, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	struct thread_param tpm[3] = { };
	struct mobj *mobj = NULL;
	TEE_Result res = TEE_SUCCESS;
	void *va = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].memref.size) {
		va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_SOCKET,
						THREAD_SHM_TYPE_APPLICATION,
						params[1].memref.size, &mobj);
		if (!va)
			return TEE_ERROR_OUT_OF_MEMORY;
	}

	tpm[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_SOCKET_RECV, instance_id,
				    params[0].value.a /* handle */);
	tpm[1] = THREAD_PARAM_MEMREF(OUT, mobj, 0, params[1].memref.size);
	tpm[2] = THREAD_PARAM_VALUE(IN, params[0].value.b /* timeout */, 0, 0);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_SOCKET, 3, tpm);

	if (params[1].memref.size) {
		TEE_Result res2 = TEE_SUCCESS;

		res2 = copy_to_user(params[1].memref.buffer, va,
				    MIN(params[1].memref.size,
					tpm[1].u.memref.size));
		if (res2)
			return res2;
	}
	params[1].memref.size = tpm[1].u.memref.size;

	return res;
}

static TEE_Result socket_ioctl(uint32_t instance_id, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	struct thread_param tpm[3] = { };
	struct mobj *mobj = NULL;
	TEE_Result res = TEE_SUCCESS;
	void *va = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INOUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("got param_types 0x%x, expected 0x%x",
		     param_types, exp_pt);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_SOCKET,
					THREAD_SHM_TYPE_APPLICATION,
					params[1].memref.size, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = copy_from_user(va, params[1].memref.buffer,
			     params[1].memref.size);
	if (res)
		return res;

	tpm[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_SOCKET_IOCTL, instance_id,
				    params[0].value.a /* handle */);
	tpm[1] = THREAD_PARAM_MEMREF(INOUT, mobj, 0, params[1].memref.size);
	tpm[2] = THREAD_PARAM_VALUE(IN, params[0].value.b /* ioctl command */,
				    0, 0);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_SOCKET, 3, tpm);
	if (tpm[1].u.memref.size <= params[1].memref.size) {
		TEE_Result res2 = TEE_SUCCESS;

		res2 = copy_to_user(params[1].memref.buffer, va,
				    tpm[1].u.memref.size);
		if (res2)
			return res2;
	}

	params[1].memref.size = tpm[1].u.memref.size;

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
	struct ts_session *s = ts_get_calling_session();

	/* Check that we're called from a TA */
	if (!s || !is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	*sess_ctx = (void *)(vaddr_t)get_instance_id(s);

	return TEE_SUCCESS;
}

static void pta_socket_close_session(void *sess_ctx)
{
	TEE_Result res;
	struct thread_param tpm = {
		.attr = THREAD_PARAM_ATTR_VALUE_IN, .u.value = {
			.a = OPTEE_RPC_SOCKET_CLOSE_ALL, .b = (vaddr_t)sess_ctx,
		},
	};

	res = thread_rpc_cmd(OPTEE_RPC_CMD_SOCKET, 1, &tpm);
	if (res != TEE_SUCCESS)
		DMSG("OPTEE_RPC_SOCKET_CLOSE_ALL failed: %#" PRIx32, res);
}

static TEE_Result pta_socket_invoke_command(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	if (cmd_id < ARRAY_SIZE(ta_funcs) && ta_funcs[cmd_id])
		return ta_funcs[cmd_id]((vaddr_t)sess_ctx, param_types, params);

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SOCKET_UUID, .name = "socket",
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		   .open_session_entry_point = pta_socket_open_session,
		   .close_session_entry_point = pta_socket_close_session,
		   .invoke_command_entry_point = pta_socket_invoke_command);
