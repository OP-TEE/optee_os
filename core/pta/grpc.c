// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Microsoft Corporation
 */

#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <optee_rpc_cmd.h>
#include <pta_grpc.h>
#include <string.h>
#include <util.h>

static TEE_Result rpc_calc_param_size(uint32_t param_type, TEE_Param *param,
				      uint32_t *size)
{
	switch (param_type) {
	case TEE_PARAM_TYPE_NONE:
	case TEE_PARAM_TYPE_VALUE_INPUT:
	case TEE_PARAM_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_TYPE_VALUE_INOUT:
		*size = 0;
		break;
	case TEE_PARAM_TYPE_MEMREF_INPUT:
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		*size = param->memref.size;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result rpc_preprocess_param(struct thread_param *rpc_msg_param,
				       struct mobj *mobj,
				       uint8_t *mobj_va,
				       uint32_t *mobj_offset,
				       uint32_t param_type,
				       TEE_Param *param)
{
	/* Fill the thread_param struct */
	switch (param_type) {
	case TEE_PARAM_TYPE_NONE:
		rpc_msg_param->attr = THREAD_PARAM_ATTR_NONE;
		break;
	case TEE_PARAM_TYPE_VALUE_INPUT:
		*rpc_msg_param = THREAD_PARAM_VALUE(IN, param->value.a,
			param->value.b, 0);
		break;
	case TEE_PARAM_TYPE_VALUE_OUTPUT:
		*rpc_msg_param = THREAD_PARAM_VALUE(OUT, param->value.a,
			param->value.b, 0);
		break;
	case TEE_PARAM_TYPE_VALUE_INOUT:
		*rpc_msg_param = THREAD_PARAM_VALUE(INOUT, param->value.a,
			param->value.b, 0);
		break;
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		*rpc_msg_param = THREAD_PARAM_MEMREF(IN, mobj, *mobj_offset,
			param->memref.size);
		break;
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		*rpc_msg_param = THREAD_PARAM_MEMREF(OUT, mobj, *mobj_offset,
			param->memref.size);
		break;
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		*rpc_msg_param = THREAD_PARAM_MEMREF(INOUT, mobj, *mobj_offset,
			param->memref.size);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Perform copies into shared memory, if necessary */
	switch (param_type) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		if (!mobj)
			return TEE_ERROR_BAD_PARAMETERS;

		memcpy(mobj_va + *mobj_offset, param->memref.buffer,
			param->memref.size);
		*mobj_offset += param->memref.size;
		break;
	default:
		break;
	}

	return TEE_SUCCESS;
}

static TEE_Result rpc_postprocess_param(struct thread_param *rpc_msg_param,
					uint8_t *mobj_va,
					uint32_t *mobj_offset,
					uint32_t param_type,
					TEE_Param *param)
{
	switch (param_type) {
	case TEE_PARAM_TYPE_VALUE_INPUT:
		return TEE_ERROR_BAD_PARAMETERS;
	case TEE_PARAM_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_TYPE_VALUE_INOUT:
		if (rpc_msg_param->u.value.a > UINT32_MAX ||
		    rpc_msg_param->u.value.b > UINT32_MAX)
			return TEE_ERROR_BAD_PARAMETERS;

		param->value.a = (uint32_t)rpc_msg_param->u.value.a;
		param->value.b = (uint32_t)rpc_msg_param->u.value.b;
		break;
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		return TEE_ERROR_BAD_PARAMETERS;
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		if (!mobj_va ||
		    (rpc_msg_param->u.memref.size > param->memref.size))
			return TEE_ERROR_BAD_PARAMETERS;

		memcpy(param->memref.buffer, mobj_va + *mobj_offset,
			rpc_msg_param->u.memref.size);
		*mobj_offset += rpc_msg_param->u.memref.size;
	default:
		break;
	}

	return TEE_SUCCESS;
}

static TEE_Result rpc_execute(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;

	struct mobj *mobj = NULL;
	uint8_t *mobj_va = NULL;

	uint32_t mobj_size = 0;
	uint32_t mobj_offset = 0;

	struct thread_param rpc_msg_params[TEE_NUM_PARAMS] = { 0 };

	uint8_t i;
	uint32_t param_type;
	uint32_t param_size;

	/* Compute RPC payload size */
	for (i = 0; i < TEE_NUM_PARAMS; i++) {
		param_type = TEE_PARAM_TYPE_GET(param_types, i);
		res = rpc_calc_param_size(param_type, &params[i], &param_size);
		if (res != TEE_SUCCESS)
			goto exit;

		if (ADD_OVERFLOW(mobj_size, param_size, &mobj_size)) {
			res = TEE_ERROR_SECURITY;
			goto exit;
		}
	}

	/* Allocate RPC payload with host, if necessary */
	if (mobj_size) {
		mobj = thread_rpc_alloc_host_payload(mobj_size);
		if (!mobj) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		mobj_va = mobj_get_va(mobj, 0);
		if (!mobj_va) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}
	}

	/* Prepare parameters for the RPC */
	for (i = 0; i < TEE_NUM_PARAMS; i++) {
		param_type = TEE_PARAM_TYPE_GET(param_types, i);
		res = rpc_preprocess_param(&rpc_msg_params[i], mobj, mobj_va,
			&mobj_offset, param_type, &params[i]);
	}

	/* Send RPC message to the host */
	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_GENERIC,
		ARRAY_SIZE(rpc_msg_params), rpc_msg_params);
	if (res != TEE_SUCCESS)
		goto exit;

	/* Process output parameters from the RPC */
	mobj_offset = 0;
	for (i = 0; i < TEE_NUM_PARAMS; i++) {
		param_type = TEE_PARAM_TYPE_GET(param_types, i);
		res = rpc_postprocess_param(&rpc_msg_params[i], mobj_va,
			&mobj_offset, param_type, &params[i]);
		if (res != TEE_SUCCESS)
			goto exit;
	}

exit:
	if (mobj)
		thread_rpc_free_host_payload(mobj);

	return res;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_GRPC_EXECUTE:
		return rpc_execute(param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct tee_ta_session *sess = NULL;

	sess = tee_ta_get_calling_session();
	if (!sess)
		return TEE_ERROR_ACCESS_DENIED;

	if (!is_user_ta_ctx(sess->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static void close_session(void *sess_ctx __unused)
{
	/* Nothing */
}

pseudo_ta_register(.uuid = PTA_RPC_UUID, .name = "system.rpc",
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
