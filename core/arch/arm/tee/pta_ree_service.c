/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#include <kernel/pseudo_ta.h>
#include <kernel/msg_param.h>
#include <optee_rpc_cmd.h>
#include <pta_ree_service.h>
#include <string.h>
#include <tee/tee_fs_rpc.h>

static uint32_t get_instance_id(struct tee_ta_session *sess)
{
	return sess->ctx->ops->get_instance_id(sess->ctx);
}

/**
 * is_param_memref() - return true if parameter is memory reference
 */
static inline bool is_param_memref(uint32_t param_types, uint32_t idx)
{
	uint32_t ptype = TEE_PARAM_TYPE_GET(param_types, idx);

	switch (ptype) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		return true;
	default:
		return false;
	}
}

/**
 * is_param_out() - return true if parameter can be filled by REE (output)
 */
static inline bool is_param_out(uint32_t param_types, uint32_t idx)
{
	uint32_t ptype = TEE_PARAM_TYPE_GET(param_types, idx);

	switch  (ptype) {
	case TEE_PARAM_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_TYPE_VALUE_INOUT:
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		return true;
	default:
		return false;
	}
}

/**
 * is_param_value() - returns true if parameter is value
 */
static inline bool is_param_value(uint32_t param_types, uint32_t idx)
{
	uint32_t ptype = TEE_PARAM_TYPE_GET(param_types, idx);

	switch (ptype) {
	case TEE_PARAM_TYPE_VALUE_INPUT:
	case TEE_PARAM_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_TYPE_VALUE_INOUT:
		return true;
	default:
		return false;
	}
}

/**
 * is_param_none() - if the parameter has nothing to send/receive to REE
 */
static inline bool is_param_none(uint32_t param_types, uint32_t idx)
{
	return (TEE_PARAM_TYPE_GET(param_types, idx) == TEE_PARAM_TYPE_NONE);
}

/**
 * alloc_transient_shm() - allocate buffer with RPC call scope
 * Allocates a buffer whose lifetime is the RPC call. The buffer
 * gets freed once the call returns the data is filled back to
 * the UTA buffer.
 */
static void *alloc_transient_shm(size_t size, struct mobj **mobj)
{
	paddr_t p;
	void *va;

	*mobj = thread_rpc_alloc_payload(size);
	if (!*mobj)
		return NULL;

	if (mobj_get_pa(*mobj, 0, 0, &p))
		goto err;

	if (!ALIGNMENT_IS_OK(p, uint64_t))
		goto err;

	va = mobj_get_va(*mobj, 0);
	if (!va)
		goto err;

	return va;

err:
	thread_rpc_free_payload(*mobj);
	return NULL;
}

/**
 * free_transient_shm() - free the transient buffer
 */
static void free_transient_shm(struct mobj *mobj)
{
	thread_rpc_free_payload(mobj);
}

/**
 * prepare_memref_params() - fill the shared buffers if required
 */
static void *prepare_memref_params(TEE_Param *param, uint32_t param_type,
			 bool cached, struct mobj **mobj,
			 struct thread_param *tpm)
{
	size_t size = param->memref.size;
	void *va = NULL;

	/* Allocate shared buffer to be sent over to REE over RPC */
	if (cached)
		va = tee_fs_rpc_cache_alloc(size, mobj);
	else
		va = alloc_transient_shm(size, mobj);
	if (!va)
		return NULL;

	/*
	 * Prepare buffers as per their direction
	 * INPUT : Filled by TEE and to be interpreted by REE
	 * OUTPUT: Empty buffer sent by TEE to be filled by REE
	 * INPUT : Filled by TEE and overwritten by REE
	 */
	switch (param_type) {
	case  TEE_PARAM_TYPE_MEMREF_INPUT:
		*tpm = THREAD_PARAM_MEMREF(IN, *mobj, 0, size);
		memcpy(va, param->memref.buffer, size);
		break;
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		*tpm = THREAD_PARAM_MEMREF(OUT, *mobj, 0, size);
		break;
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		*tpm = THREAD_PARAM_MEMREF(INOUT, *mobj, 0, size);
		memcpy(va, param->memref.buffer, size);
		break;
	default:
		goto err;
	}

	return va;

err:
	if (!cached)
		free_transient_shm(*mobj);
	return NULL;
}

/**
 * find_ree_service() - find if expected REE service is alive
 */
static TEE_Result find_ree_service(void *sess_ctx, uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	struct mobj *mobj;
	struct thread_param tpm[3];
	TEE_Result res = TEE_SUCCESS;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
	void *va;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Prepare RPC params for opening REE session */
	memset(tpm, 0, sizeof(tpm));

	/*
	 * Fill in the command ID. This will be handled by tee-supplicant to
	 * find if the REE service identified by UUID (params[0].memref) is
	 * available to service the UTA calls.
	 */
	tpm[0] = THREAD_PARAM_VALUE(IN,
			OPTEE_MRC_REE_SERVICE_OPEN,(uint64_t)sess_ctx, 0);

	/* Prepare to fill in REE service UUID */
	va = tee_fs_rpc_cache_alloc(params[0].memref.size, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	tpm[1] = THREAD_PARAM_MEMREF(OUT, mobj, 0, params[0].memref.size);
	memcpy(va, params[0].memref.buffer, params[0].memref.size);

	/* tee-supplicant will return a handle to REE service */
	tpm[2] = THREAD_PARAM_VALUE(OUT, 0, 0, 0);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_REE_SERVICE, 3, tpm);
	if (res == TEE_SUCCESS)
		params[1].value.a = tpm[2].u.value.a;

	return res;
}

/*
 * Trusted Application Entry Points
 */

/**
 * pta_ree_service_open_session() - open the session for the calling UTA
 */
static TEE_Result pta_ree_service_open_session(uint32_t param_types __unused,
		TEE_Param params[TEE_NUM_PARAMS] __unused,
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

/**
 * pta_ree_service_close_session() - close the session of calling TA
 * TODO: Seems like okay to do, but, a discussion is required. If doing
 * nothing is okay, this callback needs to be deleted.
 */
static void pta_ree_service_close_session(void *sess_ctx __unused)
{
	return;
}

/**
 * pta_ree_service_invoke_command() - invoke the custom REE command
 */
static TEE_Result pta_ree_service_invoke_command(void *sess_ctx,
					uint32_t cmd_id, uint32_t param_types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	bool cache_allocated = false;
	int32_t idx = 0;
	int32_t msg_params_count = 1;
	struct mobj *mobj[THREAD_RPC_MAX_NUM_PARAMS - 1];
	struct thread_param tpm[THREAD_RPC_MAX_NUM_PARAMS];
	TEE_Result res = TEE_SUCCESS;
	uint8_t i;
	void *va[THREAD_RPC_MAX_NUM_PARAMS - 1];

	/* Find the REE service if it's available */
	if (cmd_id == OPTEE_MRC_REE_SERVICE_OPEN)
		return find_ree_service(sess_ctx, param_types, params);

	/* The first parameter has to be input value */
	if (!is_param_value(param_types, 0))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Prepare RPC params */
	memset(tpm, 0, sizeof(tpm));

	/* params[0].value.a: handle to the service */
	tpm[0] = THREAD_PARAM_VALUE(IN, cmd_id,
				(uint64_t)sess_ctx, params[0].value.a);

	/*
	 * Allocate a cached buffer for first memref and for subsequent memrefs
	 * allocate a transient buffer which will be freed after this call.
	 */
	for (i = 1; i < THREAD_RPC_MAX_NUM_PARAMS; i++) {
		/* Reached end of params */
		if (is_param_none(param_types, i))
			break;

		msg_params_count++;

		/*
		 * If the parameter is memref, then prepare it based on the
		 * direction of data.
		 */
		if (is_param_memref(param_types, i)) {
			va[idx] = prepare_memref_params(&params[i],
					TEE_PARAM_TYPE_GET(param_types, i),
					cache_allocated ? false : true,
					&mobj[idx], &tpm[i]);
			if (!va[idx]) {
				res = TEE_ERROR_OUT_OF_MEMORY;
				goto err;
			}

			cache_allocated = true;
			idx++;
		} else {
			switch (TEE_PARAM_TYPE_GET(param_types, i)) {
			case TEE_PARAM_TYPE_VALUE_INPUT:
				tpm[i] = THREAD_PARAM_VALUE(IN,
						params[i].value.a,
						params[i].value.b, 0);
				break;
			case TEE_PARAM_TYPE_VALUE_OUTPUT:
				tpm[i] = THREAD_PARAM_VALUE(OUT,
						params[i].value.a,
						params[i].value.b, 0);
				break;
			case TEE_PARAM_TYPE_VALUE_INOUT:
				tpm[i] = THREAD_PARAM_VALUE(INOUT,
						params[i].value.a,
						params[i].value.b, 0);
				break;
			default:
				/* Warning fix */
				break;
			}
		}
	}

	/* Send the command to Normal World */
	res = thread_rpc_cmd(OPTEE_RPC_CMD_REE_SERVICE, msg_params_count, tpm);
	if (res != TEE_SUCCESS)
		goto err;

	/* Fill in OUT and INOUT params from relevant parameters */
	idx = 0;
	for (i = 0; i < msg_params_count; i++) {
		if (is_param_memref(param_types, i)) {
			idx++;

			/*
			 * If the param is memref and not OUTPUT, then REE is
			 * not expected to modify the data content, so, not
			 * copying it
			 */
			if (!is_param_out(param_types, i))
				continue;

			memcpy(params[i].memref.buffer,
					va[idx - 1], params[i].memref.size);
		} else {
			if (!is_param_out(param_types, i))
				continue;
			params[i].value.a = tpm[i].u.value.a;
			params[i].value.b = tpm[i].u.value.b;
		}
	}

err:
	while (idx && --idx)
		free_transient_shm(mobj[idx]);

	return res;
}

pseudo_ta_register(.uuid = PTA_REE_SERVICE_UUID, .name = "REE Service",
		.flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		.open_session_entry_point = pta_ree_service_open_session,
		.close_session_entry_point = pta_ree_service_close_session,
		.invoke_command_entry_point = pta_ree_service_invoke_command);
