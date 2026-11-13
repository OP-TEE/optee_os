// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/panic.h>
#include <kernel/thread_private.h>
#include <optee_msg.h>
#include <optee_rpc_cmd.h>
#include <string.h>
#include <tee/entry_std.h>
#include <utee_defines.h>
#include <util.h>

#include "optee_rpmi_private.h"

TEE_Result thread_rpmi_handle_control(uint32_t caller, uint32_t op,
				      const void *service_data,
				      size_t service_len)
{
	thread_check_canaries();

	if (op == OPTEE_RPMI_YIELDING_CALL_WITH_ARG) {
		uint32_t req_hi = 0;
		uint32_t req_lo = 0;

		if (service_len != sizeof(struct optee_rpmi_call_req))
			return TEE_ERROR_BAD_PARAMETERS;

		reg_pair_from_64((uintptr_t)service_data, &req_hi, &req_lo);
		/*
		 * a0/a1 carry the request pointer's high/low halves; a2 is the
		 * caller ID. Remaining arguments are unused and zero.
		 * The request is in a reusable per-hart buffer, so thread entry
		 * must copy it to its own stack before it can yield.
		 */
		thread_alloc_and_run(req_hi, req_lo, caller, 0, 0, 0);
		/* No thread was acquired, so the command has not started. */
		return TEE_ERROR_BUSY;

	} else if (op == OPTEE_RPMI_YIELDING_CALL_RESUME) {
		const struct optee_rpmi_resume_req *req = service_data;
		uint32_t thread_id = 0;

		if (service_len != sizeof(*req))
			return TEE_ERROR_BAD_PARAMETERS;

		thread_id = get_unaligned_le32(&req->resume_token);
		/* Common code checks the index and suspended state. */
		thread_resume_from_rpc(thread_id, 0, 0, 0, 0);
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

/* Validate and execute the call while holding its parcel reference. */
static TEE_Result yielding_call_with_arg(const struct optee_rpmi_call_req *req)
{
	struct thread_ctx *thr = &threads[thread_get_id()];
	uint64_t global_id = TEE_U64_FROM_LITTLE_ENDIAN(req->global_id);
	uint64_t arg_offset = TEE_U64_FROM_LITTLE_ENDIAN(req->arg_offset);
	uint64_t rpc_offset = TEE_U64_FROM_LITTLE_ENDIAN(req->rpc_offset);
	size_t arg_size = TEE_U32_FROM_LITTLE_ENDIAN(req->arg_size);
	size_t rpc_size = TEE_U32_FROM_LITTLE_ENDIAN(req->rpc_size);
	struct optee_msg_arg *rpc_arg = NULL;
	struct optee_msg_arg *arg = NULL;
	struct mobj *mobj = NULL;
	uint32_t num_params = 0;
	TEE_Result res = TEE_SUCCESS;

	if (arg_offset > SIZE_MAX || rpc_offset > SIZE_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (arg_size < sizeof(struct optee_msg_arg) ||
	    rpc_size < OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS))
		return TEE_ERROR_BAD_PARAMETERS;

	res = mobj_rpmi_get_by_cookie(global_id, &mobj);
	if (res)
		return res;
	res = mobj_inc_map(mobj);
	if (res) {
		mobj_put(mobj);
		return res;
	}

	res = TEE_ERROR_BAD_PARAMETERS;
	arg = mobj_get_va(mobj, arg_offset, arg_size);
	rpc_arg = mobj_get_va(mobj, rpc_offset, rpc_size);
	/* Both buffers must fit in the parcel and be aligned for their type. */
	if (!arg || !rpc_arg ||
	    !IS_ALIGNED_WITH_TYPE(arg, struct optee_msg_arg) ||
	    !IS_ALIGNED_WITH_TYPE(rpc_arg, struct optee_msg_arg))
		goto out_failed;
	/* Command and RPC argument buffers must not overlap. */
	if (arg_offset < rpc_offset + rpc_size &&
	    rpc_offset < arg_offset + arg_size)
		goto out_failed;

	num_params = READ_ONCE(arg->num_params);
	if (num_params > OPTEE_MSG_MAX_NUM_PARAMS ||
	    OPTEE_MSG_GET_ARG_SIZE(num_params) != arg_size)
		goto out_failed;

	thr->rpc_arg = rpc_arg;
	res = tee_entry_std(arg, num_params);
	/* Cache cleanup can itself issue RPC while the call is still live. */
	thread_rpc_shm_cache_clear(&thr->shm_cache);
	thr->rpc_arg = NULL;

out_failed:
	mobj_dec_map(mobj);
	mobj_put(mobj);

	return res;
}

/* C entry for a secure thread started by thread_alloc_and_run(). */
uint32_t __thread_std_abi_entry(uint32_t a0, uint32_t a1, uint32_t a2,
				uint32_t a3 __unused, uint32_t a4 __unused,
				uint32_t a5 __unused)
{
	const void *service_data =
		(const void *)(uintptr_t)reg_pair_to_64(a0, a1);
	struct optee_rpmi_call_req req = {};
	TEE_Result res = TEE_SUCCESS;

	/* Copy before a yield can allow the request buffer to be reused. */
	memcpy(&req, service_data, sizeof(req));
	thread_get_tsd()->rpmi_caller_id = a2;
	res = yielding_call_with_arg(&req);
	thread_get_tsd()->rpmi_caller_id = 0;

	return res;
}

/* Encode a parcel-relative RPC memory reference. */
static bool set_pmem(struct optee_msg_param *mp, const struct thread_param *p)
{
	struct mobj *mobj = p->u.memref.mobj;
	uint64_t offs = p->u.memref.offs;

	mp->attr = p->attr - THREAD_PARAM_ATTR_MEMREF_IN +
		   OPTEE_MSG_ATTR_TYPE_PMEM_INPUT;
	mp->u.pmem.size = p->u.memref.size;
	/* Encode NULL with a zero identity and offset, preserving size. */
	if (!mobj) {
		mp->u.pmem.offs = 0;
		mp->u.pmem.global_id = 0;
		return true;
	}

	mp->u.pmem.global_id = mobj_get_cookie(mobj);
	if (!optee_rpmi_nonce(mp->u.pmem.global_id) ||
	    !mobj_is_nonsec(mobj) || offs > mobj->size ||
	    p->u.memref.size > mobj->size - offs)
		return false;

	mp->u.pmem.offs = rpmi_shm_view_offset(mobj) + offs;

	return true;
}

/* Prepare the caller-supplied RPC argument buffer. */
static uint32_t get_rpc_arg(uint32_t cmd, size_t num_params,
			    struct thread_param *params,
			    struct optee_msg_arg **arg_ret)
{
	struct optee_msg_arg *arg = threads[thread_get_id()].rpc_arg;
	size_t n = 0;

	if (!arg || num_params > THREAD_RPC_MAX_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(arg, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	arg->cmd = cmd;
	arg->num_params = num_params;
	arg->ret = TEE_ERROR_GENERIC;
	for (n = 0; n < num_params; n++) {
		struct thread_param *p = params + n;
		struct optee_msg_param *mp = arg->params + n;

		switch (p->attr) {
		case THREAD_PARAM_ATTR_NONE:
			break;
		case THREAD_PARAM_ATTR_VALUE_IN:
		case THREAD_PARAM_ATTR_VALUE_OUT:
		case THREAD_PARAM_ATTR_VALUE_INOUT:
			mp->attr = p->attr - THREAD_PARAM_ATTR_VALUE_IN +
				   OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			mp->u.value.a = p->u.value.a;
			mp->u.value.b = p->u.value.b;
			mp->u.value.c = p->u.value.c;
			break;
		case THREAD_PARAM_ATTR_MEMREF_IN:
		case THREAD_PARAM_ATTR_MEMREF_OUT:
		case THREAD_PARAM_ATTR_MEMREF_INOUT:
			if (!set_pmem(mp, p))
				return TEE_ERROR_BAD_PARAMETERS;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	*arg_ret = arg;

	return TEE_SUCCESS;
}

/* Copy RPC output values and sizes back to the original parameters. */
static uint32_t get_rpc_arg_res(struct optee_msg_arg *arg, size_t num_params,
				struct thread_param *params)
{
	size_t n = 0;

	for (n = 0; n < num_params; n++) {
		switch (params[n].attr) {
		case THREAD_PARAM_ATTR_VALUE_OUT:
		case THREAD_PARAM_ATTR_VALUE_INOUT:
			params[n].u.value.a = arg->params[n].u.value.a;
			params[n].u.value.b = arg->params[n].u.value.b;
			params[n].u.value.c = arg->params[n].u.value.c;
			break;
		case THREAD_PARAM_ATTR_MEMREF_OUT:
		case THREAD_PARAM_ATTR_MEMREF_INOUT:
			params[n].u.memref.size = arg->params[n].u.pmem.size;
			break;
		default:
			break;
		}
	}

	return arg->ret;
}

static void thread_rpmi_rpc(void)
{
	/*
	 * Yield for an RPC prepared in thr->rpc_arg, the shared buffer set by
	 * yielding_call_with_arg(). Arguments and results use this buffer,
	 * so thread_rpc() does not need a register-argument array.
	 */
	thread_rpc(NULL);
}

/* Issue an RPC through the caller-supplied buffer and collect its result. */
uint32_t thread_rpc_cmd(uint32_t cmd, size_t num_params,
			struct thread_param *params)
{
	struct optee_msg_arg *arg = NULL;
	uint32_t res = TEE_SUCCESS;

	res = get_rpc_arg(cmd, num_params, params, &arg);
	if (res)
		return res;

	thread_rpmi_rpc();

	return get_rpc_arg_res(arg, num_params, params);
}

static void release_payload(unsigned int type, uint64_t global_id)
{
	struct thread_param p = THREAD_PARAM_VALUE(IN, type, global_id, 0);
	uint32_t caller = thread_get_tsd()->rpmi_caller_id;
	TEE_Result res = TEE_SUCCESS;

	/* Release secure receiver interest before Linux reclaims the parcel. */
	res = rpmi_shm_unregister(optee_rpmi_shm_context(),
				  optee_rpmi_channel(), caller, global_id);
	if (res) {
		EMSG("Cannot retire RPC parcel: %#"PRIx32, res);
		return;
	}

	thread_rpc_cmd(OPTEE_RPC_CMD_SHM_FREE, 1, &p);
}

static void free_payload_with_shm_type(unsigned int type, struct mobj *mobj)
{
	uint64_t global_id = 0;

	if (!mobj)
		return;

	global_id = mobj_get_cookie(mobj);
	/* Matching inc in alloc_payload_with_shm_type(). */
	mobj_dec_map(mobj);
	mobj_put(mobj);
	release_payload(type, global_id);
}

static struct mobj *alloc_payload_with_shm_type(size_t size, unsigned int type)
{
	struct thread_param p = THREAD_PARAM_VALUE(IN, type, size, 8);
	struct optee_msg_arg *arg = threads[thread_get_id()].rpc_arg;
	struct mobj *payload = NULL;
	struct mobj *mobj = NULL;
	uint64_t alloc_size = 0;
	uint64_t global_id = 0;
	uint64_t offset = 0;
	TEE_Result res = TEE_SUCCESS;

	res = thread_rpc_cmd(OPTEE_RPC_CMD_SHM_ALLOC, 1, &p);
	if (res || arg->num_params != 1 ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_PMEM_OUTPUT)
		return NULL;

	global_id = READ_ONCE(arg->params[0].u.pmem.global_id);
	/* Offset identifies the start of the logical SHM. */
	offset = READ_ONCE(arg->params[0].u.pmem.offs);
	alloc_size = READ_ONCE(arg->params[0].u.pmem.size);
	if (offset > SIZE_MAX || alloc_size > SIZE_MAX || alloc_size < size)
		goto out_failed;

	res = mobj_rpmi_get_by_cookie(global_id, &mobj);
	if (res)
		goto out_failed;

	payload = rpmi_shm_view_alloc(mobj, offset, alloc_size);
	if (!payload) {
		mobj_put(mobj);
		goto out_failed;
	}

	res = mobj_inc_map(payload);
	if (res) {
		mobj_put(payload);
		goto out_failed;
	}

	return payload;

out_failed:
	/* Release the payload if not NULL. */
	if (optee_rpmi_nonce(global_id))
		release_payload(type, global_id);

	return NULL;
}

struct mobj *thread_rpc_alloc_payload(size_t size)
{
	return alloc_payload_with_shm_type(size, OPTEE_RPC_SHM_TYPE_APPL);
}

struct mobj *thread_rpc_alloc_kernel_payload(size_t size)
{
	return alloc_payload_with_shm_type(size, OPTEE_RPC_SHM_TYPE_KERNEL);
}

struct mobj *thread_rpc_alloc_global_payload(size_t size)
{
	return alloc_payload_with_shm_type(size, OPTEE_RPC_SHM_TYPE_GLOBAL);
}

void thread_rpc_free_payload(struct mobj *mobj)
{
	free_payload_with_shm_type(OPTEE_RPC_SHM_TYPE_APPL, mobj);
}

void thread_rpc_free_kernel_payload(struct mobj *mobj)
{
	free_payload_with_shm_type(OPTEE_RPC_SHM_TYPE_KERNEL, mobj);
}

void thread_rpc_free_global_payload(struct mobj *mobj)
{
	free_payload_with_shm_type(OPTEE_RPC_SHM_TYPE_GLOBAL, mobj);
}
