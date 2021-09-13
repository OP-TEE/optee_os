// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Arm Limited
 */
#include <assert.h>
#include <bench.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/secure_partition.h>
#include <kernel/spinlock.h>
#include <kernel/spmc_sp_handler.h>
#include <mm/mobj.h>
#include <mm/sp_mem.h>
#include <mm/vm.h>
#include <optee_ffa.h>
#include <string.h>
#include "thread_private.h"

void spmc_sp_start_thread(struct thread_smc_args *args)
{
	thread_sp_alloc_and_run(args);
}

static void ffa_set_error(struct thread_smc_args *args, uint32_t error)
{
	args->a0 = FFA_ERROR;
	args->a2 = error;
}

static TEE_Result ffa_get_dst(struct thread_smc_args *args,
			      struct sp_session *caller,
			      struct sp_session **dst)
{
	struct sp_session *s = NULL;

	if (args->a2 != FFA_PARAM_MBZ)
		return FFA_INVALID_PARAMETERS;

	s = sp_get_session(FFA_DST(args->a1));

	/* Message came from the NW */
	if (!caller) {
		if (!s) {
			EMSG("Neither destination nor source is a SP");
			return FFA_INVALID_PARAMETERS;
		}
	} else {
		/* Check if the source matches the endpoint we came from */
		if (FFA_SRC(args->a1) != caller->endpoint_id) {
			EMSG("Source address doesn't match the endpoint id");
			return FFA_INVALID_PARAMETERS;
		}
	}

	*dst = s;

	return FFA_OK;
}

static struct sp_mem_receiver *get_sp_mem_receiver(struct sp_session *s,
						   struct sp_mem *smem)
{
	struct sp_mem_receiver *receiver  = NULL;

	/*
	 * FF-A Spec 8.10.2:
	 * Each Handle identifies a single unique composite memory region
	 * description that is, there is a 1:1 mapping between the two.
	 *
	 * Each memory share has an unique handle. We can only have each SP
	 * once as a receiver in the memory share. For each receiver of a
	 * memory share, we have one sp_mem_access_descr object.
	 * This means that there can only be one SP linked to a specific
	 * struct sp_mem_access_descr.
	 */
	SLIST_FOREACH(receiver, &smem->receivers, link) {
		if (receiver->perm.endpoint_id == s->endpoint_id)
			return receiver;
	}
	return NULL;
}

static int add_mem_region_to_sp(struct ffa_mem_access *mem_acc,
				struct sp_mem *smem)
{
	struct ffa_mem_access_perm *access_perm =
		&mem_acc->access_perm;
	uint16_t endpoint_id = 0;
	struct sp_session *s = NULL;
	struct sp_mem_receiver *receiver = NULL;

	endpoint_id = READ_ONCE(access_perm->endpoint_id);
	s = sp_get_session(endpoint_id);

	/* Only add memory shares of loaded SPs */
	if (!s)
		return FFA_DENIED;

	/* Only allow each endpoint once */
	if (get_sp_mem_receiver(s, smem))
		return FFA_DENIED;

	receiver = calloc(1, sizeof(struct sp_mem_receiver));

	if (!receiver)
		return FFA_NO_MEMORY;

	receiver->smem = smem;

	receiver->ref_count = 0;
	receiver->perm.endpoint_id = READ_ONCE(access_perm->endpoint_id);
	receiver->perm.perm = READ_ONCE(access_perm->perm);
	receiver->perm.flags = READ_ONCE(access_perm->flags);

	SLIST_INSERT_HEAD(&smem->receivers, receiver, link);

	return FFA_OK;
}

static void spmc_sp_handle_mem_share(struct thread_smc_args *args,
				     struct ffa_rxtx *rxtx,
				     struct sp_session *owner_sp)
{
	uint64_t global_handle = 0;
	int res = FFA_OK;
	uint32_t ret_w2 = 0;
	uint32_t ret_w3 = 0;

	cpu_spin_lock(&rxtx->spinlock);

	/*clear top bits*/
	args->a1 &= 0x0000ffff;

	res = spmc_sp_add_share(rxtx, args->a1, &global_handle, owner_sp);
	if (!res) {
		reg_pair_from_64(global_handle, &ret_w3, &ret_w2);
		args->a3 = ret_w3;
		args->a2 = ret_w2;
		args->a0 = FFA_SUCCESS_32;
	} else {
		ffa_set_error(args, res);
	}

	cpu_spin_unlock(&rxtx->spinlock);
}

static int spmc_sp_add_sp_region(struct sp_mem *smem,
				 struct ffa_address_range *mem_reg,
				 struct sp_session *owner_sp,
				 uint8_t highest_permission)
{
	return FFA_OK;
}

static int spmc_sp_add_nw_region(struct sp_mem *smem,
				 struct ffa_mem_region *mem_reg)
{
	return FFA_OK;
}

int spmc_sp_add_share(struct ffa_rxtx *rxtx,
		      size_t blen, uint64_t *global_handle,
		      struct sp_session *owner_sp)
{
	int res = FFA_INVALID_PARAMETERS;
	unsigned int num_mem_accs = 0;
	unsigned int i = 0;
	struct ffa_mem_access *mem_acc = NULL;
	size_t needed_size = 0;
	size_t addr_range_offs = 0;
	struct ffa_mem_region *mem_reg = NULL;
	uint8_t highest_permission = 0;
	struct sp_mem *smem = sp_mem_new();
	struct ffa_mem_transaction *input_descr = rxtx->rx;

	if (!smem)
		return FFA_NO_MEMORY;

	if (owner_sp) {
		if (owner_sp->endpoint_id !=
		    READ_ONCE(input_descr->sender_id)) {
			res = FFA_DENIED;
			goto cleanup;
		}
	} else {
		if (sp_get_session(READ_ONCE(input_descr->sender_id))) {
			res = FFA_DENIED;
			goto cleanup;
		}
	}

	num_mem_accs = READ_ONCE(input_descr->mem_access_count);
	mem_acc = input_descr->mem_access_array;

	if (!num_mem_accs) {
		res = FFA_DENIED;
		goto cleanup;
	}

	/* Store the ffa_mem_transaction */
	smem->transaction.sender_id = READ_ONCE(input_descr->sender_id);
	smem->transaction.mem_reg_attr = READ_ONCE(input_descr->mem_reg_attr);
	smem->transaction.flags = READ_ONCE(input_descr->flags);
	smem->transaction.tag = READ_ONCE(input_descr->tag);
	smem->transaction.mem_access_count = 0;

	SLIST_INIT(&smem->receivers);

	if (MUL_OVERFLOW(num_mem_accs, sizeof(struct ffa_mem_access),
			 &needed_size)) {
		res = FFA_NO_MEMORY;
		goto cleanup;
	}
	if (ADD_OVERFLOW(needed_size, sizeof(*input_descr), &needed_size)) {
		res = FFA_NO_MEMORY;
		goto cleanup;
	}

	if (needed_size > blen) {
		res = FFA_NO_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < num_mem_accs; i++)
		highest_permission |= READ_ONCE(mem_acc[i].access_perm.perm);

	addr_range_offs = READ_ONCE(mem_acc[0].region_offs);
	mem_reg = (void *)((char *)input_descr + addr_range_offs);

	/* Iterate over all the addresses */
	if (owner_sp) {
		for (i = 0; i < READ_ONCE(mem_reg->address_range_count); i++) {
			struct ffa_address_range *addr_range = NULL;

			addr_range =  &mem_reg->address_range_array[i];

			if ((char *)addr_range +
			    sizeof(struct ffa_mem_region) >
			    (char *)rxtx->rx + rxtx->size) {
				res = FFA_NO_MEMORY;
				goto cleanup;
			}
			res = spmc_sp_add_sp_region(smem, addr_range,
						    owner_sp,
						    highest_permission);
			if (res)
				goto cleanup;
		}
	} else {
		res = spmc_sp_add_nw_region(smem, mem_reg);
		if (res)
			goto cleanup;
	}

	/* Add the memory address to the SP */
	for (i = 0; i < num_mem_accs; i++) {
		res = add_mem_region_to_sp(&mem_acc[i], smem);
		if (res)
			goto cleanup;
	}
	*global_handle = smem->transaction.global_handle;
	return FFA_OK;

cleanup:
	/* Remove all receivers*/
	while (!SLIST_EMPTY(&smem->receivers)) {
		struct sp_mem_receiver *receiver = NULL;

		receiver = SLIST_FIRST(&smem->receivers);
		SLIST_REMOVE_HEAD(&smem->receivers, link);
		free(receiver);
	}
	/* Remove all regions*/
	while (!SLIST_EMPTY(&smem->regions)) {
		struct sp_mem_map_region *region = SLIST_FIRST(&smem->regions);

		SLIST_REMOVE_HEAD(&smem->regions, link);
		mobj_put(region->mobj);
		free(region);
	}
	sp_mem_remove(smem);
	return res;
}

static struct sp_session *
ffa_handle_sp_direct_req(struct thread_smc_args *args,
			 struct sp_session *caller_sp)
{
	struct sp_session *dst = NULL;
	TEE_Result res = FFA_OK;

	if (args->a2 != FFA_PARAM_MBZ) {
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return NULL;
	}

	res = ffa_get_dst(args, caller_sp, &dst);
	if (res) {
		/* Tried to send message to an incorrect endpoint */
		ffa_set_error(args, res);
		return caller_sp;
	}
	if (!dst) {
		EMSG("Request to normal world not supported");
		ffa_set_error(args, FFA_NOT_SUPPORTED);
		return NULL;
	}

	cpu_spin_lock(&dst->spinlock);
	if (dst->state != sp_idle) {
		DMSG("SP is busy");
		ffa_set_error(args, FFA_BUSY);
		cpu_spin_unlock(&dst->spinlock);
		return caller_sp;
	}

	dst->state = sp_busy;
	cpu_spin_unlock(&dst->spinlock);

	/*
	 * Store the calling endpoint id. This will make it possible to check
	 * if the response is sent back to the correct endpoint.
	 */
	dst->caller_id = FFA_SRC(args->a1);

	/* Forward the message to the destination SP */
	res = sp_enter(args, dst);
	if (res) {
		/* The SP Panicked */
		ffa_set_error(args, FFA_ABORTED);
		/* Return error to calling SP */
		return caller_sp;
	}

	return dst;
}

static struct sp_session *
ffa_handle_sp_direct_resp(struct thread_smc_args *args,
			  struct sp_session *caller_sp)
{
	struct sp_session *dst = NULL;
	TEE_Result res = FFA_OK;

	if (!caller_sp) {
		EMSG("Response from normal world not supported");
		ffa_set_error(args, FFA_NOT_SUPPORTED);
		return NULL;
	}

	res = ffa_get_dst(args, caller_sp, &dst);
	if (res) {
		/* Tried to send response to an incorrect endpoint */
		ffa_set_error(args, res);
		return caller_sp;
	}

	if (caller_sp->state != sp_busy) {
		EMSG("SP is not waiting for a request");
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return caller_sp;
	}

	if (caller_sp->caller_id != FFA_DST(args->a1)) {
		EMSG("FFA_MSG_SEND_DIRECT_RESP to incorrect SP");
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return caller_sp;
	}

	caller_sp->caller_id = 0;

	cpu_spin_lock(&caller_sp->spinlock);
	caller_sp->state = sp_idle;
	cpu_spin_unlock(&caller_sp->spinlock);

	if (!dst) {
		/* Send message back to the NW */
		return NULL;
	}

	/* Forward the message to the destination SP */
	res = sp_enter(args, dst);
	if (res) {
		/* The SP Panicked */
		ffa_set_error(args, FFA_ABORTED);
		/* Return error to calling SP */
		return caller_sp;
	}
	return dst;
}

static struct sp_session *
ffa_handle_sp_error(struct thread_smc_args *args,
		    struct sp_session *caller_sp)
{
	struct sp_session *dst = NULL;

	dst = sp_get_session(FFA_DST(args->a1));

	/* FFA_ERROR Came from Noral World */
	if (caller_sp)
		caller_sp->state = sp_idle;

	/* If dst == NULL send message to Normal World */
	if (dst && sp_enter(args, dst)) {
		/*
		 * We can not return the error. Unwind the call chain with one
		 * link. Set the state of the SP to dead.
		 */
		dst->state = sp_dead;
		/* Create error. */
		ffa_set_error(args, FFA_DENIED);
		return  sp_get_session(dst->caller_id);
	}

	return dst;
}

static void handle_features(struct thread_smc_args *args)
{
	uint32_t ret_fid = 0;
	uint32_t ret_w2 = FFA_PARAM_MBZ;

	switch (args->a1) {
#ifdef ARM64
	case FFA_RXTX_MAP_64:
#endif
	case FFA_RXTX_MAP_32:
		ret_fid = FFA_SUCCESS_32;
		ret_w2 = 0; /* 4kB Minimum buffer size and alignment boundary */
		break;
	case FFA_ERROR:
	case FFA_VERSION:
	case FFA_SUCCESS_32:
#ifdef ARM64
	case FFA_SUCCESS_64:
#endif
	default:
		ret_fid = FFA_ERROR;
		ret_w2 = FFA_NOT_SUPPORTED;
		break;
	}

	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, ret_w2, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

/*
 * FF-A messages handler for SP. Every messages for or from a SP is handled
 * here. This is the entry of the sp_spmc kernel thread. The caller_sp is set
 * to NULL when it is the Normal World.
 */
void spmc_sp_msg_handler(struct thread_smc_args *args,
			 struct sp_session *caller_sp)
{
	thread_check_canaries();
	do {
		switch (args->a0) {
		case FFA_MSG_SEND_DIRECT_REQ_32:
			caller_sp = ffa_handle_sp_direct_req(args, caller_sp);
			break;
		case FFA_MSG_SEND_DIRECT_RESP_32:
			caller_sp = ffa_handle_sp_direct_resp(args, caller_sp);
			break;
		case FFA_ERROR:
			caller_sp = ffa_handle_sp_error(args, caller_sp);
			break;
		case FFA_MSG_WAIT:
			/* FFA_WAIT gives control back to NW */
			cpu_spin_lock(&caller_sp->spinlock);
			caller_sp->state = sp_idle;
			cpu_spin_unlock(&caller_sp->spinlock);
			caller_sp = NULL;
			break;
#ifdef ARM64
		case FFA_RXTX_MAP_64:
#endif
		case FFA_RXTX_MAP_32:
			ts_push_current_session(&caller_sp->ts_sess);
			spmc_handle_rxtx_map(args, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		case FFA_RXTX_UNMAP:
			ts_push_current_session(&caller_sp->ts_sess);
			spmc_handle_rxtx_unmap(args, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		case FFA_RX_RELEASE:
			ts_push_current_session(&caller_sp->ts_sess);
			spmc_handle_rx_release(args, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		case FFA_ID_GET:
			args->a0 = FFA_SUCCESS_32;
			args->a2 = caller_sp->endpoint_id;
			sp_enter(args, caller_sp);
			break;
		case FFA_VERSION:
			spmc_handle_version(args);
			sp_enter(args, caller_sp);
			break;
		case FFA_FEATURES:
			handle_features(args);
			sp_enter(args, caller_sp);
			break;
		case FFA_PARTITION_INFO_GET:
			ts_push_current_session(&caller_sp->ts_sess);
			spmc_handle_partition_info_get(args, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
#ifdef ARM64
		case FFA_MEM_SHARE_64:
#endif
		case FFA_MEM_SHARE_32:
			ts_push_current_session(&caller_sp->ts_sess);
			spmc_sp_handle_mem_share(args, &caller_sp->rxtx,
						 caller_sp);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		default:
			EMSG("Unhandled FFA function ID %#"PRIx32,
			     (uint32_t)args->a0);
			ffa_set_error(args, FFA_INVALID_PARAMETERS);
			sp_enter(args, caller_sp);
		}
	} while (caller_sp);
}
