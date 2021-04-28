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
#include <mm/mobj_ffa.h>
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

static struct sp_mem_access_descr *
get_sp_mem_access_descr(struct sp_session *s,
			struct mobj_ffa *m)
{
	struct sp_mem_access_descr *sma = NULL;

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
	SLIST_FOREACH(sma, &m->sp_head, link) {
		if (sma->perm.endpoint_id == s->endpoint_id)
			return sma;
	}
	return NULL;
}

static TEE_Result add_mem_region_to_sp(struct ffa_mem_access *mem_acc,
				       struct mobj_ffa *m)
{
	struct ffa_mem_access_perm *access_perm =
		&mem_acc->access_perm;
	uint16_t endpoint_id = 0;
	struct sp_session *s = NULL;
	struct sp_mem_access_descr *sma = NULL;

	endpoint_id = READ_ONCE(access_perm->endpoint_id);
	s = sp_get_session(endpoint_id);

	/* Only add memory shares of loaded SPs */
	if (!s)
		return FFA_DENIED;

	/* Only allow each endpoint once */
	if (get_sp_mem_access_descr(s, m))
		return FFA_DENIED;

	sma = calloc(1, sizeof(struct sp_mem_access_descr));

	if (!sma)
		return FFA_NO_MEMORY;

	sma->counter = 0;
	sma->perm.endpoint_id = s->endpoint_id;
	sma->perm.flags = access_perm->flags;
	sma->perm.perm = access_perm->perm;
	sma->m = m;

	SLIST_INSERT_HEAD(&m->sp_head, sma, link);

	return FFA_OK;
}

TEE_Result spmc_sp_add_share(struct ffa_mem_transaction *input_descr,
			     struct mobj_ffa *m, size_t blen)
{
	int rc = FFA_INVALID_PARAMETERS;
	unsigned int num_mem_accs = 0;
	unsigned int i = 0;
	struct ffa_mem_access *mem_acc = NULL;
	size_t needed_size = 0;
	struct sp_session *owner_sp = sp_get_active();
	size_t addr_range_offs = 0;
	struct ffa_mem_region *mem_reg = NULL;
	uint8_t highest_permission = 0;

	 /* Make sure that we don't allow spoofing of another endpoint id.*/
	if (owner_sp) {
		if (owner_sp->endpoint_id != input_descr->sender_id)
			return FFA_DENIED;
	} else {
		if (sp_get_session(input_descr->sender_id))
			return FFA_DENIED;
	}

	num_mem_accs = READ_ONCE(input_descr->mem_access_count);
	mem_acc = input_descr->mem_access_array;

	if (!num_mem_accs)
		return FFA_DENIED;

	/* Store the ffa_mem_transaction */
	memcpy(&m->transaction, (void *)input_descr, sizeof(m->transaction));
	SLIST_INIT(&m->sp_head);

	needed_size = (num_mem_accs * (sizeof(struct ffa_mem_access)))
		      + sizeof(*input_descr);

	if (needed_size > blen)
		return FFA_NO_MEMORY;

	for (i = 0; i < num_mem_accs; i++)
		highest_permission |= mem_acc[i].access_perm.perm;

	addr_range_offs = input_descr->mem_access_array[0].region_offs;
	mem_reg = (struct ffa_mem_region *)
		  ((char *)input_descr + addr_range_offs);

	/* Iterate over all the addresses */
	for (i = 0; i < mem_reg->address_range_count; i++) {
		paddr_t pa = mem_reg->address_range_array[i].address;
		size_t size = mem_reg->address_range_array[i].page_count *
			      SMALL_PAGE_SIZE;

		if (!sp_has_exclusive_access((paddr_t)pa, owner_sp, size)) {
			rc = FFA_DENIED;
			goto cleanup;
		}

		/*
		 * If we share memory from a SP, check if we are not sharing
		 * with a higher permission than the memory was originally
		 * mapped.
		 */
		if (owner_sp) {
			uint16_t prot = 0;
			struct sp_ctx *sp_ctx = NULL;

			sp_ctx = to_sp_ctx(owner_sp->ts_sess.ctx);

			if (vm_get_prot(&sp_ctx->uctx,
					(vaddr_t)vm_pa2va(&sp_ctx->uctx, pa),
					size, &prot)) {
				rc = FFA_DENIED;
				goto cleanup;
			}

			if ((highest_permission & FFA_MEM_ACC_RW) &&
			    !(prot & TEE_MATTR_PW)) {
				rc = FFA_DENIED;
				goto cleanup;
			}

			if ((highest_permission & FFA_MEM_ACC_EXE) &&
			    !(prot & TEE_MATTR_PX)) {
				rc = FFA_DENIED;
				goto cleanup;
			}
		}
	}

	/* Add the memory address to the SP */
	for (i = 0; i < num_mem_accs; i++) {
		rc = add_mem_region_to_sp(&mem_acc[i], m);
		if (rc)
			goto cleanup;
	}

	return FFA_OK;

cleanup:
	while (!SLIST_EMPTY(&m->sp_head)) {
		struct sp_mem_access_descr *sma = NULL;

		sma = SLIST_FIRST(&m->sp_head);
		SLIST_REMOVE_HEAD(&m->sp_head, link);
		free(sma);
	}
	return rc;
}

static bool check_rxtx(struct ffa_rxtx *rxtx)
{
	return rxtx && rxtx->rx && rxtx->tx && rxtx->size > 0;
}

static void zero_mem_region(struct mobj_ffa *mf, struct sp_session *s)
{
	size_t sz = mobj_ffa_get_page_count(mf) * SMALL_PAGE_SIZE;
	void *addr = NULL;
	struct sp_ctx *ctx = to_sp_ctx(s->ts_sess.ctx);

	ts_push_current_session(&s->ts_sess);
	addr = sp_get_mobj_va(&mf->mobj, ctx);
	memset(addr, 0, sz);
	ts_pop_current_session();
}

static TEE_Result check_retrieve_request(struct sp_mem_access_descr *sma,
					 struct ffa_mem_transaction *retr_dsc)
{
	struct ffa_mem_access *retr_access = NULL;
	bool zero_retrieve_flag = false;
	uint8_t share_perm = sma->perm.perm;
	uint8_t share_flags = sma->perm.flags;
	uint32_t retr_perm = 0;
	uint32_t retr_flags =  retr_dsc->flags;

	/*
	 * The request came for the endpoint. It should only have one
	 * ffa_mem_access element
	 */
	if (retr_dsc->mem_access_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	retr_access = &retr_dsc->mem_access_array[0];
	retr_perm = retr_access->access_perm.perm;
	/*
	 * Compare the permissions and flags of the original share(sm) with the
	 * current request (retr_dsc and access)
	 */

	/* Check if tag is correct */
	if (sma->m->transaction.tag != retr_dsc->tag) {
		EMSG("Incorrect tag! %lx %lx", sma->m->transaction.tag,
		     retr_dsc->tag);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check permissions  and flags*/
	if ((retr_perm & FFA_MEM_ACC_RW) &&
	    !(share_perm & FFA_MEM_ACC_RW)) {
		DMSG("Incorrect memshare permission set");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((retr_perm & FFA_MEM_ACC_EXE) &&
	    !(share_perm & FFA_MEM_ACC_EXE)) {
		DMSG("Incorrect memshare permission set");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((retr_flags & FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH)) {
		if (!(share_flags & FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH)) {
			/*
			 * If FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH is set in
			 * the request it also has to set in the original
			 * MEM_SHARE request.
			 */
			DMSG("Incorrect memshare clear flag set");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		if (!(retr_perm & FFA_MEM_ACC_RW)) {
			DMSG("CLEAR_RELINQUISH is only allowed for RW regions");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	/* Check global memory transaction descriptor values. */
	/*
	 * b’1: Retrieve the memory region only if the Sender
	 * requested the Relayer to zero its contents prior to retrieval
	 * by setting the Bit[0] in Table 8.20
	 */
	zero_retrieve_flag = retr_dsc->flags & FFA_MEMORY_REGION_FLAG_CLEAR;

	if (zero_retrieve_flag &&
	    !(sma->m->transaction.flags & FFA_MEMORY_REGION_FLAG_CLEAR)) {
		return FFA_INVALID_PARAMETERS;
	}
	/* Zero flag should only be set when we have write access */
	if (zero_retrieve_flag && !(retr_perm & FFA_MEM_ACC_RW)) {
		EMSG("Zero flag should not be set for read-only mem");
		return FFA_INVALID_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static void create_retrieve_response(void *dst_buffer,
				     struct sp_mem_access_descr *sma,
				     struct sp_session *s)
{
	size_t off = 0;
	struct ffa_mem_region *dst_region =  NULL;
	struct ffa_mem_transaction *d_ds = dst_buffer;
	struct ffa_address_range *addr_dst = NULL;
	struct sp_ctx *ctx = to_sp_ctx(s->ts_sess.ctx);

	/*
	 * We respond with a FFA_MEM_RETRIEVE_RESP which defines the
	 * following data in the rx buffer of the SP.
	 * struct mem_transaction_descr
	 * struct mem_access_descr //1 Element
	 * struct mem_region_descr
	 */
	/* Copy the mem_transaction_descr */
	memcpy(d_ds, &sma->m->transaction,
	       sizeof(sma->m->transaction));

	off = sizeof(struct ffa_mem_transaction) +
	      sizeof(struct ffa_mem_access);

	d_ds->mem_access_count = 1;

	/* Copy the mem_accsess_descr */
	d_ds->mem_access_array[0].region_offs = off;
	memcpy(&d_ds->mem_access_array[0].access_perm,
	       &sma->perm, sizeof(struct ffa_mem_access_perm));

	/* Copy the mem_region_descr */
	dst_region = (struct ffa_mem_region *)((vaddr_t)d_ds + off);

	/* We only return 1 virtual address */
	dst_region->address_range_count = 1;

	addr_dst = &dst_region->address_range_array[0];
	addr_dst->address = (uint64_t)sp_get_mobj_va(&sma->m->mobj, ctx);
	addr_dst->page_count = mobj_ffa_get_page_count(sma->m);
	dst_region->total_page_count = addr_dst->page_count;
}

static void ffa_mem_retrieve(struct thread_smc_args *args,
			     struct sp_session *caller_sp,
			     struct ffa_rxtx *rxtx)
{
	TEE_Result ret = FFA_OK;
	struct sp_mem_access_descr *sma = NULL;
	size_t tx_len = 0;
	struct ffa_mem_transaction *retr_dsc = NULL;
	uint32_t perm = TEE_MATTR_UR;
	struct ffa_mem_region *mem_region = NULL;
	uint64_t va = 0;
	struct mobj *m = NULL;
	bool original_zero_flag = false;

	if (!check_rxtx(rxtx) || !rxtx->tx_is_mine) {
		ret = FFA_DENIED;
		goto out;
	}

	tx_len = rxtx->size;
	retr_dsc = rxtx->rx;

	m = mobj_ffa_get_by_cookie(retr_dsc->global_handle, 0);
	if (!m) {
		DMSG("Incorrect handle");
		ret = FFA_DENIED;
		goto out;
	}

	sma = get_sp_mem_access_descr(caller_sp, to_mobj_ffa(m));
	if (!sma) {
		ret = FFA_INVALID_PARAMETERS;
		goto out;
	}

	original_zero_flag = sma->zero_flag;
	sma->zero_flag = retr_dsc->flags &
		       FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH;

	if (check_retrieve_request(sma, retr_dsc) != TEE_SUCCESS) {
		ret = FFA_INVALID_PARAMETERS;
		goto out;
	}

	if (!sma->counter) {
		struct ffa_mem_access *retr_access = NULL;

		retr_access = &retr_dsc->mem_access_array[0];

		/* Get the permission */
		if (retr_access->access_perm.perm & FFA_MEM_ACC_RW)
			perm = TEE_MATTR_URW;

		if (retr_access->access_perm.perm & FFA_MEM_ACC_EXE)
			perm |= TEE_MATTR_UX;

		/*
		 * Try to map the memory linked to the handle in
		 * sp_mem_access_descr.
		 */
		mem_region = (struct ffa_mem_region *)((vaddr_t)retr_dsc +
				retr_dsc->mem_access_array[0].region_offs);

		va = mem_region->address_range_array[0].address;

		ret = sp_map_shared_va(caller_sp, sma, perm, &va);

		if (ret)
			goto out;
	}

	sma->counter++;

	create_retrieve_response(rxtx->tx, sma, caller_sp);

	/* Set the memory value to 0 when FFA_MEMORY_REGION_FLAG_CLEAR is set */
	if (retr_dsc->flags & FFA_MEMORY_REGION_FLAG_CLEAR)
		zero_mem_region(sma->m, caller_sp);

	args->a0 = FFA_MEM_RETRIEVE_RESP;
	args->a1 = tx_len;
	args->a2 = tx_len;

	rxtx->tx_is_mine = false;

	mobj_put(m);
	return;
out:
	if (sma)
		sma->zero_flag = original_zero_flag;

	if (m)
		mobj_put(m);
	ffa_set_error(args, ret);
}

static void ffa_mem_relinquish(struct thread_smc_args *args,
			       struct sp_session *caller_sp,
			       struct ffa_rxtx  *rxtx)
{
	struct sp_mem_access_descr *sma = NULL;
	struct ffa_mem_relinquish *mem = rxtx->rx;
	uint32_t err = 0;
	struct mobj *m = NULL;

	if (!check_rxtx(rxtx)) {
		ffa_set_error(args, FFA_DENIED);
		return;
	}

	cpu_spin_lock(&rxtx->spinlock);

	m = mobj_ffa_get_by_cookie(mem->handle, 0);

	if (!m) {
		DMSG("Incorrect handle");
		err = FFA_DENIED;
		goto out_spinlock;
	}

	sma = get_sp_mem_access_descr(caller_sp, to_mobj_ffa(m));

	if (mem->endpoint_count != 1) {
		DMSG("Incorrect endpoint count");
		err = FFA_INVALID_PARAMETERS;
		goto out_spinlock;
	}

	if (mem->endpoint_id_array[0] != caller_sp->endpoint_id) {
		DMSG("Incorrect endpoint id");
		err = FFA_DENIED;
		goto out_spinlock;
	}

	cpu_spin_unlock(&rxtx->spinlock);

	if (!sma->counter) {
		DMSG("To many relinquish requests");
		err = FFA_DENIED;
		goto out;
	}

	if (sma->counter == 1) {
		if ((mem->flags & FFA_MEMORY_REGION_FLAG_CLEAR) ||
		    sma->zero_flag) {
			zero_mem_region(sma->m, caller_sp);
		}

		if (sp_unmap_regions(caller_sp, sma) != TEE_SUCCESS) {
			DMSG("Failed to unmap region");
			err = FFA_DENIED;
			goto out;
		}
	}
	sma->counter--;

	mobj_put(m);

	args->a0 = FFA_SUCCESS_32;
	return;

out_spinlock:
	cpu_spin_unlock(&rxtx->spinlock);
out:
	ffa_set_error(args, err);
	if (m)
		mobj_put(m);
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
		case FFA_MEM_SHARE_64:
		case FFA_MEM_SHARE_32:
			ts_push_current_session(&caller_sp->ts_sess);
			thread_spmc_handle_mem_share(args, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		case FFA_MEM_RETRIEVE_REQ_32:
		case FFA_MEM_RETRIEVE_REQ_64:
			ts_push_current_session(&caller_sp->ts_sess);
			ffa_mem_retrieve(args, caller_sp, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		case FFA_MEM_RELINQUISH:
			ts_push_current_session(&caller_sp->ts_sess);
			ffa_mem_relinquish(args, caller_sp, &caller_sp->rxtx);
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
