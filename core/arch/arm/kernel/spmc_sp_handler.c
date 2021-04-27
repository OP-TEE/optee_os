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
#include <optee_ffa.h>
#include <string.h>
#include "thread_private.h"

#define FFA_NW_ID			0

TAILQ_HEAD(mem_shares_t, shared_mem);
static struct mem_shares_t mem_shares = TAILQ_HEAD_INITIALIZER(mem_shares);

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

static struct sp_shared_mem *get_sp_shared_mem_by_handle(struct sp_session *s,
							 uint64_t handle)
{
	struct sp_shared_mem *ssm = NULL;

	/*
	 * FF-A Spec 8.10.2:
	 * Each Handle identifies a single unique composite memory region
	 * description that is, there is a 1:1 mapping between the two.
	 * This means that there can only be one SP linked to a specific handle.
	 */
	SLIST_FOREACH(ssm, &s->mem_head, link) {
		if (ssm->s_mem->mem_descr->global_handle == handle)
			return ssm;
	}
	return NULL;
}

static TEE_Result add_mem_region_to_sp(struct ffa_mem_access *mem_acc,
				       struct shared_mem *mem_share,
				       uint64_t global_handle)
{
	struct ffa_mem_access_perm *access_perm =
		&mem_acc->access_perm;
	uint16_t endpoint_id = 0;
	struct sp_session *s = NULL;

	endpoint_id = READ_ONCE(access_perm->endpoint_id);
	s = sp_get_session(endpoint_id);

	/* Only add memory shares of loaded SPs */
	if (s) {
		struct sp_shared_mem *ssm = NULL;

		ssm = calloc(1, sizeof(struct sp_shared_mem));

		if (!ssm)
			return FFA_NO_MEMORY;

		ssm->access_descr = mem_acc;

		ssm->counter = 0;
		ssm->endpoint_id = s->endpoint_id;

		/* Only allow each endpoint ones */
		if (get_sp_shared_mem_by_handle(s, global_handle)) {
			free(ssm);
			return FFA_DENIED;
		}
		/*
		 * Make a link between struct shared_mem and
		 * struct sp_shared_mem
		 */
		ssm->s_mem = mem_share;
		SLIST_INSERT_HEAD(&s->mem_head, ssm, link);
		SLIST_INSERT_HEAD(&mem_share->sp_head, ssm,
				  link);

	} else {
		/*
		 * We don't register memory that is shared with
		 * the OP-TEE endpoint. However we do need to
		 * check that if someone tries to share with an
		 * invalid endpoint.
		 */
		if (endpoint_id != spmc_get_id())
			return FFA_DENIED;
	}

	return FFA_OK;
}

TEE_Result spmc_sp_add_share(struct ffa_mem_transaction *input_descr,
			     uint64_t global_handle, size_t blen)
{
	int rc = FFA_INVALID_PARAMETERS;
	struct ts_session *ts = 0;
	uint16_t caller_id = FFA_NW_ID;
	unsigned int num_mem_accs = 0;
	unsigned int i = 0;
	void *mem_share_buffer = NULL;
	struct ffa_mem_access *mem_acc = NULL;
	struct shared_mem *mem_share = NULL;

	ts = sp_get_active();

	/* Find the endpoint which is sharing the memory region */
	if (ts) {
		struct sp_ctx *uctx = NULL;
		struct sp_session *calling_s = NULL;

		uctx = to_sp_ctx(ts->ctx);
		calling_s = uctx->open_session;
		caller_id = calling_s->endpoint_id;
	}

	num_mem_accs = READ_ONCE(input_descr->mem_access_count);

	if (num_mem_accs) {
		/*
		 * We store the full incoming transaction buffer and have
		 * shared_mem->mem_descr point to the beginning of the buffer.
		 * A struct sp_shared_mem object is created for each
		 * struct ffa_mem_access in the buffer.
		 * sp_shared_mem->access_descr is set to point to the
		 * corresponding struct ffa_mem_access in the transaction
		 * buffer.
		 */
		mem_share = calloc(1, sizeof(struct shared_mem));
		if (!mem_share)
			return FFA_NO_MEMORY;

		mem_share_buffer = calloc(1, blen);
		if (!mem_share_buffer) {
			free(mem_share);
			return FFA_NO_MEMORY;
		}

		memcpy(mem_share_buffer, (void *)input_descr, blen);

		/* Point mem_descr to the beginning of the buffer*/
		mem_share->mem_descr = mem_share_buffer;
		mem_share->mem_descr->global_handle = global_handle;
		mem_share->owner_id = caller_id;

		/* Create a list for all struct sp_shared_mem */
		SLIST_INIT(&mem_share->sp_head);
		TAILQ_INSERT_TAIL(&mem_shares, mem_share, link);

		mem_acc = mem_share->mem_descr->mem_access_array;

		/* Iterate over the mem_access_array */
		for (i = 0; i < num_mem_accs; i++) {
			rc = add_mem_region_to_sp(&mem_acc[i], mem_share,
						  global_handle);
			if (rc)
				goto cleanup;
		}
		/* Return if we processed a valid message */
		if (!rc)
			return rc;
	}

cleanup:
	if (num_mem_accs) {
		struct sp_shared_mem *ssm = NULL;
		struct sp_shared_mem *prev_ssm = NULL;

		SLIST_FOREACH(ssm, &mem_share->sp_head, link) {
			struct sp_session *sp_s = NULL;

			sp_s = sp_get_session(ssm->endpoint_id);
			if (prev_ssm)
				free(prev_ssm);
			prev_ssm = ssm;

			SLIST_REMOVE(&sp_s->mem_head, ssm, sp_shared_mem, link);
		}

		if (prev_ssm)
			free(prev_ssm);

		TAILQ_REMOVE(&mem_shares, mem_share, link);
		free(mem_share);
		free(mem_share_buffer);
	}
	return rc;
}

static bool check_rxtx(struct ffa_rxtx *rxtx)
{
	return rxtx && rxtx->rx && rxtx->tx && rxtx->size > 0 &&
	       rxtx->tx_is_mine;
}

static void zero_mem_region(struct ffa_mem_region *region)
{
	size_t i = 0;

	for (i = 0; i < region->address_range_count; i++) {
		uaddr_t phaddr = 0;
		vaddr_t vaddr = 0;
		size_t sz = 0;

		phaddr = region->address_range_array[i].address;
		vaddr = (vaddr_t)phys_to_virt((paddr_t)phaddr,
			MEM_AREA_TS_VASPACE);

		sz = region->address_range_array[i].page_count *
		      SMALL_PAGE_SIZE;
		memset((void *)vaddr, 0, sz);
	}
}

static TEE_Result store_virtual_addresses(struct ffa_mem_region *m_region,
					  struct ffa_mem_region *dst_region,
					  size_t *blen)
{
	size_t i = 0;
	size_t len =  sizeof(struct ffa_mem_transaction) +
		      sizeof(struct ffa_mem_access) +
		      sizeof(struct ffa_mem_region);

	for (i = 0; i < m_region->address_range_count; i++) {
		uaddr_t phaddr = 0;
		vaddr_t vaddr = 0;

		len += sizeof(dst_region->address_range_array[i]);

		if (len > *blen)
			return TEE_ERROR_OUT_OF_MEMORY;

		memcpy(&dst_region->address_range_array[i],
		       &m_region->address_range_array[i],
		       sizeof(struct ffa_address_range)
		       );

		/*change address to the virt address */
		phaddr = m_region->address_range_array[i].address;
		vaddr = (vaddr_t)phys_to_virt((paddr_t)phaddr,
			MEM_AREA_TS_VASPACE);
		dst_region->address_range_array[i].address = vaddr;
	}
	*blen = len;
	return TEE_SUCCESS;
}

static struct ffa_mem_access *get_mem_access(struct ffa_mem_transaction *descr,
					     uint16_t endpoint_id)
{
	uint32_t i = 0;

	/*
	 * There is a 1:1 association between an endpoint and the permissions
	 * with which it can access a memory region.
	 */
	for (i = 0; i < descr->mem_access_count; i++) {
		struct ffa_mem_access *req = &descr->mem_access_array[i];

		if (req->access_perm.endpoint_id == endpoint_id)
			return req;
	}
	EMSG("Incorrect endpoint! %x", endpoint_id);
	return NULL;
}

static TEE_Result check_retrieve_request(struct sp_shared_mem *sm,
					 struct ffa_mem_transaction *retr_dsc,
					 struct ffa_mem_access *access)
{
	struct shared_mem *ssm =  sm->s_mem;
	bool zero_retrieve_flag = false;
	uint8_t share_perm = sm->access_descr->access_perm.perm;
	uint8_t share_flags = sm->access_descr->access_perm.flags;
	uint32_t retr_perm = access->access_perm.perm;
	uint32_t retr_flags = access->access_perm.flags;

	/*
	 * Compare the permissions and flags of the original share(sm) with the
	 * current request (retr_dsc and access)
	 */

	/* Check if tag is correct */
	if (sm->s_mem->mem_descr->tag != retr_dsc->tag) {
		EMSG("Incorrect tag! %lx %lx", sm->s_mem->mem_descr->tag,
		     retr_dsc->tag);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check permissions  and flags*/
	if ((retr_perm & FFA_MEM_ACC_RW) &&
	    !(share_perm & FFA_MEM_ACC_RW)) {
		DMSG("Incorrect memshare permison set");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((retr_perm & FFA_MEM_ACC_EXE) &&
	    !(share_perm & FFA_MEM_ACC_EXE)) {
		DMSG("Incorrect memshare permison set");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((retr_flags & FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH)) {
		if (!(share_flags & FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH)) {
			/*
			 * If FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH is set in
			 * the request it also has to set in the original
			 * MEM_SHARE request.
			 */
			DMSG("Incorrect memshare permison set");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		if (!(retr_perm & FFA_MEM_ACC_RW)) {
			DMSG("FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH should only be set for RW regions");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	/*
	 * b’1: Retrieve the memory region only if the Sender
	 * requested the Relayer to zero its contents prior to retrieval
	 * by setting the Bit[0] in Table 8.20
	 */
	zero_retrieve_flag = retr_dsc->flags & FFA_MEMORY_REGION_FLAG_CLEAR;

	if (zero_retrieve_flag &&
	    !(ssm->mem_descr->flags & FFA_MEMORY_REGION_FLAG_CLEAR)) {
		return FFA_INVALID_PARAMETERS;
	}
	/* Zero flag should only be set when we have write access */
	if (zero_retrieve_flag && !(retr_perm & FFA_MEM_ACC_RW)) {
		EMSG("Zero flag should not be set for read-only mem");
		return FFA_INVALID_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result create_retrieve_response(struct ffa_mem_transaction *retr_dsc,
					   void *dst_buffer,
					   struct sp_shared_mem *ssm,
					   size_t *tx_len)
{
	size_t off = 0;
	struct ffa_mem_region *dst_region =  NULL;
	struct ffa_mem_transaction *d_ds = dst_buffer;
	struct ffa_mem_region *retrieve_region = NULL;
	struct ffa_mem_region *share_region = NULL;

	/*
	 * We respond with a FFA_MEM_RETRIEVE_RESP which defines the
	 * following data in the rx buffer of the SP.
	 * struct mem_transaction_descr
	 * struct mem_access_descr //1 Element
	 * struct mem_region_descr
	 */
	/* Copy the mem_transaction_descr*/
	memcpy(d_ds, retr_dsc,
	       sizeof(*retr_dsc));

	/* Copy the mem_accsess_descr*/
	memcpy(&d_ds->mem_access_array[0],
	       &retr_dsc->mem_access_array[0], sizeof(struct ffa_mem_access));

	/* Copy the mem_region_descr.*/
	off = d_ds->mem_access_array[0].region_offs;
	dst_region = (struct ffa_mem_region *)((vaddr_t)d_ds + off);
	retrieve_region = (struct ffa_mem_region *)((vaddr_t)retr_dsc + off);

	share_region = (struct ffa_mem_region *)
			((vaddr_t)ssm->s_mem->mem_descr +
			ssm->access_descr->region_offs);

	memcpy(dst_region, retrieve_region, sizeof(*dst_region));

	return store_virtual_addresses(share_region, dst_region, tx_len);
}

static void ffa_mem_retrieve(struct thread_smc_args *args,
			     struct sp_session *caller_sp,
			     struct ffa_rxtx *rxtx)
{
	struct sp_shared_mem *ssm = NULL;
	size_t tx_len = 0;
	struct ffa_mem_transaction *retr_dsc = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t perm = TEE_MATTR_UR;
	struct ffa_mem_access *mem_access = NULL;

	if (!check_rxtx(rxtx)) {
		ffa_set_error(args, FFA_DENIED);
		return;
	}

	tx_len = rxtx->size;
	retr_dsc = rxtx->rx;

	cpu_spin_lock(&rxtx->spinlock);
	ssm = get_sp_shared_mem_by_handle(caller_sp, retr_dsc->global_handle);
	if (!ssm) {
		cpu_spin_unlock(&rxtx->spinlock);
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return;
	}

	ssm->zero_flag = retr_dsc->flags &
		       FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH;

	mem_access = get_mem_access(retr_dsc, ssm->endpoint_id);

	if (!mem_access) {
		cpu_spin_unlock(&rxtx->spinlock);
		ffa_set_error(args, FFA_DENIED);
		return;
	}

	if (check_retrieve_request(ssm, retr_dsc, mem_access) != TEE_SUCCESS) {
		cpu_spin_unlock(&rxtx->spinlock);
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return;
	}

	/* Get the permission */
	if (mem_access->access_perm.perm & FFA_MEM_ACC_RW)
		perm = TEE_MATTR_URW;

	if (mem_access->access_perm.perm & FFA_MEM_ACC_EXE)
		perm |= TEE_MATTR_UX;

	/*
	 * Try to map the memory linked to the handle in sp_shared_mem.
	 * sp_map_shared_va() doesn't allow active spinlocks.
	 */
	cpu_spin_unlock(&rxtx->spinlock);
	if (!sp_map_shared_va(caller_sp, ssm, perm)) {
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return;
	}
	cpu_spin_lock(&rxtx->spinlock);

	res = create_retrieve_response(retr_dsc, rxtx->tx, ssm, &tx_len);

	if (res) {
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		cpu_spin_unlock(&rxtx->spinlock);
		return;
	}

	/* Set the memory value to 0 when FFA_MEMORY_REGION_FLAG_CLEAR is set */
	if (retr_dsc->flags & FFA_MEMORY_REGION_FLAG_CLEAR) {
		struct ffa_mem_region *region = NULL;
		struct shared_mem *sm =  ssm->s_mem;

		region = (struct ffa_mem_region *)((vaddr_t)sm->mem_descr +
						ssm->access_descr->region_offs);

		zero_mem_region(region);
	}

	args->a0 = FFA_MEM_RETRIEVE_RESP;
	args->a1 = tx_len;
	args->a2 = tx_len;
	ssm->counter++;

	rxtx->tx_is_mine = false;
	cpu_spin_unlock(&rxtx->spinlock);
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
		default:
			EMSG("Unhandled FFA function ID %#"PRIx32,
			     (uint32_t)args->a0);
			ffa_set_error(args, FFA_INVALID_PARAMETERS);
			sp_enter(args, caller_sp);
		}
	} while (caller_sp);
}
