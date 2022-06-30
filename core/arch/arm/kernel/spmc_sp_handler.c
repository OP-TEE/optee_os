// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2022, Arm Limited
 */
#include <assert.h>
#include <bench.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/secure_partition.h>
#include <kernel/spinlock.h>
#include <kernel/spmc_sp_handler.h>
#include <kernel/tee_misc.h>
#include <kernel/thread_private.h>
#include <mm/mobj.h>
#include <mm/sp_mem.h>
#include <mm/vm.h>
#include <optee_ffa.h>
#include <string.h>

static unsigned int mem_ref_lock = SPINLOCK_UNLOCK;

void spmc_sp_start_thread(struct thread_smc_args *args)
{
	thread_sp_alloc_and_run(args);
}

static void ffa_set_error(struct thread_smc_args *args, uint32_t error)
{
	args->a0 = FFA_ERROR;
	args->a2 = error;
}

static void ffa_success(struct thread_smc_args *args)
{
	args->a0 = FFA_SUCCESS_32;
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

static struct sp_mem_receiver *find_sp_mem_receiver(struct sp_session *s,
						    struct sp_mem *smem)
{
	struct sp_mem_receiver *receiver = NULL;

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
			break;
	}
	return receiver;
}

static int add_mem_region_to_sp(struct ffa_mem_access *mem_acc,
				struct sp_mem *smem)
{
	struct ffa_mem_access_perm *access_perm = &mem_acc->access_perm;
	struct sp_session *s = NULL;
	struct sp_mem_receiver *receiver = NULL;
	uint8_t perm = READ_ONCE(access_perm->perm);
	uint16_t endpoint_id = READ_ONCE(access_perm->endpoint_id);

	s = sp_get_session(endpoint_id);

	/* Only add memory shares of loaded SPs */
	if (!s)
		return FFA_DENIED;

	/* Only allow each endpoint once */
	if (find_sp_mem_receiver(s, smem))
		return FFA_DENIED;

	if (perm & ~FFA_MEM_ACC_MASK)
		return FFA_DENIED;

	receiver = calloc(1, sizeof(struct sp_mem_receiver));
	if (!receiver)
		return FFA_NO_MEMORY;

	receiver->smem = smem;

	receiver->perm.endpoint_id = endpoint_id;
	receiver->perm.perm = perm;
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

	res = spmc_sp_add_share(rxtx, args->a1, &global_handle, owner_sp);
	if (!res) {
		reg_pair_from_64(global_handle, &ret_w3, &ret_w2);
		args->a3 = ret_w3;
		args->a2 = ret_w2;
		args->a1 = FFA_PARAM_MBZ;
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
	struct sp_ctx *sp_ctx = NULL;
	uint64_t va = READ_ONCE(mem_reg->address);
	int res = FFA_OK;
	uint64_t region_len = READ_ONCE(mem_reg->page_count) * SMALL_PAGE_SIZE;
	struct mobj *mobj = NULL;

	sp_ctx = to_sp_ctx(owner_sp->ts_sess.ctx);

	/*
	 * The memory region we try to share might not be linked to just one
	 * mobj. Create a new region for each mobj.
	 */
	while (region_len) {
		size_t len = region_len;
		struct sp_mem_map_region *region = NULL;
		uint16_t prot = 0;
		size_t offs = 0;

		/*
		 * There is already a mobj for each address that is in the SPs
		 * address range.
		 */
		mobj = vm_get_mobj(&sp_ctx->uctx, va, &len, &prot, &offs);
		if (!mobj)
			return FFA_DENIED;

		/*
		 * If we share memory from a SP, check if we are not sharing
		 * with a higher permission than the memory was originally
		 * mapped.
		 */
		if ((highest_permission & FFA_MEM_ACC_RW) &&
		    !(prot & TEE_MATTR_UW)) {
			res = FFA_DENIED;
			goto err;
		}

		if ((highest_permission & FFA_MEM_ACC_EXE) &&
		    !(prot & TEE_MATTR_UX)) {
			res = FFA_DENIED;
			goto err;
		}

		region = calloc(1, sizeof(*region));
		region->mobj = mobj;
		region->page_offset = offs;
		region->page_count = len / SMALL_PAGE_SIZE;

		if (!sp_has_exclusive_access(region, &sp_ctx->uctx)) {
			free(region);
			res = FFA_DENIED;
			goto err;
		}

		va += len;
		region_len -= len;
		SLIST_INSERT_HEAD(&smem->regions, region, link);
	}

	return FFA_OK;
err:
	mobj_put(mobj);

	return res;
}

static int spmc_sp_add_nw_region(struct sp_mem *smem,
				 struct ffa_mem_region *mem_reg)
{
	uint64_t page_count = READ_ONCE(mem_reg->total_page_count);
	struct sp_mem_map_region *region = NULL;
	struct mobj *m = sp_mem_new_mobj(page_count, TEE_MATTR_MEM_TYPE_CACHED,
					 false);
	unsigned int i = 0;
	unsigned int idx = 0;
	int res = FFA_OK;
	uint64_t address_count = READ_ONCE(mem_reg->address_range_count);

	if (!m)
		return FFA_NO_MEMORY;

	for (i = 0; i < address_count; i++) {
		struct ffa_address_range *addr_range = NULL;

		addr_range = &mem_reg->address_range_array[i];
		if (sp_mem_add_pages(m, &idx,
				     READ_ONCE(addr_range->address),
				     READ_ONCE(addr_range->page_count))) {
			res = FFA_DENIED;
			goto clean_up;
		}
	}

	region = calloc(1, sizeof(*region));
	if (!region) {
		res = FFA_NO_MEMORY;
		goto clean_up;
	}

	region->mobj = m;
	region->page_count = page_count;

	if (!sp_has_exclusive_access(region, NULL)) {
		free(region);
		res = FFA_DENIED;
		goto clean_up;
	}

	SLIST_INSERT_HEAD(&smem->regions, region, link);
	return FFA_OK;
clean_up:
	mobj_put(m);
	return res;
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
	uint16_t sender_id = READ_ONCE(input_descr->sender_id);

	if (!smem)
		return FFA_NO_MEMORY;

	if ((owner_sp && owner_sp->endpoint_id != sender_id) ||
	    (!owner_sp && sp_get_session(sender_id))) {
		res = FFA_DENIED;
		goto cleanup;
	}

	num_mem_accs = READ_ONCE(input_descr->mem_access_count);
	mem_acc = input_descr->mem_access_array;

	if (!num_mem_accs) {
		res = FFA_DENIED;
		goto cleanup;
	}

	/* Store the ffa_mem_transaction */
	smem->sender_id = sender_id;
	smem->mem_reg_attr = READ_ONCE(input_descr->mem_reg_attr);
	smem->flags = READ_ONCE(input_descr->flags);
	smem->tag = READ_ONCE(input_descr->tag);

	if (MUL_OVERFLOW(num_mem_accs, sizeof(*mem_acc), &needed_size) ||
	    ADD_OVERFLOW(needed_size, sizeof(*input_descr), &needed_size) ||
	    needed_size > blen) {
		res = FFA_NO_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < num_mem_accs; i++)
		highest_permission |= READ_ONCE(mem_acc[i].access_perm.perm);

	addr_range_offs = READ_ONCE(mem_acc[0].region_offs);
	mem_reg = (void *)((char *)input_descr + addr_range_offs);

	/* Iterate over all the addresses */
	if (owner_sp) {
		size_t address_range = READ_ONCE(mem_reg->address_range_count);

		for (i = 0; i < address_range; i++) {
			struct ffa_address_range *addr_range = NULL;

			addr_range = &mem_reg->address_range_array[i];

			if (!core_is_buffer_inside((vaddr_t)addr_range,
						   sizeof(*addr_range),
						   (vaddr_t)rxtx->rx,
						   rxtx->size)) {
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
	*global_handle = smem->global_handle;
	sp_mem_add(smem);

	return FFA_OK;

cleanup:
	sp_mem_remove(smem);
	return res;
}

static bool check_rxtx(struct ffa_rxtx *rxtx)
{
	return rxtx && rxtx->rx && rxtx->tx && rxtx->size > 0;
}

static TEE_Result check_retrieve_request(struct sp_mem_receiver *receiver,
					 struct ffa_mem_transaction *retr_dsc,
					 struct sp_mem *smem, int64_t tx_len)
{
	struct ffa_mem_access *retr_access = NULL;
	uint8_t share_perm = receiver->perm.perm;
	uint32_t retr_perm = 0;
	uint32_t retr_flags = READ_ONCE(retr_dsc->flags);
	uint64_t retr_tag = READ_ONCE(retr_dsc->tag);
	struct sp_mem_map_region *reg = NULL;

	/*
	 * The request came from the endpoint. It should only have one
	 * ffa_mem_access element
	 */
	if (READ_ONCE(retr_dsc->mem_access_count) != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	retr_access = retr_dsc->mem_access_array;
	retr_perm = READ_ONCE(retr_access->access_perm.perm);

	/* Check if tag is correct */
	if (receiver->smem->tag != retr_tag) {
		EMSG("Incorrect tag %#"PRIx64" %#"PRIx64, receiver->smem->tag,
		     retr_tag);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check permissions and flags */
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

	if (retr_flags & FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH) {
		DMSG("CLEAR_RELINQUISH is not allowed for FFA_SHARE");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Check if there is enough space in the tx buffer to send the respons.
	 */
	tx_len -= sizeof(struct ffa_mem_transaction) +
		  sizeof(struct ffa_mem_access) +
		  sizeof(struct ffa_mem_region);

	if (tx_len < 0)
		return FFA_NO_MEMORY;

	SLIST_FOREACH(reg, &smem->regions, link) {
		tx_len -= sizeof(struct ffa_address_range);
		if (tx_len < 0)
			return FFA_NO_MEMORY;
	}

	return TEE_SUCCESS;
}

static void create_retrieve_response(void *dst_buffer,
				     struct sp_mem_receiver *receiver,
				     struct sp_mem *smem, struct sp_session *s)
{
	size_t off = 0;
	struct ffa_mem_region *dst_region =  NULL;
	struct ffa_mem_transaction *d_ds = dst_buffer;
	struct ffa_address_range *addr_dst = NULL;
	struct sp_mem_map_region *reg = NULL;

	/*
	 * We respond with a FFA_MEM_RETRIEVE_RESP which defines the
	 * following data in the rx buffer of the SP.
	 * struct mem_transaction_descr
	 * struct mem_access_descr (always 1 Element)
	 * struct mem_region_descr
	 */
	/* Copy the mem_transaction_descr */
	d_ds->sender_id = receiver->smem->sender_id;
	d_ds->mem_reg_attr = receiver->smem->mem_reg_attr;
	d_ds->flags = receiver->smem->flags;
	d_ds->tag = receiver->smem->tag;

	off = sizeof(struct ffa_mem_transaction) +
	      sizeof(struct ffa_mem_access);

	d_ds->mem_access_count = 1;

	/* Copy the mem_accsess_descr */
	d_ds->mem_access_array[0].region_offs = off;
	memcpy(&d_ds->mem_access_array[0].access_perm,
	       &receiver->perm, sizeof(struct ffa_mem_access_perm));

	/* Copy the mem_region_descr */
	dst_region = (struct ffa_mem_region *)((vaddr_t)d_ds + off);

	dst_region->address_range_count = 0;
	dst_region->total_page_count = 0;

	addr_dst = dst_region->address_range_array;

	SLIST_FOREACH(reg, &smem->regions, link) {
		uint32_t offset = reg->page_offset;
		struct sp_ctx *ctx = to_sp_ctx(s->ts_sess.ctx);

		addr_dst->address = (uint64_t)sp_mem_get_va(&ctx->uctx,
							    offset,
							    reg->mobj);
		addr_dst->page_count = reg->page_count;
		dst_region->address_range_count++;

		dst_region->total_page_count += addr_dst->page_count;
	}
}

static void ffa_mem_retrieve(struct thread_smc_args *args,
			     struct sp_session *caller_sp,
			     struct ffa_rxtx *rxtx)
{
	int ret = FFA_OK;
	size_t tx_len = 0;
	struct ffa_mem_transaction *retr_dsc = NULL;
	struct ffa_mem_region *mem_region = NULL;
	uint64_t va = 0;
	struct sp_mem *smem = NULL;
	struct sp_mem_receiver *receiver = NULL;
	uint32_t exceptions = 0;
	uint32_t address_offset = 0;
	size_t needed_size = 0;

	if (!check_rxtx(rxtx) || !rxtx->tx_is_mine) {
		ret = FFA_DENIED;
		goto err;
	}

	tx_len = rxtx->size;
	retr_dsc = rxtx->rx;

	smem = sp_mem_get(retr_dsc->global_handle);
	if (!smem) {
		DMSG("Incorrect handle");
		ret = FFA_DENIED;
		goto err;
	}

	receiver = sp_mem_get_receiver(caller_sp->endpoint_id, smem);

	address_offset = READ_ONCE(retr_dsc->mem_access_array[0].region_offs);

	if (ADD_OVERFLOW(address_offset, sizeof(struct ffa_mem_region),
			 &needed_size) || needed_size > tx_len) {
		ret = FFA_INVALID_PARAMETERS;
		goto err;
	}

	if (check_retrieve_request(receiver, retr_dsc, smem, tx_len) !=
	    TEE_SUCCESS) {
		ret = FFA_INVALID_PARAMETERS;
		goto err;
	}

	exceptions = cpu_spin_lock_xsave(&mem_ref_lock);

	if (receiver->ref_count == UINT8_MAX) {
		ret = FFA_DENIED;
		cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);
		goto err;
	}

	receiver->ref_count++;

	/* We only need to map the region the first time we request it. */
	if (receiver->ref_count == 1) {
		TEE_Result ret_map = TEE_SUCCESS;

		cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);

		/*
		 * Try to map the memory linked to the handle in
		 * sp_mem_access_descr.
		 */
		mem_region = (struct ffa_mem_region *)((vaddr_t)retr_dsc +
						       address_offset);

		va = READ_ONCE(mem_region->address_range_array[0].address);
		ret_map = sp_map_shared(caller_sp, receiver, smem,  &va);

		if (ret_map) {
			EMSG("Could not map memory region: %#"PRIx32, ret_map);
			exceptions = cpu_spin_lock_xsave(&mem_ref_lock);
			receiver->ref_count--;
			cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);
			ret = FFA_DENIED;
			goto err;
		}
	} else {
		cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);
	}

	create_retrieve_response(rxtx->tx, receiver, smem, caller_sp);

	args->a0 = FFA_MEM_RETRIEVE_RESP;
	args->a1 = tx_len;
	args->a2 = tx_len;

	rxtx->tx_is_mine = false;

	return;
err:
	ffa_set_error(args, ret);
}

static void ffa_mem_relinquish(struct thread_smc_args *args,
			       struct sp_session *caller_sp,
			       struct ffa_rxtx  *rxtx)
{
	struct sp_mem *smem = NULL;
	struct ffa_mem_relinquish *mem = rxtx->rx;
	struct sp_mem_receiver *receiver = NULL;
	int err = FFA_NOT_SUPPORTED;
	uint32_t exceptions = 0;

	if (!check_rxtx(rxtx)) {
		ffa_set_error(args, FFA_DENIED);
		return;
	}

	exceptions = cpu_spin_lock_xsave(&rxtx->spinlock);
	smem = sp_mem_get(READ_ONCE(mem->handle));

	if (!smem) {
		DMSG("Incorrect handle");
		err = FFA_DENIED;
		goto err_unlock_rxtwx;
	}

	if (READ_ONCE(mem->endpoint_count) != 1) {
		DMSG("Incorrect endpoint count");
		err = FFA_INVALID_PARAMETERS;
		goto err_unlock_rxtwx;
	}

	if (READ_ONCE(mem->endpoint_id_array[0]) != caller_sp->endpoint_id) {
		DMSG("Incorrect endpoint id");
		err = FFA_DENIED;
		goto err_unlock_rxtwx;
	}

	cpu_spin_unlock_xrestore(&rxtx->spinlock, exceptions);

	receiver = sp_mem_get_receiver(caller_sp->endpoint_id, smem);

	exceptions = cpu_spin_lock_xsave(&mem_ref_lock);
	if (!receiver->ref_count) {
		DMSG("To many relinquish requests");
		err = FFA_DENIED;
		goto err_unlock_memref;
	}

	receiver->ref_count--;
	if (!receiver->ref_count) {
		cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);
		if (sp_unmap_ffa_regions(caller_sp, smem) != TEE_SUCCESS) {
			DMSG("Failed to unmap region");
			ffa_set_error(args, FFA_DENIED);
			return;
		}
	} else {
		cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);
	}

	ffa_success(args);
	return;

err_unlock_rxtwx:
	cpu_spin_unlock_xrestore(&rxtx->spinlock, exceptions);
	ffa_set_error(args, err);
	return;
err_unlock_memref:
	cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);
	ffa_set_error(args, err);
}

static void zero_mem_region(struct sp_mem *smem, struct sp_session *s)
{
	void *addr = NULL;
	struct sp_ctx *ctx = to_sp_ctx(s->ts_sess.ctx);
	struct sp_mem_map_region *reg = NULL;

	ts_push_current_session(&s->ts_sess);
	SLIST_FOREACH(reg, &smem->regions, link) {
		size_t sz = reg->page_count * SMALL_PAGE_SIZE;

		addr = sp_mem_get_va(&ctx->uctx, reg->page_offset, reg->mobj);

		assert(addr);
		memset(addr, 0, sz);
	}
	ts_pop_current_session();
}

/*
 * ffa_mem_reclaim returns false if it couldn't process the reclaim message.
 * This happens when the memory regions was shared with the OP-TEE endpoint.
 * After this thread_spmc calls handle_mem_reclaim() to make sure that the
 * region is reclaimed from the OP-TEE endpoint.
 */
bool ffa_mem_reclaim(struct thread_smc_args *args,
		     struct sp_session *caller_sp)
{
	uint64_t handle = reg_pair_to_64(args->a2, args->a1);
	uint32_t flags = args->a3;
	uint32_t endpoint = 0;
	struct sp_mem *smem = NULL;
	struct sp_mem_receiver *receiver  = NULL;
	uint32_t exceptions = 0;

	smem = sp_mem_get(handle);
	if (!smem)
		return false;

	if (caller_sp)
		endpoint = caller_sp->endpoint_id;

	/* Make sure that the caller is the owner of the share */
	if (smem->sender_id != endpoint) {
		ffa_set_error(args, FFA_DENIED);
		return true;
	}

	exceptions = cpu_spin_lock_xsave(&mem_ref_lock);

	/* Make sure that all shares where relinquished */
	SLIST_FOREACH(receiver, &smem->receivers, link) {
		if (receiver->ref_count != 0) {
			ffa_set_error(args, FFA_DENIED);
			cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);
			return true;
		}
	}

	if (flags & FFA_MEMORY_REGION_FLAG_CLEAR) {
		if (caller_sp) {
			zero_mem_region(smem, caller_sp);
		} else {
			/*
			 * Currently we don't support zeroing Normal World
			 * memory. To do this we would have to map the memory
			 * again, zero it and unmap it.
			 */
			ffa_set_error(args, FFA_DENIED);
			cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);
			return true;
		}
	}

	sp_mem_remove(smem);
	cpu_spin_unlock_xrestore(&mem_ref_lock, exceptions);

	ffa_success(args);
	return true;
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
#ifdef ARM64
		case FFA_MSG_SEND_DIRECT_REQ_64:
#endif
		case FFA_MSG_SEND_DIRECT_REQ_32:
			caller_sp = ffa_handle_sp_direct_req(args, caller_sp);
			break;
#ifdef ARM64
		case FFA_MSG_SEND_DIRECT_RESP_64:
#endif
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
#ifdef ARM64
		case FFA_MEM_RETRIEVE_REQ_64:
#endif
		case FFA_MEM_RETRIEVE_REQ_32:
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
		case FFA_MEM_RECLAIM:
			ffa_mem_reclaim(args, caller_sp);
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
