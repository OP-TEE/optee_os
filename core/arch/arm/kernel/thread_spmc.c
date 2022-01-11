// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2021, Linaro Limited.
 * Copyright (c) 2019-2021, Arm Limited. All rights reserved.
 */

#include <assert.h>
#include <ffa.h>
#include <io.h>
#include <initcall.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/secure_partition.h>
#include <kernel/spinlock.h>
#include <kernel/spmc_sp_handler.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <kernel/thread_spmc.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <optee_ffa.h>
#include <optee_msg.h>
#include <optee_rpc_cmd.h>
#include <string.h>
#include <sys/queue.h>
#include <tee/entry_std.h>
#include <tee/uuid.h>
#include <util.h>

#include "thread_private.h"

#if defined(CFG_CORE_SEL1_SPMC)
struct mem_share_state {
	struct mobj_ffa *mf;
	unsigned int page_count;
	unsigned int region_count;
	unsigned int current_page_idx;
};

struct mem_frag_state {
	struct mem_share_state share;
	tee_mm_entry_t *mm;
	unsigned int frag_offset;
	SLIST_ENTRY(mem_frag_state) link;
};
#endif

/* Initialized in spmc_init() below */
static uint16_t my_endpoint_id;

/*
 * If struct ffa_rxtx::size is 0 RX/TX buffers are not mapped or initialized.
 *
 * struct ffa_rxtx::spin_lock protects the variables below from concurrent
 * access this includes the use of content of struct ffa_rxtx::rx and
 * @frag_state_head.
 *
 * struct ffa_rxtx::tx_buf_is_mine is true when we may write to struct
 * ffa_rxtx::tx and false when it is owned by normal world.
 *
 * Note that we can't prevent normal world from updating the content of
 * these buffers so we must always be careful when reading. while we hold
 * the lock.
 */

#ifdef CFG_CORE_SEL2_SPMC
static uint8_t __rx_buf[SMALL_PAGE_SIZE] __aligned(SMALL_PAGE_SIZE);
static uint8_t __tx_buf[SMALL_PAGE_SIZE] __aligned(SMALL_PAGE_SIZE);
static struct ffa_rxtx nw_rxtx = { .rx = __rx_buf, .tx = __tx_buf };
#else
static struct ffa_rxtx nw_rxtx;

static bool is_nw_buf(struct ffa_rxtx *rxtx)
{
	return rxtx == &nw_rxtx;
}

static SLIST_HEAD(mem_frag_state_head, mem_frag_state) frag_state_head =
	SLIST_HEAD_INITIALIZER(&frag_state_head);
#endif

static uint32_t swap_src_dst(uint32_t src_dst)
{
	return (src_dst >> 16) | (src_dst << 16);
}

void spmc_set_args(struct thread_smc_args *args, uint32_t fid, uint32_t src_dst,
		   uint32_t w2, uint32_t w3, uint32_t w4, uint32_t w5)
{
	*args = (struct thread_smc_args){ .a0 = fid,
					  .a1 = src_dst,
					  .a2 = w2,
					  .a3 = w3,
					  .a4 = w4,
					  .a5 = w5, };
}

#if defined(CFG_CORE_SEL1_SPMC)
void spmc_handle_version(struct thread_smc_args *args)
{
	/*
	 * We currently only support one version, 1.0 so let's keep it
	 * simple.
	 */
	spmc_set_args(args,
		      MAKE_FFA_VERSION(FFA_VERSION_MAJOR, FFA_VERSION_MINOR),
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
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
#ifdef ARM64
	case FFA_MEM_SHARE_64:
#endif
	case FFA_MEM_SHARE_32:
		ret_fid = FFA_SUCCESS_32;
		/*
		 * Partition manager supports transmission of a memory
		 * transaction descriptor in a buffer dynamically allocated
		 * by the endpoint.
		 */
		ret_w2 = BIT(0);
		break;

	case FFA_ERROR:
	case FFA_VERSION:
	case FFA_SUCCESS_32:
#ifdef ARM64
	case FFA_SUCCESS_64:
#endif
	case FFA_MEM_FRAG_TX:
	case FFA_MEM_RECLAIM:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_INTERRUPT:
	case FFA_PARTITION_INFO_GET:
	case FFA_RX_RELEASE:
		ret_fid = FFA_SUCCESS_32;
		break;
	default:
		ret_fid = FFA_ERROR;
		ret_w2 = FFA_NOT_SUPPORTED;
		break;
	}

	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, ret_w2, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static int map_buf(paddr_t pa, unsigned int sz, void **va_ret)
{
	tee_mm_entry_t *mm = NULL;

	if (!core_pbuf_is(CORE_MEM_NON_SEC, pa, sz))
		return FFA_INVALID_PARAMETERS;

	mm = tee_mm_alloc(&tee_mm_shm, sz);
	if (!mm)
		return FFA_NO_MEMORY;

	if (core_mmu_map_contiguous_pages(tee_mm_get_smem(mm), pa,
					  sz / SMALL_PAGE_SIZE,
					  MEM_AREA_NSEC_SHM)) {
		tee_mm_free(mm);
		return FFA_INVALID_PARAMETERS;
	}

	*va_ret = (void *)tee_mm_get_smem(mm);
	return 0;
}

static void unmap_buf(void *va, size_t sz)
{
	tee_mm_entry_t *mm = tee_mm_find(&tee_mm_shm, (vaddr_t)va);

	assert(mm);
	core_mmu_unmap_pages(tee_mm_get_smem(mm), sz / SMALL_PAGE_SIZE);
	tee_mm_free(mm);
}

void spmc_handle_rxtx_map(struct thread_smc_args *args, struct ffa_rxtx *rxtx)
{
	int rc = 0;
	uint32_t ret_fid = FFA_ERROR;
	unsigned int sz = 0;
	paddr_t rx_pa = 0;
	paddr_t tx_pa = 0;
	void *rx = NULL;
	void *tx = NULL;

	cpu_spin_lock(&rxtx->spinlock);

	if (args->a3 & GENMASK_64(63, 6)) {
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}

	sz = args->a3 * SMALL_PAGE_SIZE;
	if (!sz) {
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}
	/* TX/RX are swapped compared to the caller */
	tx_pa = args->a2;
	rx_pa = args->a1;

	if (rxtx->size) {
		rc = FFA_DENIED;
		goto out;
	}

	/*
	 * If the buffer comes from a SP the address is virtual and already
	 * mapped.
	 */
	if (is_nw_buf(rxtx)) {
		rc = map_buf(tx_pa, sz, &tx);
		if (rc)
			goto out;
		rc = map_buf(rx_pa, sz, &rx);
		if (rc) {
			unmap_buf(tx, sz);
			goto out;
		}
		rxtx->tx = tx;
		rxtx->rx = rx;
	} else {
		if ((tx_pa & SMALL_PAGE_MASK) || (rx_pa & SMALL_PAGE_MASK)) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}

		if (!virt_to_phys((void *)tx_pa) ||
		    !virt_to_phys((void *)rx_pa)) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}

		rxtx->tx = (void *)tx_pa;
		rxtx->rx = (void *)rx_pa;
	}

	rxtx->size = sz;
	rxtx->tx_is_mine = true;
	ret_fid = FFA_SUCCESS_32;
	DMSG("Mapped tx %#"PRIxPA" size %#x @ %p", tx_pa, sz, tx);
	DMSG("Mapped rx %#"PRIxPA" size %#x @ %p", rx_pa, sz, rx);
out:
	cpu_spin_unlock(&rxtx->spinlock);
	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, rc, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

void spmc_handle_rxtx_unmap(struct thread_smc_args *args, struct ffa_rxtx *rxtx)
{
	uint32_t ret_fid = FFA_ERROR;
	int rc = FFA_INVALID_PARAMETERS;

	cpu_spin_lock(&rxtx->spinlock);

	if (!rxtx->size)
		goto out;

	/* We don't unmap the SP memory as the SP might still use it */
	if (is_nw_buf(rxtx)) {
		unmap_buf(rxtx->rx, rxtx->size);
		unmap_buf(rxtx->tx, rxtx->size);
	}
	rxtx->size = 0;
	rxtx->rx = NULL;
	rxtx->tx = NULL;
	ret_fid = FFA_SUCCESS_32;
	rc = 0;
out:
	cpu_spin_unlock(&rxtx->spinlock);
	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, rc, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

void spmc_handle_rx_release(struct thread_smc_args *args, struct ffa_rxtx *rxtx)
{
	uint32_t ret_fid = 0;
	int rc = 0;

	cpu_spin_lock(&rxtx->spinlock);
	/* The senders RX is our TX */
	if (!rxtx->size || rxtx->tx_is_mine) {
		ret_fid = FFA_ERROR;
		rc = FFA_DENIED;
	} else {
		ret_fid = FFA_SUCCESS_32;
		rc = 0;
		rxtx->tx_is_mine = true;
	}
	cpu_spin_unlock(&rxtx->spinlock);

	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, rc, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static bool is_nil_uuid(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3)
{
	return !w0 && !w1 && !w2 && !w3;
}

static bool is_my_uuid(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3)
{
	/*
	 * This depends on which UUID we have been assigned.
	 * TODO add a generic mechanism to obtain our UUID.
	 *
	 * The test below is for the hard coded UUID
	 * 486178e0-e7f8-11e3-bc5e-0002a5d5c51b
	 */
	return w0 == 0xe0786148 && w1 == 0xe311f8e7 &&
	       w2 == 0x02005ebc && w3 == 0x1bc5d5a5;
}

void spmc_fill_partition_entry(struct ffa_partition_info *fpi,
			       uint16_t endpoint_id, uint16_t execution_context)
{
	fpi->id = endpoint_id;
	/* Number of execution contexts implemented by this partition */
	fpi->execution_context = execution_context;

	fpi->partition_properties = FFA_PARTITION_DIRECT_REQ_RECV_SUPPORT |
				    FFA_PARTITION_DIRECT_REQ_SEND_SUPPORT;
}

static uint32_t handle_partition_info_get_all(size_t *elem_count,
					      struct ffa_rxtx *rxtx)
{
	struct ffa_partition_info *fpi = rxtx->tx;

	/* Add OP-TEE SP */
	spmc_fill_partition_entry(fpi, my_endpoint_id, CFG_TEE_CORE_NB_CORE);
	rxtx->tx_is_mine = false;
	*elem_count = 1;
	fpi++;

	if (IS_ENABLED(CFG_SECURE_PARTITION)) {
		size_t count = (rxtx->size / sizeof(*fpi)) - 1;

		if (sp_partition_info_get_all(fpi, &count))
			return FFA_NO_MEMORY;
		*elem_count += count;
	}

	return FFA_OK;
}

void spmc_handle_partition_info_get(struct thread_smc_args *args,
				    struct ffa_rxtx *rxtx)
{
	uint32_t ret_fid = FFA_ERROR;
	uint32_t rc = 0;
	uint32_t endpoint_id = my_endpoint_id;
	struct ffa_partition_info *fpi = NULL;

	cpu_spin_lock(&rxtx->spinlock);

	if (!rxtx->size || !rxtx->tx_is_mine) {
		if (rxtx->size)
			rc = FFA_BUSY;
		else
			rc = FFA_DENIED; /* TX buffer not setup yet */
		goto out;
	}

	fpi = rxtx->tx;

	if (rxtx->size < sizeof(*fpi)) {
		ret_fid = FFA_ERROR;
		rc = FFA_NO_MEMORY;
		goto out;
	}

	if (is_nil_uuid(args->a1, args->a2, args->a3, args->a4)) {
		size_t elem_count = 0;

		ret_fid = handle_partition_info_get_all(&elem_count, rxtx);

		if (ret_fid) {
			rc = ret_fid;
			ret_fid = FFA_ERROR;
		} else {
			ret_fid = FFA_SUCCESS_32;
			rc = elem_count;
		}

		goto out;
	}

	if (is_my_uuid(args->a1, args->a2, args->a3, args->a4)) {
		spmc_fill_partition_entry(fpi, endpoint_id,
					  CFG_TEE_CORE_NB_CORE);
	} else if (IS_ENABLED(CFG_SECURE_PARTITION)) {
		uint32_t uuid_array[4] = { 0 };
		TEE_UUID uuid = { };
		TEE_Result res = TEE_SUCCESS;

		uuid_array[0] = args->a1;
		uuid_array[1] = args->a2;
		uuid_array[2] = args->a3;
		uuid_array[3] = args->a4;
		tee_uuid_from_octets(&uuid, (uint8_t *)uuid_array);

		res = sp_find_session_id(&uuid, &endpoint_id);
		if (res != TEE_SUCCESS) {
			ret_fid = FFA_ERROR;
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}
		spmc_fill_partition_entry(fpi, endpoint_id, 1);
	} else {
		ret_fid = FFA_ERROR;
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}

	ret_fid = FFA_SUCCESS_32;
	rxtx->tx_is_mine = false;
	rc = 1;

out:
	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, rc, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
	cpu_spin_unlock(&rxtx->spinlock);
}
#endif /*CFG_CORE_SEL1_SPMC*/

static void handle_yielding_call(struct thread_smc_args *args)
{
	TEE_Result res = 0;

	thread_check_canaries();

	if (args->a3 == OPTEE_FFA_YIELDING_CALL_RESUME) {
		/* Note connection to struct thread_rpc_arg::ret */
		thread_resume_from_rpc(args->a7, args->a4, args->a5, args->a6,
				       0);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		thread_alloc_and_run(args->a1, args->a3, args->a4, args->a5,
				     args->a6, args->a7);
		res = TEE_ERROR_BUSY;
	}
	spmc_set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
		      swap_src_dst(args->a1), 0, res, 0, 0);
}

static uint32_t handle_unregister_shm(uint32_t a4, uint32_t a5)
{
	uint64_t cookie = reg_pair_to_64(a5, a4);
	uint32_t res = 0;

	res = mobj_ffa_unregister_by_cookie(cookie);
	switch (res) {
	case TEE_SUCCESS:
	case TEE_ERROR_ITEM_NOT_FOUND:
		return 0;
	case TEE_ERROR_BUSY:
		EMSG("res %#"PRIx32, res);
		return FFA_BUSY;
	default:
		EMSG("res %#"PRIx32, res);
		return FFA_INVALID_PARAMETERS;
	}
}

static void handle_blocking_call(struct thread_smc_args *args)
{
	switch (args->a3) {
	case OPTEE_FFA_GET_API_VERSION:
		spmc_set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
			      swap_src_dst(args->a1), 0,
			      OPTEE_FFA_VERSION_MAJOR, OPTEE_FFA_VERSION_MINOR,
			      0);
		break;
	case OPTEE_FFA_GET_OS_VERSION:
		spmc_set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
			      swap_src_dst(args->a1), 0,
			      CFG_OPTEE_REVISION_MAJOR,
			      CFG_OPTEE_REVISION_MINOR, TEE_IMPL_GIT_SHA1);
		break;
	case OPTEE_FFA_EXCHANGE_CAPABILITIES:
		spmc_set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
			      swap_src_dst(args->a1), 0, 0,
			      THREAD_RPC_MAX_NUM_PARAMS, 0);
		break;
	case OPTEE_FFA_UNREGISTER_SHM:
		spmc_set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
			      swap_src_dst(args->a1), 0,
			      handle_unregister_shm(args->a4, args->a5), 0, 0);
		break;
	default:
		EMSG("Unhandled blocking service ID %#"PRIx32,
		     (uint32_t)args->a3);
		panic();
	}
}

#if defined(CFG_CORE_SEL1_SPMC)
static int get_acc_perms(struct ffa_mem_access *mem_acc,
			 unsigned int num_mem_accs, uint8_t *acc_perms,
			 unsigned int *region_offs)
{
	unsigned int n = 0;

	for (n = 0; n < num_mem_accs; n++) {
		struct ffa_mem_access_perm *descr = &mem_acc[n].access_perm;

		if (READ_ONCE(descr->endpoint_id) == my_endpoint_id) {
			*acc_perms = READ_ONCE(descr->perm);
			*region_offs = READ_ONCE(mem_acc[n].region_offs);
			return 0;
		}
	}

	return FFA_INVALID_PARAMETERS;
}

static int mem_share_init(void *buf, size_t blen, unsigned int *page_count,
			  unsigned int *region_count, size_t *addr_range_offs)
{
	const uint8_t exp_mem_reg_attr = FFA_NORMAL_MEM_REG_ATTR;
	const uint8_t exp_mem_acc_perm = FFA_MEM_ACC_RW;
	struct ffa_mem_region *region_descr = NULL;
	struct ffa_mem_transaction *descr = NULL;
	unsigned int num_mem_accs = 0;
	uint8_t mem_acc_perm = 0;
	unsigned int region_descr_offs = 0;
	size_t n = 0;

	if (!IS_ALIGNED_WITH_TYPE(buf, struct ffa_mem_transaction) ||
	    blen < sizeof(struct ffa_mem_transaction))
		return FFA_INVALID_PARAMETERS;

	descr = buf;

	/* Check that the endpoint memory access descriptor array fits */
	num_mem_accs = READ_ONCE(descr->mem_access_count);
	if (MUL_OVERFLOW(sizeof(struct ffa_mem_access), num_mem_accs, &n) ||
	    ADD_OVERFLOW(sizeof(*descr), n, &n) || n > blen)
		return FFA_INVALID_PARAMETERS;

	if (READ_ONCE(descr->mem_reg_attr) != exp_mem_reg_attr)
		return FFA_INVALID_PARAMETERS;

	/* Check that the access permissions matches what's expected */
	if (get_acc_perms(descr->mem_access_array,
			  num_mem_accs, &mem_acc_perm, &region_descr_offs) ||
	    mem_acc_perm != exp_mem_acc_perm)
		return FFA_INVALID_PARAMETERS;

	/* Check that the Composite memory region descriptor fits */
	if (ADD_OVERFLOW(region_descr_offs, sizeof(*region_descr), &n) ||
	    n > blen)
		return FFA_INVALID_PARAMETERS;

	if (!IS_ALIGNED_WITH_TYPE((vaddr_t)descr + region_descr_offs,
				  struct ffa_mem_region))
		return FFA_INVALID_PARAMETERS;

	region_descr = (struct ffa_mem_region *)((vaddr_t)descr +
						 region_descr_offs);
	*page_count = READ_ONCE(region_descr->total_page_count);
	*region_count = READ_ONCE(region_descr->address_range_count);
	*addr_range_offs = n;
	return 0;
}

static int add_mem_share_helper(struct mem_share_state *s, void *buf,
				size_t flen)
{
	unsigned int region_count = flen / sizeof(struct ffa_address_range);
	struct ffa_address_range *arange = NULL;
	unsigned int n = 0;

	if (region_count > s->region_count)
		region_count = s->region_count;

	if (!IS_ALIGNED_WITH_TYPE(buf, struct ffa_address_range))
		return FFA_INVALID_PARAMETERS;
	arange = buf;

	for (n = 0; n < region_count; n++) {
		unsigned int page_count = READ_ONCE(arange[n].page_count);
		uint64_t addr = READ_ONCE(arange[n].address);

		if (mobj_ffa_add_pages_at(s->mf, &s->current_page_idx,
					  addr, page_count))
			return FFA_INVALID_PARAMETERS;
	}

	s->region_count -= region_count;
	if (s->region_count)
		return region_count * sizeof(*arange);

	if (s->current_page_idx != s->page_count)
		return FFA_INVALID_PARAMETERS;

	return 0;
}

static int add_mem_share_frag(struct mem_frag_state *s, void *buf, size_t flen)
{
	int rc = 0;

	rc = add_mem_share_helper(&s->share, buf, flen);
	if (rc >= 0) {
		if (!ADD_OVERFLOW(s->frag_offset, rc, &s->frag_offset)) {
			if (s->share.region_count)
				return s->frag_offset;
			/* We're done, return the number of consumed bytes */
			rc = s->frag_offset;
		} else {
			rc = FFA_INVALID_PARAMETERS;
		}
	}

	SLIST_REMOVE(&frag_state_head, s, mem_frag_state, link);
	if (rc < 0)
		mobj_ffa_sel1_spmc_delete(s->share.mf);
	else
		mobj_ffa_push_to_inactive(s->share.mf);
	free(s);

	return rc;
}

static bool is_sp_share(void *buf)
{
	struct ffa_mem_transaction *input_descr = NULL;
	struct ffa_mem_access_perm *perm = NULL;

	if (!IS_ENABLED(CFG_SECURE_PARTITION))
		return false;

	input_descr = buf;
	perm = &input_descr->mem_access_array[0].access_perm;

	/*
	 * perm->endpoint_id is read here only to check if the endpoint is
	 * OP-TEE. We do read it later on again, but there are some additional
	 * checks there to make sure that the data is correct.
	 */
	return READ_ONCE(perm->endpoint_id) != my_endpoint_id;
}

static int add_mem_share(tee_mm_entry_t *mm, void *buf, size_t blen,
			 size_t flen, uint64_t *global_handle)
{
	int rc = 0;
	struct mem_share_state share = { };
	size_t addr_range_offs = 0;
	size_t n = 0;

	if (flen > blen)
		return FFA_INVALID_PARAMETERS;

	rc = mem_share_init(buf, flen, &share.page_count, &share.region_count,
			    &addr_range_offs);
	if (rc)
		return rc;

	if (MUL_OVERFLOW(share.region_count,
			 sizeof(struct ffa_address_range), &n) ||
	    ADD_OVERFLOW(n, addr_range_offs, &n) || n > blen)
		return FFA_INVALID_PARAMETERS;

	share.mf = mobj_ffa_sel1_spmc_new(share.page_count);
	if (!share.mf)
		return FFA_NO_MEMORY;

	if (flen != blen) {
		struct mem_frag_state *s = calloc(sizeof(*s), 1);

		if (!s) {
			rc = FFA_NO_MEMORY;
			goto err;
		}
		s->share = share;
		s->mm = mm;
		s->frag_offset = addr_range_offs;

		SLIST_INSERT_HEAD(&frag_state_head, s, link);
		rc = add_mem_share_frag(s, (char *)buf + addr_range_offs,
					flen - addr_range_offs);

		if (rc >= 0)
			*global_handle = mobj_ffa_get_cookie(share.mf);

		return rc;
	}

	rc = add_mem_share_helper(&share, (char *)buf + addr_range_offs,
				  flen - addr_range_offs);
	if (rc) {
		/*
		 * Number of consumed bytes may be returned instead of 0 for
		 * done.
		 */
		rc = FFA_INVALID_PARAMETERS;
		goto err;
	}

	*global_handle = mobj_ffa_push_to_inactive(share.mf);

	return 0;
err:
	mobj_ffa_sel1_spmc_delete(share.mf);
	return rc;
}

static int handle_mem_share_tmem(paddr_t pbuf, size_t blen, size_t flen,
				 unsigned int page_count,
				 uint64_t *global_handle, struct ffa_rxtx *rxtx)
{
	int rc = 0;
	size_t len = 0;
	tee_mm_entry_t *mm = NULL;
	vaddr_t offs = pbuf & SMALL_PAGE_MASK;

	if (MUL_OVERFLOW(page_count, SMALL_PAGE_SIZE, &len))
		return FFA_INVALID_PARAMETERS;
	if (!core_pbuf_is(CORE_MEM_NON_SEC, pbuf, len))
		return FFA_INVALID_PARAMETERS;

	/*
	 * Check that the length reported in blen is covered by len even
	 * if the offset is taken into account.
	 */
	if (len < blen || len - offs < blen)
		return FFA_INVALID_PARAMETERS;

	mm = tee_mm_alloc(&tee_mm_shm, len);
	if (!mm)
		return FFA_NO_MEMORY;

	if (core_mmu_map_contiguous_pages(tee_mm_get_smem(mm), pbuf,
					  page_count, MEM_AREA_NSEC_SHM)) {
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}

	cpu_spin_lock(&rxtx->spinlock);
	rc = add_mem_share(mm, (void *)(tee_mm_get_smem(mm) + offs), blen, flen,
			   global_handle);
	cpu_spin_unlock(&rxtx->spinlock);
	if (rc > 0)
		return rc;

	core_mmu_unmap_pages(tee_mm_get_smem(mm), page_count);
out:
	tee_mm_free(mm);
	return rc;
}

static int handle_mem_share_rxbuf(size_t blen, size_t flen,
				  uint64_t *global_handle,
				  struct ffa_rxtx *rxtx)
{
	int rc = FFA_DENIED;

	cpu_spin_lock(&rxtx->spinlock);

	if (rxtx->rx && flen <= rxtx->size) {
		if (is_sp_share(rxtx->rx)) {
			rc = spmc_sp_add_share(rxtx, blen,
					       global_handle, NULL);
		} else {
			rc = add_mem_share(NULL, rxtx->rx, blen, flen,
					   global_handle);
		}
	}

	cpu_spin_unlock(&rxtx->spinlock);

	return rc;
}

static void handle_mem_share(struct thread_smc_args *args,
			     struct ffa_rxtx *rxtx)
{
	uint32_t ret_w1 = 0;
	uint32_t ret_w2 = FFA_INVALID_PARAMETERS;
	uint32_t ret_w3 = 0;
	uint32_t ret_fid = FFA_ERROR;
	uint64_t global_handle = 0;
	int rc = 0;

	/* Check that the MBZs are indeed 0 */
	if (args->a5 || args->a6 || args->a7)
		goto out;

	if (!args->a3) {
		/*
		 * The memory transaction descriptor is passed via our rx
		 * buffer.
		 */
		if (args->a4)
			goto out;
		rc = handle_mem_share_rxbuf(args->a1, args->a2, &global_handle,
					    rxtx);
	} else {
		rc = handle_mem_share_tmem(args->a3, args->a1, args->a2,
					   args->a4, &global_handle, rxtx);
	}
	if (rc < 0) {
		ret_w2 = rc;
		goto out;
	}
	if (rc > 0) {
		ret_fid = FFA_MEM_FRAG_RX;
		ret_w3 = rc;
		reg_pair_from_64(global_handle, &ret_w2, &ret_w1);
	}
	ret_fid = FFA_SUCCESS_32;
	reg_pair_from_64(global_handle, &ret_w3, &ret_w2);
out:
	spmc_set_args(args, ret_fid, ret_w1, ret_w2, ret_w3, 0, 0);
}

static struct mem_frag_state *get_frag_state(uint64_t global_handle)
{
	struct mem_frag_state *s = NULL;

	SLIST_FOREACH(s, &frag_state_head, link)
		if (mobj_ffa_get_cookie(s->share.mf) == global_handle)
			return s;

	return NULL;
}

static void handle_mem_frag_tx(struct thread_smc_args *args,
			       struct ffa_rxtx *rxtx)
{
	int rc = 0;
	uint64_t global_handle = reg_pair_to_64(READ_ONCE(args->a2),
						READ_ONCE(args->a1));
	size_t flen = READ_ONCE(args->a3);
	struct mem_frag_state *s = NULL;
	tee_mm_entry_t *mm = NULL;
	unsigned int page_count = 0;
	void *buf = NULL;
	uint32_t ret_w1 = 0;
	uint32_t ret_w2 = 0;
	uint32_t ret_w3 = 0;
	uint32_t ret_fid = 0;

	/*
	 * Currently we're only doing this for fragmented FFA_MEM_SHARE_*
	 * requests.
	 */

	cpu_spin_lock(&rxtx->spinlock);

	s = get_frag_state(global_handle);
	if (!s) {
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}

	mm = s->mm;
	if (mm) {
		if (flen > tee_mm_get_bytes(mm)) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}
		page_count = s->share.page_count;
		buf = (void *)tee_mm_get_smem(mm);
	} else {
		if (flen > rxtx->size) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}
		buf = rxtx->rx;
	}

	rc = add_mem_share_frag(s, buf, flen);
out:
	cpu_spin_unlock(&rxtx->spinlock);

	if (rc <= 0 && mm) {
		core_mmu_unmap_pages(tee_mm_get_smem(mm), page_count);
		tee_mm_free(mm);
	}

	if (rc < 0) {
		ret_fid = FFA_ERROR;
		ret_w2 = rc;
	} else if (rc > 0) {
		ret_fid = FFA_MEM_FRAG_RX;
		ret_w3 = rc;
		reg_pair_from_64(global_handle, &ret_w2, &ret_w1);
	} else {
		ret_fid = FFA_SUCCESS_32;
		reg_pair_from_64(global_handle, &ret_w3, &ret_w2);
	}

	spmc_set_args(args, ret_fid, ret_w1, ret_w2, ret_w3, 0, 0);
}

static void handle_mem_reclaim(struct thread_smc_args *args)
{
	uint32_t ret_val = FFA_INVALID_PARAMETERS;
	uint32_t ret_fid = FFA_ERROR;
	uint64_t cookie = 0;

	if (args->a3 || args->a4 || args->a5 || args->a6 || args->a7)
		goto out;

	cookie = reg_pair_to_64(args->a2, args->a1);
	switch (mobj_ffa_sel1_spmc_reclaim(cookie)) {
	case TEE_SUCCESS:
		ret_fid = FFA_SUCCESS_32;
		ret_val = 0;
		break;
	case TEE_ERROR_ITEM_NOT_FOUND:
		DMSG("cookie %#"PRIx64" not found", cookie);
		ret_val = FFA_INVALID_PARAMETERS;
		break;
	default:
		DMSG("cookie %#"PRIx64" busy", cookie);
		ret_val = FFA_DENIED;
		break;
	}
out:
	spmc_set_args(args, ret_fid, ret_val, 0, 0, 0, 0);
}
#endif

/* Only called from assembly */
void thread_spmc_msg_recv(struct thread_smc_args *args);
void thread_spmc_msg_recv(struct thread_smc_args *args)
{
	assert((thread_get_exceptions() & THREAD_EXCP_ALL) == THREAD_EXCP_ALL);
	switch (args->a0) {
#if defined(CFG_CORE_SEL1_SPMC)
	case FFA_VERSION:
		spmc_handle_version(args);
		break;
	case FFA_FEATURES:
		handle_features(args);
		break;
#ifdef ARM64
	case FFA_RXTX_MAP_64:
#endif
	case FFA_RXTX_MAP_32:
		spmc_handle_rxtx_map(args, &nw_rxtx);
		break;
	case FFA_RXTX_UNMAP:
		spmc_handle_rxtx_unmap(args, &nw_rxtx);
		break;
	case FFA_RX_RELEASE:
		spmc_handle_rx_release(args, &nw_rxtx);
		break;
	case FFA_PARTITION_INFO_GET:
		spmc_handle_partition_info_get(args, &nw_rxtx);
		break;
#endif /*CFG_CORE_SEL1_SPMC*/
	case FFA_INTERRUPT:
		itr_core_handler();
		spmc_set_args(args, FFA_SUCCESS_32, args->a1, 0, 0, 0, 0);
		break;
	case FFA_MSG_SEND_DIRECT_REQ_32:
		if (IS_ENABLED(CFG_SECURE_PARTITION) &&
		    FFA_DST(args->a1) != my_endpoint_id) {
			spmc_sp_start_thread(args);
			break;
		}

		if (args->a3 & BIT32(OPTEE_FFA_YIELDING_CALL_BIT))
			handle_yielding_call(args);
		else
			handle_blocking_call(args);
		break;
#if defined(CFG_CORE_SEL1_SPMC)
#ifdef ARM64
	case FFA_MEM_SHARE_64:
#endif
	case FFA_MEM_SHARE_32:
		handle_mem_share(args, &nw_rxtx);
		break;
	case FFA_MEM_RECLAIM:
		if (!IS_ENABLED(CFG_SECURE_PARTITION) ||
		    !ffa_mem_reclaim(args, NULL))
			handle_mem_reclaim(args);
		break;
	case FFA_MEM_FRAG_TX:
		handle_mem_frag_tx(args, &nw_rxtx);
		break;
#endif /*CFG_CORE_SEL1_SPMC*/
	default:
		EMSG("Unhandled FFA function ID %#"PRIx32, (uint32_t)args->a0);
		spmc_set_args(args, FFA_ERROR, FFA_PARAM_MBZ, FFA_NOT_SUPPORTED,
			      FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
	}
}

static uint32_t yielding_call_with_arg(uint64_t cookie, uint32_t offset)
{
	size_t sz_rpc = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t rv = TEE_ERROR_BAD_PARAMETERS;
	struct optee_msg_arg *arg = NULL;
	struct mobj *mobj = NULL;
	uint32_t num_params = 0;
	size_t sz = 0;

	mobj = mobj_ffa_get_by_cookie(cookie, 0);
	if (!mobj) {
		EMSG("Can't find cookie %#"PRIx64, cookie);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rv = mobj_inc_map(mobj);
	if (rv)
		goto out_put_mobj;

	rv = TEE_ERROR_BAD_PARAMETERS;
	arg = mobj_get_va(mobj, offset, sizeof(*arg));
	if (!arg)
		goto out_dec_map;

	num_params = READ_ONCE(arg->num_params);
	if (num_params > OPTEE_MSG_MAX_NUM_PARAMS)
		goto out_dec_map;

	sz = OPTEE_MSG_GET_ARG_SIZE(num_params);

	thr->rpc_arg = mobj_get_va(mobj, offset + sz, sz_rpc);
	if (!thr->rpc_arg)
		goto out_dec_map;

	rv = tee_entry_std(arg, num_params);

	thread_rpc_shm_cache_clear(&thr->shm_cache);
	thr->rpc_arg = NULL;

out_dec_map:
	mobj_dec_map(mobj);
out_put_mobj:
	mobj_put(mobj);
	return rv;
}

/*
 * Helper routine for the assembly function thread_std_smc_entry()
 *
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
uint32_t __weak __thread_std_smc_entry(uint32_t a0, uint32_t a1,
				       uint32_t a2, uint32_t a3,
				       uint32_t a4, uint32_t a5 __unused)
{
	/*
	 * Arguments are supplied from handle_yielding_call() as:
	 * a0 <- w1
	 * a1 <- w3
	 * a2 <- w4
	 * a3 <- w5
	 * a4 <- w6
	 * a5 <- w7
	 */
	thread_get_tsd()->rpc_target_info = swap_src_dst(a0);
	if (a1 == OPTEE_FFA_YIELDING_CALL_WITH_ARG)
		return yielding_call_with_arg(reg_pair_to_64(a3, a2), a4);
	return FFA_DENIED;
}

static bool set_fmem(struct optee_msg_param *param, struct thread_param *tpm)
{
	uint64_t offs = tpm->u.memref.offs;

	param->attr = tpm->attr - THREAD_PARAM_ATTR_MEMREF_IN +
		      OPTEE_MSG_ATTR_TYPE_FMEM_INPUT;

	param->u.fmem.offs_low = offs;
	param->u.fmem.offs_high = offs >> 32;
	if (param->u.fmem.offs_high != offs >> 32)
		return false;

	param->u.fmem.size = tpm->u.memref.size;
	if (tpm->u.memref.mobj) {
		uint64_t cookie = mobj_get_cookie(tpm->u.memref.mobj);

		/* If a mobj is passed it better be one with a valid cookie. */
		if (cookie == OPTEE_MSG_FMEM_INVALID_GLOBAL_ID)
			return false;
		param->u.fmem.global_id = cookie;
	} else {
		param->u.fmem.global_id = OPTEE_MSG_FMEM_INVALID_GLOBAL_ID;
	}

	return true;
}

static uint32_t get_rpc_arg(uint32_t cmd, size_t num_params,
			    struct thread_param *params,
			    struct optee_msg_arg **arg_ret)
{
	size_t sz = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);
	struct thread_ctx *thr = threads + thread_get_id();
	struct optee_msg_arg *arg = thr->rpc_arg;

	if (num_params > THREAD_RPC_MAX_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!arg) {
		EMSG("rpc_arg not set");
		return TEE_ERROR_GENERIC;
	}

	memset(arg, 0, sz);
	arg->cmd = cmd;
	arg->num_params = num_params;
	arg->ret = TEE_ERROR_GENERIC; /* in case value isn't updated */

	for (size_t n = 0; n < num_params; n++) {
		switch (params[n].attr) {
		case THREAD_PARAM_ATTR_NONE:
			arg->params[n].attr = OPTEE_MSG_ATTR_TYPE_NONE;
			break;
		case THREAD_PARAM_ATTR_VALUE_IN:
		case THREAD_PARAM_ATTR_VALUE_OUT:
		case THREAD_PARAM_ATTR_VALUE_INOUT:
			arg->params[n].attr = params[n].attr -
					      THREAD_PARAM_ATTR_VALUE_IN +
					      OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			arg->params[n].u.value.a = params[n].u.value.a;
			arg->params[n].u.value.b = params[n].u.value.b;
			arg->params[n].u.value.c = params[n].u.value.c;
			break;
		case THREAD_PARAM_ATTR_MEMREF_IN:
		case THREAD_PARAM_ATTR_MEMREF_OUT:
		case THREAD_PARAM_ATTR_MEMREF_INOUT:
			if (!set_fmem(arg->params + n, params + n))
				return TEE_ERROR_BAD_PARAMETERS;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	if (arg_ret)
		*arg_ret = arg;

	return TEE_SUCCESS;
}

static uint32_t get_rpc_arg_res(struct optee_msg_arg *arg, size_t num_params,
				struct thread_param *params)
{
	for (size_t n = 0; n < num_params; n++) {
		switch (params[n].attr) {
		case THREAD_PARAM_ATTR_VALUE_OUT:
		case THREAD_PARAM_ATTR_VALUE_INOUT:
			params[n].u.value.a = arg->params[n].u.value.a;
			params[n].u.value.b = arg->params[n].u.value.b;
			params[n].u.value.c = arg->params[n].u.value.c;
			break;
		case THREAD_PARAM_ATTR_MEMREF_OUT:
		case THREAD_PARAM_ATTR_MEMREF_INOUT:
			params[n].u.memref.size = arg->params[n].u.fmem.size;
			break;
		default:
			break;
		}
	}

	return arg->ret;
}

uint32_t thread_rpc_cmd(uint32_t cmd, size_t num_params,
			struct thread_param *params)
{
	struct thread_rpc_arg rpc_arg = { .call = {
			.w1 = thread_get_tsd()->rpc_target_info,
			.w4 = OPTEE_FFA_YIELDING_CALL_RETURN_RPC_CMD,
		},
	};
	struct optee_msg_arg *arg = NULL;
	uint32_t ret = 0;

	ret = get_rpc_arg(cmd, num_params, params, &arg);
	if (ret)
		return ret;

	thread_rpc(&rpc_arg);

	return get_rpc_arg_res(arg, num_params, params);
}

static void thread_rpc_free(unsigned int bt, uint64_t cookie, struct mobj *mobj)
{
	struct thread_rpc_arg rpc_arg = { .call = {
			.w1 = thread_get_tsd()->rpc_target_info,
			.w4 = OPTEE_FFA_YIELDING_CALL_RETURN_RPC_CMD,
		},
	};
	struct thread_param param = THREAD_PARAM_VALUE(IN, bt, cookie, 0);
	uint32_t res2 = 0;
	uint32_t res = 0;

	DMSG("freeing cookie %#"PRIx64, cookie);

	res = get_rpc_arg(OPTEE_RPC_CMD_SHM_FREE, 1, &param, NULL);

	mobj_put(mobj);
	res2 = mobj_ffa_unregister_by_cookie(cookie);
	if (res2)
		DMSG("mobj_ffa_unregister_by_cookie(%#"PRIx64"): %#"PRIx32,
		     cookie, res2);
	if (!res)
		thread_rpc(&rpc_arg);
}

static struct mobj *thread_rpc_alloc(size_t size, size_t align, unsigned int bt)
{
	struct thread_rpc_arg rpc_arg = { .call = {
			.w1 = thread_get_tsd()->rpc_target_info,
			.w4 = OPTEE_FFA_YIELDING_CALL_RETURN_RPC_CMD,
		},
	};
	struct thread_param param = THREAD_PARAM_VALUE(IN, bt, size, align);
	struct optee_msg_arg *arg = NULL;
	unsigned int internal_offset = 0;
	struct mobj *mobj = NULL;
	uint64_t cookie = 0;

	if (get_rpc_arg(OPTEE_RPC_CMD_SHM_ALLOC, 1, &param, &arg))
		return NULL;

	thread_rpc(&rpc_arg);

	if (arg->num_params != 1 ||
	    arg->params->attr != OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT)
		return NULL;

	internal_offset = READ_ONCE(arg->params->u.fmem.internal_offs);
	cookie = READ_ONCE(arg->params->u.fmem.global_id);
	mobj = mobj_ffa_get_by_cookie(cookie, internal_offset);
	if (!mobj) {
		DMSG("mobj_ffa_get_by_cookie(%#"PRIx64", %#x): failed",
		     cookie, internal_offset);
		return NULL;
	}

	assert(mobj_is_nonsec(mobj));

	if (mobj->size < size) {
		DMSG("Mobj %#"PRIx64": wrong size", cookie);
		mobj_put(mobj);
		return NULL;
	}

	if (mobj_inc_map(mobj)) {
		DMSG("mobj_inc_map(%#"PRIx64"): failed", cookie);
		mobj_put(mobj);
		return NULL;
	}

	return mobj;
}

struct mobj *thread_rpc_alloc_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_APPL);
}

struct mobj *thread_rpc_alloc_kernel_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_KERNEL);
}

void thread_rpc_free_kernel_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_RPC_SHM_TYPE_KERNEL, mobj_get_cookie(mobj), mobj);
}

void thread_rpc_free_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_RPC_SHM_TYPE_APPL, mobj_get_cookie(mobj),
			mobj);
}

struct mobj *thread_rpc_alloc_global_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_GLOBAL);
}

void thread_rpc_free_global_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_RPC_SHM_TYPE_GLOBAL, mobj_get_cookie(mobj),
			mobj);
}

#ifdef CFG_CORE_SEL2_SPMC
static bool is_ffa_success(uint32_t fid)
{
#ifdef ARM64
	if (fid == FFA_SUCCESS_64)
		return true;
#endif
	return fid == FFA_SUCCESS_32;
}

static void spmc_rxtx_map(struct ffa_rxtx *rxtx)
{
	struct thread_smc_args args = {
#ifdef ARM64
		.a0 = FFA_RXTX_MAP_64,
#else
		.a0 = FFA_RXTX_MAP_32,
#endif
		.a1 = (vaddr_t)rxtx->tx,
		.a2 = (vaddr_t)rxtx->rx,
		.a3 = 1,
	};

	thread_smccc(&args);
	if (!is_ffa_success(args.a0)) {
		if (args.a0 == FFA_ERROR)
			EMSG("rxtx map failed with error %ld", args.a2);
		else
			EMSG("rxtx map failed");
		panic();
	}
}

static uint16_t spmc_get_id(void)
{
	struct thread_smc_args args = {
		.a0 = FFA_ID_GET,
	};

	thread_smccc(&args);
	if (!is_ffa_success(args.a0)) {
		if (args.a0 == FFA_ERROR)
			EMSG("Get id failed with error %ld", args.a2);
		else
			EMSG("Get id failed");
		panic();
	}

	return args.a2;
}

static struct ffa_mem_transaction *spmc_retrieve_req(uint64_t cookie)
{
	struct ffa_mem_transaction *trans_descr = nw_rxtx.tx;
	struct ffa_mem_access *acc_descr_array = NULL;
	struct ffa_mem_access_perm *perm_descr = NULL;
	size_t size = sizeof(*trans_descr) +
		      1 * sizeof(struct ffa_mem_access);
	struct thread_smc_args args = {
		.a0 = FFA_MEM_RETRIEVE_REQ_32,
		.a1 =   size,	/* Total Length */
		.a2 =	size,	/* Frag Length == Total length */
		.a3 =	0,	/* Address, Using TX -> MBZ */
		.a4 =   0,	/* Using TX -> MBZ */
	};

	memset(trans_descr, 0, size);
	trans_descr->sender_id = thread_get_tsd()->rpc_target_info;
	trans_descr->mem_reg_attr = FFA_NORMAL_MEM_REG_ATTR;
	trans_descr->global_handle = cookie;
	trans_descr->flags = FFA_MEMORY_REGION_FLAG_TIME_SLICE |
			     FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE |
			     FFA_MEMORY_REGION_FLAG_ANY_ALIGNMENT;
	trans_descr->mem_access_count = 1;
	acc_descr_array = trans_descr->mem_access_array;
	acc_descr_array->region_offs = 0;
	acc_descr_array->reserved = 0;
	perm_descr = &acc_descr_array->access_perm;
	perm_descr->endpoint_id = my_endpoint_id;
	perm_descr->perm = FFA_MEM_ACC_RW;
	perm_descr->flags = FFA_MEMORY_REGION_FLAG_TIME_SLICE;

	thread_smccc(&args);
	if (args.a0 != FFA_MEM_RETRIEVE_RESP) {
		if (args.a0 == FFA_ERROR)
			EMSG("Failed to fetch cookie %#"PRIx64" error code %d",
			     cookie, (int)args.a2);
		else
			EMSG("Failed to fetch cookie %#"PRIx64" a0 %#"PRIx64,
			     cookie, args.a0);
		return NULL;
	}

	return nw_rxtx.rx;
}

void thread_spmc_relinquish(uint64_t cookie)
{
	struct ffa_mem_relinquish *relinquish_desc = nw_rxtx.tx;
	struct thread_smc_args args = {
		.a0 = FFA_MEM_RELINQUISH,
	};

	memset(relinquish_desc, 0, sizeof(*relinquish_desc));
	relinquish_desc->handle = cookie;
	relinquish_desc->flags = 0;
	relinquish_desc->endpoint_count = 1;
	relinquish_desc->endpoint_id_array[0] = my_endpoint_id;
	thread_smccc(&args);
	if (!is_ffa_success(args.a0))
		EMSG("Failed to relinquish cookie %#"PRIx64, cookie);
}

static int set_pages(struct ffa_address_range *regions,
		     unsigned int num_regions, unsigned int num_pages,
		     struct mobj_ffa *mf)
{
	unsigned int n = 0;
	unsigned int idx = 0;

	for (n = 0; n < num_regions; n++) {
		unsigned int page_count = READ_ONCE(regions[n].page_count);
		uint64_t addr = READ_ONCE(regions[n].address);

		if (mobj_ffa_add_pages_at(mf, &idx, addr, page_count))
			return FFA_INVALID_PARAMETERS;
	}

	if (idx != num_pages)
		return FFA_INVALID_PARAMETERS;

	return 0;
}

struct mobj_ffa *thread_spmc_populate_mobj_from_rx(uint64_t cookie)
{
	struct mobj_ffa *ret = NULL;
	struct ffa_mem_transaction *retrieve_desc = NULL;
	struct ffa_mem_access *descr_array = NULL;
	struct ffa_mem_region *descr = NULL;
	struct mobj_ffa *mf = NULL;
	unsigned int num_pages = 0;
	unsigned int offs = 0;
	struct thread_smc_args ffa_rx_release_args = {
		.a0 = FFA_RX_RELEASE
	};

	/*
	 * OP-TEE is only supporting a single mem_region while the
	 * specification allows for more than one.
	 */
	retrieve_desc = spmc_retrieve_req(cookie);
	if (!retrieve_desc) {
		EMSG("Failed to retrieve cookie from rx buffer %#"PRIx64,
		     cookie);
		return NULL;
	}

	descr_array = retrieve_desc->mem_access_array;
	offs = READ_ONCE(descr_array->region_offs);
	descr = (struct ffa_mem_region *)((vaddr_t)retrieve_desc + offs);

	num_pages = READ_ONCE(descr->total_page_count);
	mf = mobj_ffa_sel2_spmc_new(cookie, num_pages);
	if (!mf)
		goto out;

	if (set_pages(descr->address_range_array,
		      READ_ONCE(descr->address_range_count), num_pages, mf)) {
		mobj_ffa_sel2_spmc_delete(mf);
		goto out;
	}

	ret = mf;

out:
	/* Release RX buffer after the mem retrieve request. */
	thread_smccc(&ffa_rx_release_args);

	return ret;
}

static TEE_Result spmc_init(void)
{
	spmc_rxtx_map(&nw_rxtx);
	my_endpoint_id = spmc_get_id();
	DMSG("My endpoint ID %#x", my_endpoint_id);

	return TEE_SUCCESS;
}
#endif /*CFG_CORE_SEL2_SPMC*/

#if defined(CFG_CORE_SEL1_SPMC)
static TEE_Result spmc_init(void)
{
	my_endpoint_id = SPMC_ENDPOINT_ID;
	DMSG("My endpoint ID %#x", my_endpoint_id);

	return TEE_SUCCESS;
}
#endif /*CFG_CORE_SEL1_SPMC*/

service_init(spmc_init);
