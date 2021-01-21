// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited.
 * Copyright (c) 2019-2021, Arm Limited. All rights reserved.
 */

#include <assert.h>
#include <ffa.h>
#include <io.h>
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
#include <util.h>

#include "thread_private.h"

/* Table 39: Constituent memory region descriptor */
struct constituent_address_range {
	uint64_t address;
	uint32_t page_count;
	uint32_t reserved;
};

/* Table 38: Composite memory region descriptor */
struct mem_region_descr {
	uint32_t total_page_count;
	uint32_t address_range_count;
	uint64_t reserved;
	struct constituent_address_range address_range_array[];
};

/* Table 40: Memory access permissions descriptor */
struct mem_access_perm_descr {
	uint16_t endpoint_id;
	uint8_t access_perm;
	uint8_t flags;
};

/* Table 41: Endpoint memory access descriptor */
struct mem_accsess_descr {
	struct mem_access_perm_descr mem_access_perm_descr;
	uint32_t mem_region_offs;
	uint64_t reserved;
};

/* Table 44: Lend, donate or share memory transaction descriptor */
struct mem_transaction_descr {
	uint16_t sender_id;
	uint8_t mem_reg_attr;
	uint8_t reserved0;
	uint32_t flags;
	uint64_t global_handle;
	uint64_t tag;
	uint32_t reserved1;
	uint32_t mem_access_descr_count;
	struct mem_accsess_descr mem_accsess_descr_array[];
};

struct ffa_partition_info {
	uint16_t id;
	uint16_t execution_context;
	uint32_t partition_properties;
};

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

/*
 * If @rxtx_size is 0 RX/TX buffers are not mapped or initialized.
 *
 * @rxtx_spinlock protects the variables below from concurrent access
 * this includes the use of content of @rx_buf and @frag_state_head.
 *
 * @tx_buf_is_mine is true when we may write to tx_buf and false when it is
 * owned by normal world.
 *
 * Note that we can't prevent normal world from updating the content of
 * these buffers so we must always be careful when reading. while we hold
 * the lock.
 */
static void *rx_buf;
static void *tx_buf;
static unsigned int rxtx_size;
static unsigned int rxtx_spinlock;
static bool tx_buf_is_mine;

static SLIST_HEAD(mem_frag_state_head, mem_frag_state) frag_state_head =
	SLIST_HEAD_INITIALIZER(&frag_state_head);

static uint32_t swap_src_dst(uint32_t src_dst)
{
	return (src_dst >> 16) | (src_dst << 16);
}

static void set_args(struct thread_smc_args *args, uint32_t fid,
		     uint32_t src_dst, uint32_t w2, uint32_t w3, uint32_t w4,
		     uint32_t w5)
{
	*args = (struct thread_smc_args){ .a0 = fid,
					  .a1 = src_dst,
					  .a2 = w2,
					  .a3 = w3,
					  .a4 = w4,
					  .a5 = w5, };
}

static void handle_version(struct thread_smc_args *args)
{
	/*
	 * We currently only support one version, 1.0 so let's keep it
	 * simple.
	 */
	set_args(args, MAKE_FFA_VERSION(FFA_VERSION_MAJOR, FFA_VERSION_MINOR),
		 FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ,
		 FFA_PARAM_MBZ);
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

	set_args(args, ret_fid, FFA_PARAM_MBZ, ret_w2,
		 FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
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

static void handle_rxtx_map(struct thread_smc_args *args)
{
	int rc = 0;
	uint32_t ret_fid = FFA_ERROR;
	unsigned int sz = 0;
	paddr_t rx_pa = 0;
	paddr_t tx_pa = 0;
	void *rx = NULL;
	void *tx = NULL;

	cpu_spin_lock(&rxtx_spinlock);

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

	if (rxtx_size) {
		rc = FFA_DENIED;
		goto out;
	}

	rc = map_buf(tx_pa, sz, &tx);
	if (rc)
		goto out;
	rc = map_buf(rx_pa, sz, &rx);
	if (rc) {
		unmap_buf(tx, sz);
		goto out;
	}

	tx_buf = tx;
	rx_buf = rx;
	rxtx_size = sz;
	tx_buf_is_mine = true;
	ret_fid = FFA_SUCCESS_32;
	DMSG("Mapped tx %#"PRIxPA" size %#x @ %p", tx_pa, sz, tx);
	DMSG("Mapped rx %#"PRIxPA" size %#x @ %p", rx_pa, sz, rx);
out:
	cpu_spin_unlock(&rxtx_spinlock);
	set_args(args, ret_fid, FFA_PARAM_MBZ, rc,
		 FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static void handle_rxtx_unmap(struct thread_smc_args *args)
{
	uint32_t ret_fid = FFA_ERROR;
	int rc = FFA_INVALID_PARAMETERS;

	cpu_spin_lock(&rxtx_spinlock);

	if (!rxtx_size)
		goto out;
	unmap_buf(rx_buf, rxtx_size);
	unmap_buf(tx_buf, rxtx_size);
	rxtx_size = 0;
	rx_buf = NULL;
	tx_buf = NULL;
	ret_fid = FFA_SUCCESS_32;
	rc = 0;
out:
	cpu_spin_unlock(&rxtx_spinlock);
	set_args(args, ret_fid, FFA_PARAM_MBZ, rc,
		 FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static void handle_rx_release(struct thread_smc_args *args)
{
	uint32_t ret_fid = 0;
	int rc = 0;

	cpu_spin_lock(&rxtx_spinlock);
	/* The senders RX is our TX */
	if (!rxtx_size || tx_buf_is_mine) {
		ret_fid = FFA_ERROR;
		rc = FFA_DENIED;
	} else {
		ret_fid = FFA_SUCCESS_32;
		rc = 0;
		tx_buf_is_mine = true;
	}
	cpu_spin_unlock(&rxtx_spinlock);

	set_args(args, ret_fid, FFA_PARAM_MBZ, rc,
		 FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static bool is_nil_uuid(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3)
{
	return !w0 && !w1 && !w2 && !w3;
}

static bool is_optee_os_uuid(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3)
{
	return w0 == OPTEE_MSG_OS_OPTEE_UUID_0 &&
	       w1 == OPTEE_MSG_OS_OPTEE_UUID_1 &&
	       w2 == OPTEE_MSG_OS_OPTEE_UUID_2 &&
	       w3 == OPTEE_MSG_OS_OPTEE_UUID_3;
}

static void handle_partition_info_get(struct thread_smc_args *args)
{
	uint32_t ret_fid = 0;
	int rc = 0;

	if (!is_nil_uuid(args->a1, args->a2, args->a3, args->a4) &&
	    !is_optee_os_uuid(args->a1, args->a2, args->a3, args->a4)) {
		ret_fid = FFA_ERROR;
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}

	cpu_spin_lock(&rxtx_spinlock);
	if (rxtx_size && tx_buf_is_mine) {
		struct ffa_partition_info *fpi = tx_buf;

		fpi->id = SPMC_ENDPOINT_ID;
		fpi->execution_context = CFG_TEE_CORE_NB_CORE;
		fpi->partition_properties = BIT(0) | BIT(1);

		ret_fid = FFA_SUCCESS_32;
		rc = 1;
		tx_buf_is_mine = false;
	} else {
		ret_fid = FFA_ERROR;
		if (rxtx_size)
			rc = FFA_BUSY;
		else
			rc = FFA_DENIED; /* TX buffer not setup yet */
	}
	cpu_spin_unlock(&rxtx_spinlock);

out:
	set_args(args, ret_fid, FFA_PARAM_MBZ, rc,
		 FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static void handle_yielding_call(struct thread_smc_args *args)
{
	uint32_t ret_val = 0;

	thread_check_canaries();

	if (args->a3 == OPTEE_FFA_YIELDING_CALL_RESUME) {
		/* Note connection to struct thread_rpc_arg::ret */
		thread_resume_from_rpc(args->a7, args->a4, args->a5, args->a6,
				       0);
		ret_val = FFA_INVALID_PARAMETERS;
	} else {
		thread_alloc_and_run(args->a1, args->a3, args->a4, args->a5);
		ret_val = FFA_BUSY;
	}
	set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
		 swap_src_dst(args->a1), 0, ret_val, 0, 0);
}

static void handle_blocking_call(struct thread_smc_args *args)
{
	switch (args->a3) {
	case OPTEE_FFA_GET_API_VERSION:
		set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
			 swap_src_dst(args->a1), 0, OPTEE_FFA_VERSION_MAJOR,
			 OPTEE_FFA_VERSION_MINOR, 0);
		break;
	case OPTEE_FFA_GET_OS_VERSION:
		set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
			 swap_src_dst(args->a1), 0, CFG_OPTEE_REVISION_MAJOR,
			 CFG_OPTEE_REVISION_MINOR, TEE_IMPL_GIT_SHA1);
		break;
	case OPTEE_FFA_EXCHANGE_CAPABILITIES:
		set_args(args, FFA_MSG_SEND_DIRECT_RESP_32,
			 swap_src_dst(args->a1), 0, 0, 0, 0);
		break;
	default:
		EMSG("Unhandled blocking service ID %#"PRIx32,
		     (uint32_t)args->a3);
		panic();
	}
}

static int get_acc_perms(struct mem_accsess_descr *mem_acc,
			 unsigned int num_mem_accs, uint8_t *acc_perms,
			 unsigned int *region_offs)
{
	unsigned int n = 0;

	for (n = 0; n < num_mem_accs; n++) {
		struct mem_access_perm_descr *descr =
			&mem_acc[n].mem_access_perm_descr;

		if (READ_ONCE(descr->endpoint_id) == SPMC_ENDPOINT_ID) {
			*acc_perms = READ_ONCE(descr->access_perm);
			*region_offs = READ_ONCE(mem_acc[n].mem_region_offs);
			return 0;
		}
	}

	return FFA_INVALID_PARAMETERS;
}

static int mem_share_init(void *buf, size_t blen, unsigned int *page_count,
			  unsigned int *region_count, size_t *addr_range_offs)
{
	struct mem_region_descr *region_descr = NULL;
	struct mem_transaction_descr *descr = NULL;
	const uint8_t exp_mem_acc_perm = 0x6; /* Not executable, Read-write */
	/* Normal memory, Write-Back cacheable, Inner shareable */
	const uint8_t exp_mem_reg_attr = 0x2f;
	unsigned int num_mem_accs = 0;
	uint8_t mem_acc_perm = 0;
	unsigned int region_descr_offs = 0;
	size_t n = 0;

	if (!ALIGNMENT_IS_OK(buf, struct mem_transaction_descr) ||
	    blen < sizeof(struct mem_transaction_descr))
		return FFA_INVALID_PARAMETERS;

	descr = buf;

	/* Check that the endpoint memory access descriptor array fits */
	num_mem_accs = READ_ONCE(descr->mem_access_descr_count);
	if (MUL_OVERFLOW(sizeof(struct mem_accsess_descr), num_mem_accs, &n) ||
	    ADD_OVERFLOW(sizeof(*descr), n, &n) || n > blen)
		return FFA_INVALID_PARAMETERS;

	if (READ_ONCE(descr->mem_reg_attr) != exp_mem_reg_attr)
		return FFA_INVALID_PARAMETERS;

	/* Check that the access permissions matches what's expected */
	if (get_acc_perms(descr->mem_accsess_descr_array,
			  num_mem_accs, &mem_acc_perm, &region_descr_offs) ||
	    mem_acc_perm != exp_mem_acc_perm)
		return FFA_INVALID_PARAMETERS;

	/* Check that the Composite memory region descriptor fits */
	if (ADD_OVERFLOW(region_descr_offs, sizeof(*region_descr), &n) ||
	    n > blen)
		return FFA_INVALID_PARAMETERS;

	if (!ALIGNMENT_IS_OK((vaddr_t)descr + region_descr_offs,
			     struct mem_region_descr))
		return FFA_INVALID_PARAMETERS;

	region_descr = (struct mem_region_descr *)((vaddr_t)descr +
						    region_descr_offs);
	*page_count = READ_ONCE(region_descr->total_page_count);
	*region_count = READ_ONCE(region_descr->address_range_count);
	*addr_range_offs = n;
	return 0;
}

static int add_mem_share_helper(struct mem_share_state *s, void *buf,
				size_t flen)
{
	unsigned int region_count = flen /
				    sizeof(struct constituent_address_range);
	struct constituent_address_range *arange = NULL;
	unsigned int n = 0;

	if (region_count > s->region_count)
		region_count = s->region_count;

	if (!ALIGNMENT_IS_OK(buf, struct constituent_address_range))
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
			 sizeof(struct constituent_address_range), &n) ||
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
				 uint64_t *global_handle)
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

	cpu_spin_lock(&rxtx_spinlock);
	rc = add_mem_share(mm, (void *)(tee_mm_get_smem(mm) + offs), blen, flen,
			   global_handle);
	cpu_spin_unlock(&rxtx_spinlock);
	if (rc > 0)
		return rc;

	core_mmu_unmap_pages(tee_mm_get_smem(mm), page_count);
out:
	tee_mm_free(mm);
	return rc;
}

static int handle_mem_share_rxbuf(size_t blen, size_t flen,
				  uint64_t *global_handle)
{
	int rc = FFA_DENIED;

	cpu_spin_lock(&rxtx_spinlock);

	if (rx_buf && flen <= rxtx_size)
		rc = add_mem_share(NULL, rx_buf, blen, flen, global_handle);

	cpu_spin_unlock(&rxtx_spinlock);

	return rc;
}

static void handle_mem_share(struct thread_smc_args *args)
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
		rc = handle_mem_share_rxbuf(args->a1, args->a2, &global_handle);
	} else {
		rc = handle_mem_share_tmem(args->a3, args->a1, args->a2,
					   args->a4, &global_handle);
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
	set_args(args, ret_fid, ret_w1, ret_w2, ret_w3, 0, 0);
}

static struct mem_frag_state *get_frag_state(uint64_t global_handle)
{
	struct mem_frag_state *s = NULL;

	SLIST_FOREACH(s, &frag_state_head, link)
		if (mobj_ffa_get_cookie(s->share.mf) == global_handle)
			return s;

	return NULL;
}

static void handle_mem_frag_tx(struct thread_smc_args *args)
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

	cpu_spin_lock(&rxtx_spinlock);

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
		if (flen > rxtx_size) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}
		buf = rx_buf;
	}

	rc = add_mem_share_frag(s, buf, flen);
out:
	cpu_spin_unlock(&rxtx_spinlock);

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

	set_args(args, ret_fid, ret_w1, ret_w2, ret_w3, 0, 0);
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
	set_args(args, ret_fid, ret_val, 0, 0, 0, 0);
}

/* Only called from assembly */
void thread_spmc_msg_recv(struct thread_smc_args *args);
void thread_spmc_msg_recv(struct thread_smc_args *args)
{
	assert((thread_get_exceptions() & THREAD_EXCP_ALL) == THREAD_EXCP_ALL);
	switch (args->a0) {
	case FFA_VERSION:
		handle_version(args);
		break;
	case FFA_FEATURES:
		handle_features(args);
		break;
#ifdef ARM64
	case FFA_RXTX_MAP_64:
#endif
	case FFA_RXTX_MAP_32:
		handle_rxtx_map(args);
		break;
	case FFA_RXTX_UNMAP:
		handle_rxtx_unmap(args);
		break;
	case FFA_RX_RELEASE:
		handle_rx_release(args);
		break;
	case FFA_PARTITION_INFO_GET:
		handle_partition_info_get(args);
		break;
	case FFA_INTERRUPT:
		itr_core_handler();
		set_args(args, FFA_SUCCESS_32, args->a1, 0, 0, 0, 0);
		break;
	case FFA_MSG_SEND_DIRECT_REQ_32:
		if (IS_ENABLED(CFG_SECURE_PARTITION) &&
		    FFA_DST(args->a1) != SPMC_ENDPOINT_ID) {
			spmc_sp_start_thread(args);
			break;
		}

		if (args->a3 & BIT32(OPTEE_FFA_YIELDING_CALL_BIT))
			handle_yielding_call(args);
		else
			handle_blocking_call(args);
		break;
#ifdef ARM64
	case FFA_MEM_SHARE_64:
#endif
	case FFA_MEM_SHARE_32:
		handle_mem_share(args);
		break;
	case FFA_MEM_RECLAIM:
		handle_mem_reclaim(args);
		break;
	case FFA_MEM_FRAG_TX:
		handle_mem_frag_tx(args);
		break;
	default:
		EMSG("Unhandled FFA function ID %#"PRIx32, (uint32_t)args->a0);
		set_args(args, FFA_ERROR, FFA_PARAM_MBZ, FFA_NOT_SUPPORTED,
			 FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
	}
}

static uint32_t yielding_call_with_arg(uint64_t cookie)
{
	uint32_t rv = TEE_ERROR_BAD_PARAMETERS;
	struct optee_msg_arg *arg = NULL;
	struct mobj *mobj = NULL;
	uint32_t num_params = 0;

	mobj = mobj_ffa_get_by_cookie(cookie, 0);
	if (!mobj) {
		EMSG("Can't find cookie %#"PRIx64, cookie);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rv = mobj_inc_map(mobj);
	if (rv)
		goto out_put_mobj;

	rv = TEE_ERROR_BAD_PARAMETERS;
	arg = mobj_get_va(mobj, 0);
	if (!arg)
		goto out_dec_map;

	if (!mobj_get_va(mobj, sizeof(*arg)))
		goto out_dec_map;

	num_params = READ_ONCE(arg->num_params);
	if (num_params > OPTEE_MSG_MAX_NUM_PARAMS)
		goto out_dec_map;

	if (!mobj_get_va(mobj, OPTEE_MSG_GET_ARG_SIZE(num_params)))
		goto out_dec_map;

	rv = tee_entry_std(arg, num_params);

	thread_rpc_shm_cache_clear(&threads[thread_get_id()].shm_cache);

out_dec_map:
	mobj_dec_map(mobj);
out_put_mobj:
	mobj_put(mobj);
	return rv;
}

static uint32_t yielding_unregister_shm(uint64_t cookie)
{
	uint32_t res = mobj_ffa_unregister_by_cookie(cookie);

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

/*
 * Helper routine for the assembly function thread_std_smc_entry()
 *
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
uint32_t __weak __thread_std_smc_entry(uint32_t a0, uint32_t a1,
				       uint32_t a2, uint32_t a3)
{
	/*
	 * Arguments are supplied from handle_yielding_call() as:
	 * a0 <- w1
	 * a1 <- w3
	 * a2 <- w4
	 * a3 <- w5
	 */
	thread_get_tsd()->rpc_target_info = swap_src_dst(a0);
	switch (a1) {
	case OPTEE_FFA_YIELDING_CALL_WITH_ARG:
		return yielding_call_with_arg(reg_pair_to_64(a3, a2));
	case OPTEE_FFA_YIELDING_CALL_REGISTER_SHM:
		return FFA_NOT_SUPPORTED;
	case OPTEE_FFA_YIELDING_CALL_UNREGISTER_SHM:
		return yielding_unregister_shm(reg_pair_to_64(a3, a2));
	default:
		return FFA_DENIED;
	}
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
		param->u.fmem.global_id = mobj_get_cookie(tpm->u.memref.mobj);
		if (!param->u.fmem.global_id)
			return false;
	} else {
		param->u.fmem.global_id = 0;
	}

	return true;
}

static void thread_rpc_free(uint32_t type, uint64_t cookie, struct mobj *mobj)
{
	TEE_Result res = TEE_SUCCESS;
	struct thread_rpc_arg rpc_arg = { .call = {
			.w1 = thread_get_tsd()->rpc_target_info,
			.w4 = type,
		},
	};

	reg_pair_from_64(cookie, &rpc_arg.call.w6, &rpc_arg.call.w5);
	mobj_put(mobj);
	res = mobj_ffa_unregister_by_cookie(cookie);
	if (res)
		DMSG("mobj_ffa_unregister_by_cookie(%#"PRIx64"): res %#"PRIx32,
		     cookie, res);
	thread_rpc(&rpc_arg);
}

static struct mobj *thread_rpc_alloc(size_t size, uint32_t type)
{
	struct mobj *mobj = NULL;
	unsigned int page_count = ROUNDUP(size, SMALL_PAGE_SIZE) /
				  SMALL_PAGE_SIZE;
	struct thread_rpc_arg rpc_arg = { .call = {
			.w1 = thread_get_tsd()->rpc_target_info,
			.w4 = type,
			.w5 = page_count,
		},
	};
	unsigned int internal_offset = 0;
	uint64_t cookie = 0;

	thread_rpc(&rpc_arg);

	cookie = reg_pair_to_64(rpc_arg.ret.w5, rpc_arg.ret.w4);
	if (!cookie)
		return NULL;
	internal_offset = rpc_arg.ret.w6;

	mobj = mobj_ffa_get_by_cookie(cookie, internal_offset);
	if (!mobj) {
		DMSG("mobj_ffa_get_by_cookie(%#"PRIx64", %#x): failed",
		     cookie, internal_offset);
		return NULL;
	}

	assert(mobj_is_nonsec(mobj));

	if (mobj_inc_map(mobj)) {
		DMSG("mobj_inc_map(%#"PRIx64"): failed", cookie);
		mobj_put(mobj);
		return NULL;
	}

	return mobj;
}

struct mobj *thread_rpc_alloc_payload(size_t size)
{
	return thread_rpc_alloc(size,
				OPTEE_FFA_YIELDING_CALL_RETURN_ALLOC_SUPPL_SHM);
}

void thread_rpc_free_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_FFA_YIELDING_CALL_RETURN_FREE_SUPPL_SHM,
			mobj_get_cookie(mobj), mobj);
}

struct mobj *thread_rpc_alloc_kernel_payload(size_t size)
{
	return thread_rpc_alloc(size,
				OPTEE_FFA_YIELDING_CALL_RETURN_ALLOC_KERN_SHM);
}

void thread_rpc_free_kernel_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_FFA_YIELDING_CALL_RETURN_FREE_KERN_SHM,
			mobj_get_cookie(mobj), mobj);
}

static uint32_t get_rpc_arg(uint32_t cmd, size_t num_params,
			    struct thread_param *params,
			    struct optee_msg_arg **arg_ret,
			    uint64_t *carg_ret)
{
	size_t sz = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);
	struct thread_ctx *thr = threads + thread_get_id();
	struct optee_msg_arg *arg = thr->rpc_arg;

	if (num_params > THREAD_RPC_MAX_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!arg) {
		struct mobj *mobj = thread_rpc_alloc_kernel_payload(sz);

		if (!mobj)
			return TEE_ERROR_OUT_OF_MEMORY;

		arg = mobj_get_va(mobj, 0);
		if (!arg) {
			thread_rpc_free_kernel_payload(mobj);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		thr->rpc_arg = arg;
		thr->rpc_mobj = mobj;
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

	*arg_ret = arg;
	*carg_ret = mobj_get_cookie(thr->rpc_mobj);

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
	uint64_t carg = 0;
	struct optee_msg_arg *arg = NULL;
	uint32_t ret = 0;

	ret = get_rpc_arg(cmd, num_params, params, &arg, &carg);
	if (ret)
		return ret;

	reg_pair_from_64(carg, &rpc_arg.call.w6, &rpc_arg.call.w5);
	thread_rpc(&rpc_arg);

	return get_rpc_arg_res(arg, num_params, params);
}

struct mobj *thread_rpc_alloc_global_payload(size_t size __unused)
{
	return NULL;
}

void thread_rpc_free_global_payload(struct mobj *mobj __unused)
{
	/*
	 * "can't happen" since thread_rpc_alloc_global_payload() always
	 * returns NULL.
	 */
	volatile bool cant_happen __maybe_unused = true;

	assert(!cant_happen);
}
