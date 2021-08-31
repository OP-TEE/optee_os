// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Linaro Limited
 */

#include <assert.h>
#include <bitstring.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <mm/mobj.h>
#include <sys/queue.h>

struct mobj_ffa {
	struct mobj mobj;
	SLIST_ENTRY(mobj_ffa) link;
	uint64_t cookie;
	tee_mm_entry_t *mm;
	struct refcount mapcount;
	uint16_t page_offset;
#ifdef CFG_CORE_SEL1_SPMC
	bool registered_by_cookie;
	bool unregistered_by_cookie;
#endif
	paddr_t pages[];
};

SLIST_HEAD(mobj_ffa_head, mobj_ffa);

#ifdef CFG_CORE_SEL1_SPMC
#define NUM_SHMS	64
static bitstr_t bit_decl(shm_bits, NUM_SHMS);
#endif

static struct mobj_ffa_head shm_head = SLIST_HEAD_INITIALIZER(shm_head);
static struct mobj_ffa_head shm_inactive_head =
	SLIST_HEAD_INITIALIZER(shm_inactive_head);

static unsigned int shm_lock = SPINLOCK_UNLOCK;

const struct mobj_ops mobj_ffa_ops;

static struct mobj_ffa *to_mobj_ffa(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_ffa_ops);
	return container_of(mobj, struct mobj_ffa, mobj);
}

static size_t shm_size(size_t num_pages)
{
	size_t s = 0;

	if (MUL_OVERFLOW(sizeof(paddr_t), num_pages, &s))
		return 0;
	if (ADD_OVERFLOW(sizeof(struct mobj_ffa), s, &s))
		return 0;
	return s;
}

static struct mobj_ffa *ffa_new(unsigned int num_pages)
{
	struct mobj_ffa *mf = NULL;
	size_t s = 0;

	if (!num_pages)
		return NULL;

	s = shm_size(num_pages);
	if (!s)
		return NULL;
	mf = calloc(1, s);
	if (!mf)
		return NULL;

	mf->mobj.ops = &mobj_ffa_ops;
	mf->mobj.size = num_pages * SMALL_PAGE_SIZE;
	mf->mobj.phys_granule = SMALL_PAGE_SIZE;
	refcount_set(&mf->mobj.refc, 0);

	return mf;
}

#ifdef CFG_CORE_SEL1_SPMC
struct mobj_ffa *mobj_ffa_sel1_spmc_new(unsigned int num_pages)
{
	struct mobj_ffa *mf = NULL;
	uint32_t exceptions = 0;
	int i = 0;

	mf = ffa_new(num_pages);
	if (!mf)
		return NULL;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	bit_ffc(shm_bits, NUM_SHMS, &i);
	if (i != -1) {
		bit_set(shm_bits, i);
		/*
		 * Setting bit 44 to use one of the upper 32 bits too for
		 * testing.
		 */
		mf->cookie = i | BIT64(44);
	}
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	if (i == -1) {
		free(mf);
		return NULL;
	}

	return mf;
}
#endif /*CFG_CORE_SEL1_SPMC*/

static size_t get_page_count(struct mobj_ffa *mf)
{
	return ROUNDUP(mf->mobj.size, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE;
}

static bool cmp_cookie(struct mobj_ffa *mf, uint64_t cookie)
{
	return mf->cookie == cookie;
}

static bool cmp_ptr(struct mobj_ffa *mf, uint64_t ptr)
{
	return mf == (void *)(vaddr_t)ptr;
}

static struct mobj_ffa *pop_from_list(struct mobj_ffa_head *head,
				      bool (*cmp_func)(struct mobj_ffa *mf,
						       uint64_t val),
				      uint64_t val)
{
	struct mobj_ffa *mf = SLIST_FIRST(head);
	struct mobj_ffa *p = NULL;

	if (!mf)
		return NULL;

	if (cmp_func(mf, val)) {
		SLIST_REMOVE_HEAD(head, link);
		return mf;
	}

	while (true) {
		p = SLIST_NEXT(mf, link);
		if (!p)
			return NULL;
		if (cmp_func(p, val)) {
			SLIST_REMOVE_AFTER(mf, link);
			return p;
		}
		mf = p;
	}
}

static struct mobj_ffa *find_in_list(struct mobj_ffa_head *head,
				     bool (*cmp_func)(struct mobj_ffa *mf,
						      uint64_t val),
				     uint64_t val)
{
	struct mobj_ffa *mf = NULL;

	SLIST_FOREACH(mf, head, link)
		if (cmp_func(mf, val))
			return mf;

	return NULL;
}

#ifdef CFG_CORE_SEL1_SPMC
void mobj_ffa_sel1_spmc_delete(struct mobj_ffa *mf)
{
	int i = mf->cookie & ~BIT64(44);
	uint32_t exceptions = 0;

	assert(i >= 0 && i < NUM_SHMS);

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	assert(bit_test(shm_bits, i));
	bit_clear(shm_bits, i);
	assert(!mf->mm);
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	free(mf);
}
#endif /*CFG_CORE_SEL1_SPMC*/

#ifdef CFG_CORE_SEL2_SPMC
struct mobj_ffa *mobj_ffa_sel2_spmc_new(uint64_t cookie,
					unsigned int num_pages)
{
	struct mobj_ffa *mf = NULL;

	assert(cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID);
	mf = ffa_new(num_pages);
	if (mf)
		mf->cookie = cookie;
	return mf;
}

void mobj_ffa_sel2_spmc_delete(struct mobj_ffa *mf)
{
	free(mf);
}
#endif /*CFG_CORE_SEL2_SPMC*/

TEE_Result mobj_ffa_add_pages_at(struct mobj_ffa *mf, unsigned int *idx,
				 paddr_t pa, unsigned int num_pages)
{
	unsigned int n = 0;
	size_t tot_page_count = get_page_count(mf);

	if (ADD_OVERFLOW(*idx, num_pages, &n) || n > tot_page_count)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!core_pbuf_is(CORE_MEM_NON_SEC, pa, num_pages * SMALL_PAGE_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	for (n = 0; n < num_pages; n++)
		mf->pages[n + *idx] = pa + n * SMALL_PAGE_SIZE;

	(*idx) += n;
	return TEE_SUCCESS;
}

uint64_t mobj_ffa_get_cookie(struct mobj_ffa *mf)
{
	return mf->cookie;
}

uint64_t mobj_ffa_push_to_inactive(struct mobj_ffa *mf)
{
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	assert(!find_in_list(&shm_inactive_head, cmp_ptr, (vaddr_t)mf));
	assert(!find_in_list(&shm_inactive_head, cmp_cookie, mf->cookie));
	assert(!find_in_list(&shm_head, cmp_cookie, mf->cookie));
	SLIST_INSERT_HEAD(&shm_inactive_head, mf, link);
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	return mf->cookie;
}

static void unmap_helper(struct mobj_ffa *mf)
{
	if (mf->mm) {
		core_mmu_unmap_pages(tee_mm_get_smem(mf->mm),
				     get_page_count(mf));
		tee_mm_free(mf->mm);
		mf->mm = NULL;
	}
}

#ifdef CFG_CORE_SEL1_SPMC
TEE_Result mobj_ffa_sel1_spmc_reclaim(uint64_t cookie)
{
	TEE_Result res = TEE_SUCCESS;
	struct mobj_ffa *mf = NULL;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	mf = find_in_list(&shm_head, cmp_cookie, cookie);
	/*
	 * If the mobj is found here it's still active and cannot be
	 * reclaimed.
	 */
	if (mf) {
		DMSG("cookie %#"PRIx64" busy refc %u",
		     cookie, refcount_val(&mf->mobj.refc));
		res = TEE_ERROR_BUSY;
		goto out;
	}

	mf = find_in_list(&shm_inactive_head, cmp_cookie, cookie);
	if (!mf) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}
	/*
	 * If the mobj has been registered via mobj_ffa_get_by_cookie()
	 * but not unregistered yet with mobj_ffa_unregister_by_cookie().
	 */
	if (mf->registered_by_cookie && !mf->unregistered_by_cookie) {
		DMSG("cookie %#"PRIx64" busy", cookie);
		res = TEE_ERROR_BUSY;
		goto out;
	}

	if (!pop_from_list(&shm_inactive_head, cmp_ptr, (vaddr_t)mf))
		panic();
	res = TEE_SUCCESS;
out:
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);
	if (!res)
		mobj_ffa_sel1_spmc_delete(mf);
	return res;
}
#endif /*CFG_CORE_SEL1_SPMC*/

TEE_Result mobj_ffa_unregister_by_cookie(uint64_t cookie)
{
	TEE_Result res = TEE_SUCCESS;
	struct mobj_ffa *mf = NULL;
	uint32_t exceptions = 0;

	assert(cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID);
	exceptions = cpu_spin_lock_xsave(&shm_lock);
	mf = find_in_list(&shm_head, cmp_cookie, cookie);
	/*
	 * If the mobj is found here it's still active and cannot be
	 * unregistered.
	 */
	if (mf) {
		DMSG("cookie %#"PRIx64" busy refc %u",
		     cookie, refcount_val(&mf->mobj.refc));
		res = TEE_ERROR_BUSY;
		goto out;
	}
	mf = find_in_list(&shm_inactive_head, cmp_cookie, cookie);
	/*
	 * If the mobj isn't found or if it already has been unregistered.
	 */
#ifdef CFG_CORE_SEL2_SPMC
	if (!mf) {
#else
	if (!mf || mf->unregistered_by_cookie) {
#endif
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

#ifdef CFG_CORE_SEL2_SPMC
	mf = pop_from_list(&shm_inactive_head, cmp_cookie, cookie);
	mobj_ffa_sel2_spmc_delete(mf);
	thread_spmc_relinquish(cookie);
#else
	mf->unregistered_by_cookie = true;
#endif
	res = TEE_SUCCESS;

out:
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);
	return res;
}

struct mobj *mobj_ffa_get_by_cookie(uint64_t cookie,
				    unsigned int internal_offs)
{
	struct mobj_ffa *mf = NULL;
	uint32_t exceptions = 0;

	if (internal_offs >= SMALL_PAGE_SIZE)
		return NULL;
	exceptions = cpu_spin_lock_xsave(&shm_lock);
	mf = find_in_list(&shm_head, cmp_cookie, cookie);
	if (mf) {
		if (mf->page_offset == internal_offs) {
			if (!refcount_inc(&mf->mobj.refc)) {
				/*
				 * If refcount is 0 some other thread has
				 * called mobj_put() on this reached 0 and
				 * before ffa_inactivate() got the lock we
				 * found it. Let's reinitialize it.
				 */
				refcount_set(&mf->mobj.refc, 1);
			}
			DMSG("cookie %#"PRIx64" active: refc %d",
			     cookie, refcount_val(&mf->mobj.refc));
		} else {
			EMSG("cookie %#"PRIx64" mismatching internal_offs got %#"PRIx16" expected %#x",
			     cookie, mf->page_offset, internal_offs);
			mf = NULL;
		}
	} else {
		mf = pop_from_list(&shm_inactive_head, cmp_cookie, cookie);
#if defined(CFG_CORE_SEL2_SPMC)
		/* Try to retrieve it from the SPM at S-EL2 */
		if (mf) {
			DMSG("cookie %#"PRIx64" resurrecting", cookie);
		} else {
			EMSG("Populating mobj from rx buffer, cookie %#"PRIx64,
			     cookie);
			mf = thread_spmc_populate_mobj_from_rx(cookie);
		}
#endif
		if (mf) {
#if defined(CFG_CORE_SEL1_SPMC)
			mf->unregistered_by_cookie = false;
			mf->registered_by_cookie = true;
#endif
			assert(refcount_val(&mf->mobj.refc) == 0);
			refcount_set(&mf->mobj.refc, 1);
			refcount_set(&mf->mapcount, 0);
			mf->mobj.size += mf->page_offset;
			assert(!(mf->mobj.size & SMALL_PAGE_MASK));
			mf->mobj.size -= internal_offs;
			mf->page_offset = internal_offs;
			SLIST_INSERT_HEAD(&shm_head, mf, link);
		}
	}

	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	if (!mf) {
		EMSG("Failed to get cookie %#"PRIx64" internal_offs %#x",
		     cookie, internal_offs);
		return NULL;
	}
	return &mf->mobj;
}

static TEE_Result ffa_get_pa(struct mobj *mobj, size_t offset,
			     size_t granule, paddr_t *pa)
{
	struct mobj_ffa *mf = to_mobj_ffa(mobj);
	size_t full_offset = 0;
	paddr_t p = 0;

	if (!pa)
		return TEE_ERROR_GENERIC;

	if (offset >= mobj->size)
		return TEE_ERROR_GENERIC;

	full_offset = offset + mf->page_offset;
	switch (granule) {
	case 0:
		p = mf->pages[full_offset / SMALL_PAGE_SIZE] +
		    (full_offset & SMALL_PAGE_MASK);
		break;
	case SMALL_PAGE_SIZE:
		p = mf->pages[full_offset / SMALL_PAGE_SIZE];
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	*pa = p;

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(ffa_get_pa);

static size_t ffa_get_phys_offs(struct mobj *mobj,
				size_t granule __maybe_unused)
{
	assert(granule >= mobj->phys_granule);

	return to_mobj_ffa(mobj)->page_offset;
}

static void *ffa_get_va(struct mobj *mobj, size_t offset)
{
	struct mobj_ffa *mf = to_mobj_ffa(mobj);

	if (!mf->mm || offset >= mobj->size)
		return NULL;

	return (void *)(tee_mm_get_smem(mf->mm) + offset + mf->page_offset);
}

static void ffa_inactivate(struct mobj *mobj)
{
	struct mobj_ffa *mf = to_mobj_ffa(mobj);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	/*
	 * If refcount isn't 0 some other thread has found this mobj in
	 * shm_head after the mobj_put() that put us here and before we got
	 * the lock.
	 */
	if (refcount_val(&mobj->refc)) {
		DMSG("cookie %#"PRIx64" was resurrected", mf->cookie);
		goto out;
	}

	DMSG("cookie %#"PRIx64, mf->cookie);
	if (!pop_from_list(&shm_head, cmp_ptr, (vaddr_t)mf))
		panic();
	unmap_helper(mf);
	SLIST_INSERT_HEAD(&shm_inactive_head, mf, link);
out:
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);
}

static TEE_Result ffa_get_cattr(struct mobj *mobj __unused, uint32_t *cattr)
{
	if (!cattr)
		return TEE_ERROR_GENERIC;

	*cattr = TEE_MATTR_CACHE_CACHED;

	return TEE_SUCCESS;
}

static bool ffa_matches(struct mobj *mobj __maybe_unused, enum buf_is_attr attr)
{
	assert(mobj->ops == &mobj_ffa_ops);

	return attr == CORE_MEM_NON_SEC || attr == CORE_MEM_REG_SHM;
}

static uint64_t ffa_get_cookie(struct mobj *mobj)
{
	return to_mobj_ffa(mobj)->cookie;
}

static TEE_Result ffa_inc_map(struct mobj *mobj)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;
	struct mobj_ffa *mf = to_mobj_ffa(mobj);

	if (refcount_inc(&mf->mapcount))
		return TEE_SUCCESS;

	exceptions = cpu_spin_lock_xsave(&shm_lock);

	if (refcount_val(&mf->mapcount))
		goto out;

	mf->mm = tee_mm_alloc(&tee_mm_shm, mf->mobj.size);
	if (!mf->mm) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = core_mmu_map_pages(tee_mm_get_smem(mf->mm), mf->pages,
				 get_page_count(mf), MEM_AREA_NSEC_SHM);
	if (res) {
		tee_mm_free(mf->mm);
		mf->mm = NULL;
		goto out;
	}

	refcount_set(&mf->mapcount, 1);
out:
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	return res;
}

static TEE_Result ffa_dec_map(struct mobj *mobj)
{
	struct mobj_ffa *mf = to_mobj_ffa(mobj);
	uint32_t exceptions = 0;

	if (!refcount_dec(&mf->mapcount))
		return TEE_SUCCESS;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	unmap_helper(mf);
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	return TEE_SUCCESS;
}

static TEE_Result mapped_shm_init(void)
{
	vaddr_t pool_start = 0;
	vaddr_t pool_end = 0;

	core_mmu_get_mem_by_type(MEM_AREA_SHM_VASPACE, &pool_start, &pool_end);
	if (!pool_start || !pool_end)
		panic("Can't find region for shmem pool");

	if (!tee_mm_init(&tee_mm_shm, pool_start, pool_end, SMALL_PAGE_SHIFT,
			 TEE_MM_POOL_NO_FLAGS))
		panic("Could not create shmem pool");

	DMSG("Shared memory address range: %#"PRIxVA", %#"PRIxVA,
	     pool_start, pool_end);
	return TEE_SUCCESS;
}

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct mobj_ops mobj_ffa_ops __weak __rodata_unpaged("mobj_ffa_ops") = {
	.get_pa = ffa_get_pa,
	.get_phys_offs = ffa_get_phys_offs,
	.get_va = ffa_get_va,
	.get_cattr = ffa_get_cattr,
	.matches = ffa_matches,
	.free = ffa_inactivate,
	.get_cookie = ffa_get_cookie,
	.inc_map = ffa_inc_map,
	.dec_map = ffa_dec_map,
};

preinit(mapped_shm_init);
