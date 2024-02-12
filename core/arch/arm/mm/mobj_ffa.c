// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Linaro Limited
 */

#include <assert.h>
#include <bitstring.h>
#include <config.h>
#include <ffa.h>
#include <initcall.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <kernel/thread_spmc.h>
#include <kernel/virtualization.h>
#include <mm/mobj.h>
#include <sys/queue.h>

/*
 * Life cycle of struct mobj_ffa
 *
 * SPMC at S-EL1 (CFG_CORE_SEL1_SPMC=y)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * During FFA_MEM_SHARE allocated in mobj_ffa_sel1_spmc_new() and finally
 * added to the inactive list at the end of add_mem_share() once
 * successfully filled in.
 *	registered_by_cookie = false
 *	mobj.refs.val = 0
 *	inactive_refs = 0
 *
 * During FFA_MEM_RECLAIM reclaimed/freed using
 * mobj_ffa_sel1_spmc_reclaim().  This will always succeed if the normal
 * world is only calling this when all other threads are done with the
 * shared memory object. However, there are some conditions that must be
 * met to make sure that this is the case:
 *	mobj not in the active list, else -> return TEE_ERROR_BUSY
 *	mobj not in inactive list, else -> return TEE_ERROR_ITEM_NOT_FOUND
 *	mobj inactive_refs is 0, else -> return TEE_ERROR_BUSY
 *
 * mobj is activated using mobj_ffa_get_by_cookie() which unless the mobj
 * is active already:
 * - move the mobj into the active list
 * - if not registered_by_cookie ->
 *	set registered_by_cookie and increase inactive_refs
 * - set mobj.refc.val to 1
 * - increase inactive_refs
 *
 * A previously activated mobj is made ready for reclaim using
 * mobj_ffa_unregister_by_cookie() which only succeeds if the mobj is in
 * the inactive list and registered_by_cookie is set and then:
 * - clears registered_by_cookie
 * - decreases inactive_refs
 *
 * Each successful call to mobj_ffa_get_by_cookie() must be matched by a
 * call to mobj_put(). If the mobj.refc.val reaches 0 it's
 * - moved to the inactive list
 * - inactive_refs is decreased
 *
 * SPMC at S-EL2/EL3 (CFG_CORE_SEL1_SPMC=n)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * mobj is activated/allocated using mobj_ffa_get_by_cookie() which if
 * already active only is
 * - increasing mobj.refc.val and inactive_refs
 * if found in inactive list is
 * - setting mobj.refc.val to 1
 * - increasing inactive_refs
 * - moved into active list
 * if not found is created using thread_spmc_populate_mobj_from_rx() and
 * then:
 * - setting mobj.refc.val to 1
 * - increasing inactive_refs
 * - moved into active list
 *
 * A previously activated mobj is relinquished using
 * mobj_ffa_unregister_by_cookie() which only succeeds if the mobj is in
 * the inactive list and inactive_refs is 1
 */
struct mobj_ffa {
	struct mobj mobj;
	SLIST_ENTRY(mobj_ffa) link;
	uint64_t cookie;
	tee_mm_entry_t *mm;
	struct refcount mapcount;
	unsigned int inactive_refs;
	uint16_t page_offset;
#ifdef CFG_CORE_SEL1_SPMC
	bool registered_by_cookie;
#endif
	paddr_t pages[];
};

SLIST_HEAD(mobj_ffa_head, mobj_ffa);

#ifdef CFG_CORE_SEL1_SPMC
#ifdef CFG_NS_VIRTUALIZATION
static bitstr_t *get_shm_bits(void)
{
	return virt_get_shm_bits();
}
#else
static bitstr_t bit_decl(__shm_bits, SPMC_CORE_SEL1_MAX_SHM_COUNT);

static bitstr_t *get_shm_bits(void)
{
	return __shm_bits;
}
#endif
#endif

static struct mobj_ffa_head shm_head = SLIST_HEAD_INITIALIZER(shm_head);
static struct mobj_ffa_head shm_inactive_head =
	SLIST_HEAD_INITIALIZER(shm_inactive_head);

static unsigned int shm_lock = SPINLOCK_UNLOCK;

static const struct mobj_ops mobj_ffa_ops;

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
	mf->inactive_refs = 0;

	return mf;
}

#ifdef CFG_CORE_SEL1_SPMC
struct mobj_ffa *mobj_ffa_sel1_spmc_new(uint64_t cookie,
					unsigned int num_pages)
{
	struct mobj_ffa *mf = NULL;
	bitstr_t *shm_bits = NULL;
	uint32_t exceptions = 0;
	int i = 0;

	if (cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID) {
		if (!(cookie & FFA_MEMORY_HANDLE_HYPERVISOR_BIT))
			return NULL;
		if (virt_add_cookie_to_current_guest(cookie))
			return NULL;
	}

	mf = ffa_new(num_pages);
	if (!mf) {
		if (cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID)
			virt_remove_cookie(cookie);
		return NULL;
	}

	if (cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID) {
		mf->cookie = cookie;
		return mf;
	}

	shm_bits = get_shm_bits();
	exceptions = cpu_spin_lock_xsave(&shm_lock);
	bit_ffc(shm_bits, SPMC_CORE_SEL1_MAX_SHM_COUNT, &i);
	if (i != -1) {
		bit_set(shm_bits, i);
		mf->cookie = i;
		mf->cookie |= FFA_MEMORY_HANDLE_NON_SECURE_BIT;
		/*
		 * Encode the partition ID into the handle so we know which
		 * partition to switch to when reclaiming a handle.
		 */
		mf->cookie |= SHIFT_U64(virt_get_current_guest_id(),
					FFA_MEMORY_HANDLE_PRTN_SHIFT);
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

#if defined(CFG_CORE_SEL1_SPMC)
void mobj_ffa_sel1_spmc_delete(struct mobj_ffa *mf)
{

	if (!IS_ENABLED(CFG_NS_VIRTUALIZATION) ||
	    !(mf->cookie & FFA_MEMORY_HANDLE_HYPERVISOR_BIT)) {
		uint64_t mask = FFA_MEMORY_HANDLE_NON_SECURE_BIT;
		bitstr_t *shm_bits = get_shm_bits();
		uint32_t exceptions = 0;
		int64_t i = 0;

		if (IS_ENABLED(CFG_NS_VIRTUALIZATION))
			mask |= SHIFT_U64(FFA_MEMORY_HANDLE_PRTN_MASK,
					  FFA_MEMORY_HANDLE_PRTN_SHIFT);
		i = mf->cookie & ~mask;
		assert(i >= 0 && i < SPMC_CORE_SEL1_MAX_SHM_COUNT);

		exceptions = cpu_spin_lock_xsave(&shm_lock);
		assert(bit_test(shm_bits, i));
		bit_clear(shm_bits, i);
		cpu_spin_unlock_xrestore(&shm_lock, exceptions);
	}

	assert(!mf->mm);
	free(mf);
}
#else /* !defined(CFG_CORE_SEL1_SPMC) */
struct mobj_ffa *mobj_ffa_spmc_new(uint64_t cookie, unsigned int num_pages)
{
	struct mobj_ffa *mf = NULL;

	assert(cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID);
	mf = ffa_new(num_pages);
	if (mf)
		mf->cookie = cookie;
	return mf;
}

void mobj_ffa_spmc_delete(struct mobj_ffa *mf)
{
	free(mf);
}
#endif /* !defined(CFG_CORE_SEL1_SPMC) */

TEE_Result mobj_ffa_add_pages_at(struct mobj_ffa *mf, unsigned int *idx,
				 paddr_t pa, unsigned int num_pages)
{
	unsigned int n = 0;
	size_t tot_page_count = get_page_count(mf);

	if (ADD_OVERFLOW(*idx, num_pages, &n) || n > tot_page_count)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ENABLED(CFG_CORE_SEL2_SPMC) &&
	    !core_pbuf_is(CORE_MEM_NON_SEC, pa, num_pages * SMALL_PAGE_SIZE))
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
	if (mf->inactive_refs) {
		DMSG("cookie %#"PRIx64" busy inactive_refs %u",
		     cookie, mf->inactive_refs);
		res = TEE_ERROR_BUSY;
		goto out;
	}

	if (!pop_from_list(&shm_inactive_head, cmp_ptr, (vaddr_t)mf))
		panic();
	res = TEE_SUCCESS;
out:
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);
	if (!res) {
		mobj_ffa_sel1_spmc_delete(mf);
		virt_remove_cookie(cookie);
	}
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
		EMSG("cookie %#"PRIx64" busy refc %u:%u",
		     cookie, refcount_val(&mf->mobj.refc), mf->inactive_refs);
		res = TEE_ERROR_BUSY;
		goto out;
	}
	mf = find_in_list(&shm_inactive_head, cmp_cookie, cookie);
	/*
	 * If the mobj isn't found or if it already has been unregistered.
	 */
	if (!mf) {
		EMSG("cookie %#"PRIx64" not found", cookie);
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}
#if defined(CFG_CORE_SEL1_SPMC)
	if (!mf->registered_by_cookie) {
		/*
		 * This is expected behaviour if the normal world has
		 * registered the memory but OP-TEE has not yet used the
		 * corresponding cookie with mobj_ffa_get_by_cookie(). It
		 * can be non-trivial for the normal world to predict if
		 * the cookie really has been used or not. So even if we
		 * return it as an error it will be ignored by
		 * handle_unregister_shm().
		 */
		EMSG("cookie %#"PRIx64" not registered refs %u:%u",
		     cookie, refcount_val(&mf->mobj.refc), mf->inactive_refs);
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}
	assert(mf->inactive_refs);
	mf->inactive_refs--;
	mf->registered_by_cookie = false;
#else
	if (mf->inactive_refs) {
		EMSG("cookie %#"PRIx64" busy refc %u:%u",
		     cookie, refcount_val(&mf->mobj.refc), mf->inactive_refs);
		res = TEE_ERROR_BUSY;
		goto out;
	}
	mf = pop_from_list(&shm_inactive_head, cmp_cookie, cookie);
	mobj_ffa_spmc_delete(mf);
	thread_spmc_relinquish(cookie);
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
				mf->inactive_refs++;
			}
			DMSG("cookie %#"PRIx64" active: refc %u:%u",
			     cookie, refcount_val(&mf->mobj.refc),
			     mf->inactive_refs);
		} else {
			EMSG("cookie %#"PRIx64" mismatching internal_offs got %#"PRIx16" expected %#x",
			     cookie, mf->page_offset, internal_offs);
			mf = NULL;
		}
	} else {
		mf = pop_from_list(&shm_inactive_head, cmp_cookie, cookie);
#if !defined(CFG_CORE_SEL1_SPMC)
		/* Try to retrieve it from the SPM at S-EL2 */
		if (mf) {
			DMSG("cookie %#"PRIx64" resurrecting", cookie);
		} else {
			DMSG("Populating mobj from rx buffer, cookie %#"PRIx64,
			     cookie);
			mf = thread_spmc_populate_mobj_from_rx(cookie);
		}
#endif
		if (mf) {
#if defined(CFG_CORE_SEL1_SPMC)
			if (!mf->registered_by_cookie) {
				mf->inactive_refs++;
				mf->registered_by_cookie = true;
			}
#endif
			assert(refcount_val(&mf->mobj.refc) == 0);
			refcount_set(&mf->mobj.refc, 1);
			refcount_set(&mf->mapcount, 0);
			mf->inactive_refs++;

			/*
			 * mf->page_offset is offset into the first page.
			 * This offset is assigned from the internal_offs
			 * parameter to this function.
			 *
			 * While a mobj_ffa is active (ref_count > 0) this
			 * will not change, but when being pushed to the
			 * inactive list it can be changed again.
			 *
			 * So below we're backing out the old
			 * mf->page_offset and then assigning a new from
			 * internal_offset.
			 */
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

static size_t ffa_get_phys_offs(struct mobj *mobj,
				size_t granule __maybe_unused)
{
	assert(granule >= mobj->phys_granule);

	return to_mobj_ffa(mobj)->page_offset;
}

static void *ffa_get_va(struct mobj *mobj, size_t offset, size_t len)
{
	struct mobj_ffa *mf = to_mobj_ffa(mobj);

	if (!mf->mm || !mobj_check_offset_and_len(mobj, offset, len))
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

	/*
	 * pop_from_list() can fail to find the mobj if we had just
	 * decreased the refcount to 0 in mobj_put() and was going to
	 * acquire the shm_lock but another thread found this mobj and
	 * reinitialized the refcount to 1. Then before we got cpu time the
	 * other thread called mobj_put() and deactivated the mobj again.
	 *
	 * However, we still have the inactive count that guarantees
	 * that the mobj can't be freed until it reaches 0.
	 * At this point the mobj is in the inactive list.
	 */
	if (pop_from_list(&shm_head, cmp_ptr, (vaddr_t)mf)) {
		unmap_helper(mf);
		SLIST_INSERT_HEAD(&shm_inactive_head, mf, link);
	}
out:
	if (!mf->inactive_refs)
		panic();
	mf->inactive_refs--;
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);
}

static TEE_Result ffa_get_mem_type(struct mobj *mobj __unused, uint32_t *mt)
{
	if (!mt)
		return TEE_ERROR_GENERIC;

	*mt = TEE_MATTR_MEM_TYPE_CACHED;

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
	struct mobj_ffa *mf = to_mobj_ffa(mobj);
	uint32_t exceptions = 0;
	size_t sz = 0;

	while (true) {
		if (refcount_inc(&mf->mapcount))
			return TEE_SUCCESS;

		exceptions = cpu_spin_lock_xsave(&shm_lock);

		if (!refcount_val(&mf->mapcount))
			break; /* continue to reinitialize */
		/*
		 * If another thread beat us to initialize mapcount,
		 * restart to make sure we still increase it.
		 */
		cpu_spin_unlock_xrestore(&shm_lock, exceptions);
	}

	/*
	 * If we have beated another thread calling ffa_dec_map()
	 * to get the lock we need only to reinitialize mapcount to 1.
	 */
	if (!mf->mm) {
		sz = ROUNDUP(mobj->size + mf->page_offset, SMALL_PAGE_SIZE);
		mf->mm = tee_mm_alloc(&tee_mm_shm, sz);
		if (!mf->mm) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		res = core_mmu_map_pages(tee_mm_get_smem(mf->mm), mf->pages,
					 sz / SMALL_PAGE_SIZE,
					 MEM_AREA_NSEC_SHM);
		if (res) {
			tee_mm_free(mf->mm);
			mf->mm = NULL;
			goto out;
		}
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
	if (!refcount_val(&mf->mapcount))
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

	if (!tee_mm_init(&tee_mm_shm, pool_start, pool_end - pool_start,
			 SMALL_PAGE_SHIFT,
			 TEE_MM_POOL_NO_FLAGS))
		panic("Could not create shmem pool");

	DMSG("Shared memory address range: %#"PRIxVA", %#"PRIxVA,
	     pool_start, pool_end);
	return TEE_SUCCESS;
}

static const struct mobj_ops mobj_ffa_ops = {
	.get_pa = ffa_get_pa,
	.get_phys_offs = ffa_get_phys_offs,
	.get_va = ffa_get_va,
	.get_mem_type = ffa_get_mem_type,
	.matches = ffa_matches,
	.free = ffa_inactivate,
	.get_cookie = ffa_get_cookie,
	.inc_map = ffa_inc_map,
	.dec_map = ffa_dec_map,
};

preinit(mapped_shm_init);
