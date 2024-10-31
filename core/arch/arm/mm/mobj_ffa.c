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
#include <kernel/tee_misc.h>
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
	unsigned int inactive_refs;
#ifdef CFG_CORE_SEL1_SPMC
	bool registered_by_cookie;
#endif
};

struct mobj_ffa_shm {
	struct mobj_ffa mf;
	tee_mm_entry_t *mm;
	struct refcount mapcount;
	uint16_t page_offset;
	paddr_t pages[];
};

struct mobj_ffa_prm {
	struct mobj_ffa mf;
	paddr_t pa;
	enum mobj_use_case use_case;
	bool assigned_use_case;
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

static const struct mobj_ops mobj_ffa_shm_ops;
static const struct mobj_ops mobj_ffa_prm_ops;

static bool is_mobj_ffa_shm(struct mobj *mobj)
{
	return mobj->ops == &mobj_ffa_shm_ops;
}

static struct mobj_ffa_shm *to_mobj_ffa_shm(struct mobj *mobj)
{
	assert(is_mobj_ffa_shm(mobj));
	return container_of(mobj, struct mobj_ffa_shm, mf.mobj);
}

static bool is_mobj_ffa_prm(struct mobj *mobj)
{
	return mobj->ops == &mobj_ffa_prm_ops;
}

static struct mobj_ffa_prm *to_mobj_ffa_prm(struct mobj *mobj)
{
	assert(is_mobj_ffa_prm(mobj));
	return container_of(mobj, struct mobj_ffa_prm, mf.mobj);
}

static size_t shm_size(size_t num_pages)
{
	size_t s = 0;

	if (MUL_OVERFLOW(sizeof(paddr_t), num_pages, &s))
		return 0;
	if (ADD_OVERFLOW(sizeof(struct mobj_ffa_shm), s, &s))
		return 0;
	return s;
}

static struct mobj_ffa *ffa_shm_new(unsigned int num_pages)
{
	struct mobj_ffa_shm *m = NULL;
	size_t s = 0;

	if (!num_pages)
		return NULL;

	s = shm_size(num_pages);
	if (!s)
		return NULL;
	m = calloc(1, s);
	if (!m)
		return NULL;

	m->mf.mobj.ops = &mobj_ffa_shm_ops;
	m->mf.mobj.size = num_pages * SMALL_PAGE_SIZE;
	m->mf.mobj.phys_granule = SMALL_PAGE_SIZE;
	refcount_set(&m->mf.mobj.refc, 0);
	m->mf.inactive_refs = 0;

	return &m->mf;
}

static struct mobj_ffa *ffa_prm_new(unsigned int num_pages,
				    enum mobj_use_case use_case)
{
	struct mobj_ffa_prm *m = NULL;
	size_t sz = 0;

	if (!num_pages || MUL_OVERFLOW(num_pages, SMALL_PAGE_SIZE, &sz) ||
	    use_case == MOBJ_USE_CASE_NS_SHM)
		return NULL;

	m = calloc(1, sizeof(*m));
	if (!m)
		return NULL;

	m->mf.mobj.ops = &mobj_ffa_prm_ops;
	m->mf.mobj.size = sz;
	m->mf.mobj.phys_granule = SMALL_PAGE_SIZE;
	refcount_set(&m->mf.mobj.refc, 0);
	m->mf.inactive_refs = 0;
	m->use_case = use_case;

	return &m->mf;
}

#ifdef CFG_CORE_SEL1_SPMC
struct mobj_ffa *mobj_ffa_sel1_spmc_new(uint64_t cookie,
					unsigned int num_pages,
					enum mobj_use_case use_case)
{
	struct mobj_ffa *m = NULL;
	bitstr_t *shm_bits = NULL;
	uint32_t exceptions = 0;
	int i = 0;

	if (cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID) {
		if (!(cookie & FFA_MEMORY_HANDLE_HYPERVISOR_BIT))
			return NULL;
		if (virt_add_cookie_to_current_guest(cookie))
			return NULL;
	}

	switch (use_case) {
	case MOBJ_USE_CASE_NS_SHM:
		m = ffa_shm_new(num_pages);
		break;
	case MOBJ_USE_CASE_SEC_VIDEO_PLAY:
	case MOBJ_USE_CASE_TRUSED_UI:
		m = ffa_prm_new(num_pages, use_case);
		break;
	default:
		break;
	}
	if (!m) {
		if (cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID)
			virt_remove_cookie(cookie);
		return NULL;
	}

	if (cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID) {
		m->cookie = cookie;
		return m;
	}

	shm_bits = get_shm_bits();
	exceptions = cpu_spin_lock_xsave(&shm_lock);
	bit_ffc(shm_bits, SPMC_CORE_SEL1_MAX_SHM_COUNT, &i);
	if (i != -1) {
		bit_set(shm_bits, i);
		m->cookie = i;
		m->cookie |= FFA_MEMORY_HANDLE_NON_SECURE_BIT;
		/*
		 * Encode the partition ID into the handle so we know which
		 * partition to switch to when reclaiming a handle.
		 */
		m->cookie |= SHIFT_U64(virt_get_current_guest_id(),
				       FFA_MEMORY_HANDLE_PRTN_SHIFT);
	}
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	if (i == -1) {
		mobj_ffa_sel1_spmc_delete(m);
		return NULL;
	}

	return m;
}
#endif /*CFG_CORE_SEL1_SPMC*/

static size_t get_page_count(struct mobj_ffa *mf)
{
	return ROUNDUP_DIV(mf->mobj.size, SMALL_PAGE_SIZE);
}

static bool cmp_cookie(struct mobj_ffa *mf, uint64_t cookie)
{
	return mf->cookie == cookie;
}

static bool cmp_ptr(struct mobj_ffa *mf, uint64_t ptr)
{
	return mf == (void *)(vaddr_t)ptr;
}

static bool check_shm_overlaps_prm(struct mobj_ffa_shm *shm,
				   struct mobj_ffa_prm *prm)
{
	size_t n = 0;

	for (n = 0; n < shm->mf.mobj.size / SMALL_PAGE_SIZE; n++)
		if (core_is_buffer_intersect(prm->pa, prm->mf.mobj.size,
					     shm->pages[n], SMALL_PAGE_SIZE))
			return true;

	return false;
}

static bool cmp_pa_overlap(struct mobj_ffa *mf, uint64_t ptr)
{
	struct mobj_ffa *mf2 = (void *)(vaddr_t)ptr;
	bool mf_is_shm = is_mobj_ffa_shm(&mf->mobj);
	bool mf2_is_shm = is_mobj_ffa_shm(&mf2->mobj);

	if (mf_is_shm && mf2_is_shm) {
		/*
		 * Not a security issue and might be too expensive to check
		 * if we have many pages in each registered shared memory
		 * object.
		 */
		return false;
	}

	if (mf_is_shm)
		return check_shm_overlaps_prm(to_mobj_ffa_shm(&mf->mobj),
					      to_mobj_ffa_prm(&mf2->mobj));
	if (mf2_is_shm)
		return check_shm_overlaps_prm(to_mobj_ffa_shm(&mf2->mobj),
					      to_mobj_ffa_prm(&mf->mobj));

	return core_is_buffer_intersect(to_mobj_ffa_prm(&mf->mobj)->pa,
					mf->mobj.size,
					to_mobj_ffa_prm(&mf2->mobj)->pa,
					mf2->mobj.size);
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

	if (is_mobj_ffa_shm(&mf->mobj)) {
		struct mobj_ffa_shm *m = to_mobj_ffa_shm(&mf->mobj);

		assert(!m->mm);
		free(m);
	} else {
		free(to_mobj_ffa_prm(&mf->mobj));
	}
}
#else /* !defined(CFG_CORE_SEL1_SPMC) */
struct mobj_ffa *mobj_ffa_spmc_new(uint64_t cookie, unsigned int num_pages,
				   enum mobj_use_case use_case)
{
	struct mobj_ffa *mf = NULL;

	assert(cookie != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID);
	if (use_case == MOBJ_USE_CASE_NS_SHM)
		mf = ffa_shm_new(num_pages);
	else
		mf = ffa_prm_new(num_pages, use_case);
	if (mf)
		mf->cookie = cookie;
	return mf;
}

void mobj_ffa_spmc_delete(struct mobj_ffa *mf)
{
	if (is_mobj_ffa_shm(&mf->mobj))
		free(to_mobj_ffa_shm(&mf->mobj));
	else
		free(to_mobj_ffa_prm(&mf->mobj));
}
#endif /* !defined(CFG_CORE_SEL1_SPMC) */

TEE_Result mobj_ffa_add_pages_at(struct mobj_ffa *mf, unsigned int *idx,
				 paddr_t pa, unsigned int num_pages)
{
	size_t tot_page_count = tot_page_count = get_page_count(mf);
	unsigned int n = 0;

	if (ADD_OVERFLOW(*idx, num_pages, &n) || n > tot_page_count)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ENABLED(CFG_CORE_SEL2_SPMC) &&
	    !core_pbuf_is(CORE_MEM_NON_SEC, pa, num_pages * SMALL_PAGE_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_mobj_ffa_shm(&mf->mobj)) {
		struct mobj_ffa_shm *mfs = to_mobj_ffa_shm(&mf->mobj);

		for (n = 0; n < num_pages; n++)
			mfs->pages[n + *idx] = pa + n * SMALL_PAGE_SIZE;
	} else {
		struct mobj_ffa_prm *mfr = to_mobj_ffa_prm(&mf->mobj);

		if (!*idx)
			mfr->pa = pa;
		else if (mfr->pa != pa + *idx * SMALL_PAGE_SIZE)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	(*idx) += n;

	return TEE_SUCCESS;
}

uint64_t mobj_ffa_get_cookie(struct mobj_ffa *mf)
{
	return mf->cookie;
}

static TEE_Result protect_mem(struct mobj_ffa_prm *m)
{
	DMSG("use_case %d pa %#"PRIxPA", size %#zx cookie %#"PRIx64,
	     m->use_case, m->pa, m->mf.mobj.size, m->mf.cookie);

	return plat_set_protmem_range(m->use_case, m->pa, m->mf.mobj.size);
}

static TEE_Result __maybe_unused restore_mem(struct mobj_ffa_prm *m)
{
	DMSG("use_case %d pa %#" PRIxPA ", size %#zx cookie %#"PRIx64,
	     m->use_case, m->pa, m->mf.mobj.size, m->mf.cookie);

	return plat_set_protmem_range(MOBJ_USE_CASE_NS_SHM, m->pa,
				      m->mf.mobj.size);
}

TEE_Result mobj_ffa_push_to_inactive(struct mobj_ffa *mf)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	assert(!find_in_list(&shm_inactive_head, cmp_ptr, (vaddr_t)mf));
	assert(!find_in_list(&shm_inactive_head, cmp_cookie, mf->cookie));
	assert(!find_in_list(&shm_head, cmp_cookie, mf->cookie));

	if (find_in_list(&shm_inactive_head, cmp_pa_overlap, (vaddr_t)mf) ||
	    find_in_list(&shm_head, cmp_pa_overlap, (vaddr_t)mf)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	if (is_mobj_ffa_prm(&mf->mobj)) {
		res = protect_mem(to_mobj_ffa_prm(&mf->mobj));
		if (res)
			goto out;
	}

	SLIST_INSERT_HEAD(&shm_inactive_head, mf, link);

out:
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	return res;
}

static void unmap_helper(struct mobj_ffa_shm *m)
{
	if (m->mm) {
		core_mmu_unmap_pages(tee_mm_get_smem(m->mm),
				     get_page_count(&m->mf));
		tee_mm_free(m->mm);
		m->mm = NULL;
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
	if (is_mobj_ffa_prm(&mf->mobj))
		res = restore_mem(to_mobj_ffa_prm(&mf->mobj));
	else
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
	struct mobj_ffa_shm *mfs = NULL;
	struct mobj_ffa *mf = NULL;
	uint32_t exceptions = 0;
	uint16_t offs = 0;

	if (internal_offs >= SMALL_PAGE_SIZE)
		return NULL;
	exceptions = cpu_spin_lock_xsave(&shm_lock);
	mf = find_in_list(&shm_head, cmp_cookie, cookie);
	if (mf) {
		if (is_mobj_ffa_shm(&mf->mobj))
			offs = to_mobj_ffa_shm(&mf->mobj)->page_offset;
		else
			offs = 0;
		if (offs == internal_offs) {
			if (!refcount_inc(&mf->mobj.refc)) {
				/*
				 * If refcount is 0 some other thread has
				 * called mobj_put() on this reached 0 and
				 * before ffa_shm_inactivate() got the lock
				 * we found it. Let's reinitialize it.
				 */
				refcount_set(&mf->mobj.refc, 1);
				mf->inactive_refs++;
			}
			DMSG("cookie %#"PRIx64" active: refc %u:%u",
			     cookie, refcount_val(&mf->mobj.refc),
			     mf->inactive_refs);
		} else {
			EMSG("cookie %#"PRIx64" mismatching internal_offs got %#"PRIx16" expected %#x",
			     cookie, offs, internal_offs);
			mf = NULL;
		}
	} else {
		mf = pop_from_list(&shm_inactive_head, cmp_cookie, cookie);
#if !defined(CFG_CORE_SEL1_SPMC)
		/* Try to retrieve it from the SPM at S-EL2 */
		if (mf) {
			DMSG("cookie %#"PRIx64" resurrecting", cookie);
		} else {
			enum mobj_use_case uc = MOBJ_USE_CASE_NS_SHM;

			DMSG("Populating mobj from rx buffer, cookie %#"PRIx64,
			     cookie);
			mf = thread_spmc_populate_mobj_from_rx(cookie, uc);
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
			mf->inactive_refs++;
			if (is_mobj_ffa_shm(&mf->mobj)) {
				mfs = to_mobj_ffa_shm(&mf->mobj);
				refcount_set(&mfs->mapcount, 0);

				/*
				 * mfs->page_offset is offset into the
				 * first page.  This offset is assigned
				 * from the internal_offs parameter to this
				 * function.
				 *
				 * While a mobj_ffa is active (ref_count >
				 * 0) this will not change, but when being
				 * pushed to the inactive list it can be
				 * changed again.
				 *
				 * So below we're backing out the old
				 * mfs->page_offset and then assigning a
				 * new from internal_offset.
				 */
				mf->mobj.size += mfs->page_offset;
				assert(!(mf->mobj.size & SMALL_PAGE_MASK));
				mf->mobj.size -= internal_offs;
				mfs->page_offset = internal_offs;
			} else if (is_mobj_ffa_prm(&mf->mobj) &&
				   internal_offs) {
				mf = NULL;
			}

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

static TEE_Result ffa_shm_get_pa(struct mobj *mobj, size_t offset,
				 size_t granule, paddr_t *pa)
{
	struct mobj_ffa_shm *m = to_mobj_ffa_shm(mobj);
	size_t full_offset = 0;
	paddr_t p = 0;

	if (!pa)
		return TEE_ERROR_GENERIC;

	if (offset >= mobj->size)
		return TEE_ERROR_GENERIC;

	full_offset = offset + m->page_offset;
	switch (granule) {
	case 0:
		p = m->pages[full_offset / SMALL_PAGE_SIZE] +
		    (full_offset & SMALL_PAGE_MASK);
		break;
	case SMALL_PAGE_SIZE:
		p = m->pages[full_offset / SMALL_PAGE_SIZE];
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	*pa = p;

	return TEE_SUCCESS;
}

static size_t ffa_shm_get_phys_offs(struct mobj *mobj,
				    size_t granule __maybe_unused)
{
	assert(granule >= mobj->phys_granule);

	return to_mobj_ffa_shm(mobj)->page_offset;
}

static void *ffa_shm_get_va(struct mobj *mobj, size_t offset, size_t len)
{
	struct mobj_ffa_shm *m = to_mobj_ffa_shm(mobj);

	if (!m->mm || !mobj_check_offset_and_len(mobj, offset, len))
		return NULL;

	return (void *)(tee_mm_get_smem(m->mm) + offset + m->page_offset);
}

static void ffa_inactivate(struct mobj_ffa *mf)
{
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	/*
	 * If refcount isn't 0 some other thread has found this mobj in
	 * shm_head after the mobj_put() that put us here and before we got
	 * the lock.
	 */
	if (refcount_val(&mf->mobj.refc)) {
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
		if (is_mobj_ffa_shm(&mf->mobj))
			unmap_helper(to_mobj_ffa_shm(&mf->mobj));
		SLIST_INSERT_HEAD(&shm_inactive_head, mf, link);
	}
out:
	if (!mf->inactive_refs)
		panic();
	mf->inactive_refs--;
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);
}

static void ffa_shm_inactivate(struct mobj *mobj)
{
	ffa_inactivate(&to_mobj_ffa_shm(mobj)->mf);
}

static TEE_Result ffa_shm_get_mem_type(struct mobj *mobj __unused, uint32_t *mt)
{
	if (!mt)
		return TEE_ERROR_GENERIC;

	*mt = TEE_MATTR_MEM_TYPE_CACHED;

	return TEE_SUCCESS;
}

static bool ffa_shm_matches(struct mobj *mobj __maybe_unused,
			    enum buf_is_attr attr)
{
	assert(is_mobj_ffa_shm(mobj));

	return attr == CORE_MEM_NON_SEC || attr == CORE_MEM_REG_SHM;
}

static uint64_t ffa_shm_get_cookie(struct mobj *mobj)
{
	return to_mobj_ffa_shm(mobj)->mf.cookie;
}

static TEE_Result ffa_shm_inc_map(struct mobj *mobj)
{
	struct mobj_ffa_shm *m = to_mobj_ffa_shm(mobj);
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;
	size_t sz = 0;

	while (true) {
		if (refcount_inc(&m->mapcount))
			return TEE_SUCCESS;

		exceptions = cpu_spin_lock_xsave(&shm_lock);

		if (!refcount_val(&m->mapcount))
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
	if (!m->mm) {
		sz = ROUNDUP(mobj->size + m->page_offset, SMALL_PAGE_SIZE);
		m->mm = tee_mm_alloc(&core_virt_shm_pool, sz);
		if (!m->mm) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		res = core_mmu_map_pages(tee_mm_get_smem(m->mm), m->pages,
					 sz / SMALL_PAGE_SIZE,
					 MEM_AREA_NSEC_SHM);
		if (res) {
			tee_mm_free(m->mm);
			m->mm = NULL;
			goto out;
		}
	}

	refcount_set(&m->mapcount, 1);
out:
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);

	return res;
}

static TEE_Result ffa_shm_dec_map(struct mobj *mobj)
{
	struct mobj_ffa_shm *m = to_mobj_ffa_shm(mobj);
	uint32_t exceptions = 0;

	if (!refcount_dec(&m->mapcount))
		return TEE_SUCCESS;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	if (!refcount_val(&m->mapcount))
		unmap_helper(m);
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

	if (!tee_mm_init(&core_virt_shm_pool, pool_start, pool_end - pool_start,
			 SMALL_PAGE_SHIFT,
			 TEE_MM_POOL_NO_FLAGS))
		panic("Could not create shmem pool");

	DMSG("Shared memory address range: %#"PRIxVA", %#"PRIxVA,
	     pool_start, pool_end);
	return TEE_SUCCESS;
}

static const struct mobj_ops mobj_ffa_shm_ops = {
	.get_pa = ffa_shm_get_pa,
	.get_phys_offs = ffa_shm_get_phys_offs,
	.get_va = ffa_shm_get_va,
	.get_mem_type = ffa_shm_get_mem_type,
	.matches = ffa_shm_matches,
	.free = ffa_shm_inactivate,
	.get_cookie = ffa_shm_get_cookie,
	.inc_map = ffa_shm_inc_map,
	.dec_map = ffa_shm_dec_map,
};

preinit(mapped_shm_init);

#ifdef CFG_CORE_DYN_PROTMEM
static TEE_Result ffa_prm_get_pa(struct mobj *mobj, size_t offset,
				 size_t granule, paddr_t *pa)
{
	struct mobj_ffa_prm *m = to_mobj_ffa_prm(mobj);
	paddr_t p;

	if (!pa || offset >= mobj->size)
		return TEE_ERROR_GENERIC;

	p = m->pa + offset;

	if (granule) {
		if (granule != SMALL_PAGE_SIZE &&
		    granule != CORE_MMU_PGDIR_SIZE)
			return TEE_ERROR_GENERIC;
		p &= ~(granule - 1);
	}

	*pa = p;
	return TEE_SUCCESS;
}

static TEE_Result ffa_prm_get_mem_type(struct mobj *mobj __maybe_unused,
				       uint32_t *mt)
{
	assert(is_mobj_ffa_prm(mobj));

	if (!mt)
		return TEE_ERROR_GENERIC;

	*mt = TEE_MATTR_MEM_TYPE_CACHED;

	return TEE_SUCCESS;
}

static bool ffa_prm_matches(struct mobj *mobj __maybe_unused,
			    enum buf_is_attr attr)
{
	assert(is_mobj_ffa_prm(mobj));

	return attr == CORE_MEM_SEC || attr == CORE_MEM_SDP_MEM;
}

static void ffa_prm_inactivate(struct mobj *mobj)
{
	ffa_inactivate(&to_mobj_ffa_prm(mobj)->mf);
}

static uint64_t ffa_prm_get_cookie(struct mobj *mobj)
{
	return to_mobj_ffa_prm(mobj)->mf.cookie;
}

static TEE_Result ffa_prm_no_map(struct mobj *mobj __maybe_unused)
{
	assert(is_mobj_ffa_prm(mobj));

	return TEE_ERROR_GENERIC;
}

static const struct mobj_ops mobj_ffa_prm_ops = {
	.get_pa = ffa_prm_get_pa,
	.get_mem_type = ffa_prm_get_mem_type,
	.matches = ffa_prm_matches,
	.free = ffa_prm_inactivate,
	.get_cookie = ffa_prm_get_cookie,
	.inc_map = ffa_prm_no_map,
	.dec_map = ffa_prm_no_map,
};

static bool cmp_protmem_pa(struct mobj_ffa *mf, uint64_t pa)
{
	struct mobj_ffa_prm *m = NULL;

	if (!is_mobj_ffa_prm(&mf->mobj))
		return false;

	m = to_mobj_ffa_prm(&mf->mobj);
	return pa >= m->pa && pa < m->pa + m->mf.mobj.size;
}

struct mobj *mobj_ffa_protmem_get_by_pa(paddr_t pa, paddr_size_t size)
{
	struct mobj_ffa_prm *m = NULL;
	struct mobj_ffa *mf = NULL;
	struct mobj *mobj = NULL;
	uint32_t exceptions = 0;

	if (!size)
		size = 1;

	exceptions = cpu_spin_lock_xsave(&shm_lock);

	mf = find_in_list(&shm_head, cmp_protmem_pa, pa);
	if (mf) {
		m = to_mobj_ffa_prm(&mf->mobj);
		if (core_is_buffer_inside(pa, size, m->pa, m->mf.mobj.size))
			mobj = mobj_get(&mf->mobj);
	}

	cpu_spin_unlock_xrestore(&shm_lock, exceptions);
	return mobj;
}

TEE_Result mobj_ffa_assign_protmem(uint64_t cookie, enum mobj_use_case use_case)
{
	TEE_Result res = TEE_SUCCESS;
	struct mobj_ffa_prm *m = NULL;
	struct mobj_ffa *mf = NULL;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&shm_lock);
	mf = find_in_list(&shm_inactive_head, cmp_cookie, cookie);
	if (mf) {
		if (!is_mobj_ffa_prm(&mf->mobj)) {
			res = TEE_ERROR_ITEM_NOT_FOUND;
			goto out;
		}
		m = to_mobj_ffa_prm(&mf->mobj);
		if (m->assigned_use_case) {
			res = TEE_ERROR_BUSY;
			goto out;
		}
		if (m->use_case != use_case) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
		m->assigned_use_case = true;
		goto out;
	}
	mf = find_in_list(&shm_head, cmp_cookie, cookie);
	if (mf) {
		if (!is_mobj_ffa_prm(&mf->mobj))
			res = TEE_ERROR_BUSY;
		else
			res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}
#if !defined(CFG_CORE_SEL1_SPMC)
	/* Try to retrieve it from the SPM at S-EL2 */
	DMSG("Populating mobj from rx buffer, cookie %#"PRIx64" use-case %d",
	     cookie, use_case);
	mf = thread_spmc_populate_mobj_from_rx(cookie, use_case);
	if (mf) {
		SLIST_INSERT_HEAD(&shm_inactive_head, mf, link);
	} else {
		EMSG("Failed to assign use-case %d to cookie %#"PRIx64"",
		     use_case, cookie);
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}
#endif
out:
	cpu_spin_unlock_xrestore(&shm_lock, exceptions);
	return res;
}
#endif /*CFG_CORE_DYN_PROTMEM*/
