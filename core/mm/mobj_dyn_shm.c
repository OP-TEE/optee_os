// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#include <assert.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/linker.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/tee_pager.h>
#include <optee_msg.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

static struct mutex shm_mu = MUTEX_INITIALIZER;
static struct condvar shm_cv = CONDVAR_INITIALIZER;
static size_t shm_release_waiters;

/*
 * mobj_reg_shm implementation. Describes shared memory provided by normal world
 */

struct mobj_reg_shm {
	struct mobj mobj;
	SLIST_ENTRY(mobj_reg_shm) next;
	uint64_t cookie;
	tee_mm_entry_t *mm;
	paddr_t page_offset;
	struct refcount mapcount;
	bool guarded;
	bool releasing;
	bool release_frees;
	paddr_t pages[];
};

static size_t mobj_reg_shm_size(size_t nr_pages)
{
	size_t s = 0;

	if (MUL_OVERFLOW(sizeof(paddr_t), nr_pages, &s))
		return 0;
	if (ADD_OVERFLOW(sizeof(struct mobj_reg_shm), s, &s))
		return 0;
	return s;
}

static SLIST_HEAD(reg_shm_head, mobj_reg_shm) reg_shm_list =
	SLIST_HEAD_INITIALIZER(reg_shm_head);

static unsigned int reg_shm_slist_lock = SPINLOCK_UNLOCK;
static unsigned int reg_shm_map_lock = SPINLOCK_UNLOCK;

static struct mobj_reg_shm *to_mobj_reg_shm(struct mobj *mobj);

static TEE_Result mobj_reg_shm_get_pa(struct mobj *mobj, size_t offst,
				      size_t granule, paddr_t *pa)
{
	struct mobj_reg_shm *mobj_reg_shm = to_mobj_reg_shm(mobj);
	size_t full_offset = 0;
	paddr_t p = 0;

	if (!pa)
		return TEE_ERROR_GENERIC;

	if (offst >= mobj->size)
		return TEE_ERROR_GENERIC;

	full_offset = offst + mobj_reg_shm->page_offset;
	switch (granule) {
	case 0:
		p = mobj_reg_shm->pages[full_offset / SMALL_PAGE_SIZE] +
			(full_offset & SMALL_PAGE_MASK);
		break;
	case SMALL_PAGE_SIZE:
		p = mobj_reg_shm->pages[full_offset / SMALL_PAGE_SIZE];
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	*pa = p;

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(mobj_reg_shm_get_pa);

static size_t mobj_reg_shm_get_phys_offs(struct mobj *mobj,
					 size_t granule __maybe_unused)
{
	assert(granule >= mobj->phys_granule);
	return to_mobj_reg_shm(mobj)->page_offset;
}

static void *mobj_reg_shm_get_va(struct mobj *mobj, size_t offst, size_t len)
{
	struct mobj_reg_shm *mrs = to_mobj_reg_shm(mobj);

	if (!mrs->mm || !mobj_check_offset_and_len(mobj, offst, len))
		return NULL;

	return (void *)(vaddr_t)(tee_mm_get_smem(mrs->mm) + offst +
				 mrs->page_offset);
}

static void reg_shm_unmap_helper(struct mobj_reg_shm *r)
{
	assert(r->mm);
	assert(r->mm->pool->shift == SMALL_PAGE_SHIFT);
	core_mmu_unmap_pages(tee_mm_get_smem(r->mm), r->mm->size);
	tee_mm_free(r->mm);
	r->mm = NULL;
}

static void reg_shm_free_helper(struct mobj_reg_shm *mobj_reg_shm)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&reg_shm_map_lock);

	if (mobj_reg_shm->mm)
		reg_shm_unmap_helper(mobj_reg_shm);

	cpu_spin_unlock_xrestore(&reg_shm_map_lock, exceptions);

	SLIST_REMOVE(&reg_shm_list, mobj_reg_shm, mobj_reg_shm, next);
	free(mobj_reg_shm);
}

static void mobj_reg_shm_free(struct mobj *mobj)
{
	struct mobj_reg_shm *r = to_mobj_reg_shm(mobj);
	uint32_t exceptions = 0;

	if (r->guarded && !r->releasing) {
		/*
		 * Guarded registersted shared memory can't be released
		 * by cookie, only by mobj_put(). However, unguarded
		 * registered shared memory can also be freed by mobj_put()
		 * unless mobj_reg_shm_release_by_cookie() is waiting for
		 * the mobj to be released.
		 */
		exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
		reg_shm_free_helper(r);
		cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);
	} else {
		/*
		 * We've reached the point where an unguarded reg shm can
		 * be released by cookie. Notify eventual waiters.
		 */
		exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
		r->release_frees = true;
		cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);

		mutex_lock(&shm_mu);
		if (shm_release_waiters)
			condvar_broadcast(&shm_cv);
		mutex_unlock(&shm_mu);
	}
}

static TEE_Result mobj_reg_shm_get_mem_type(struct mobj *mobj __unused,
					    uint32_t *mt)
{
	if (!mt)
		return TEE_ERROR_GENERIC;

	*mt = TEE_MATTR_MEM_TYPE_CACHED;

	return TEE_SUCCESS;
}

static TEE_Result mobj_reg_shm_inc_map(struct mobj *mobj)
{
	TEE_Result res = TEE_SUCCESS;
	struct mobj_reg_shm *r = to_mobj_reg_shm(mobj);
	uint32_t exceptions = 0;
	size_t sz = 0;

	while (true) {
		if (refcount_inc(&r->mapcount))
			return TEE_SUCCESS;

		exceptions = cpu_spin_lock_xsave(&reg_shm_map_lock);

		if (!refcount_val(&r->mapcount))
			break; /* continue to reinitialize */
		/*
		 * If another thread beat us to initialize mapcount,
		 * restart to make sure we still increase it.
		 */
		cpu_spin_unlock_xrestore(&reg_shm_map_lock, exceptions);
	}

	/*
	 * If we have beaten another thread calling mobj_reg_shm_dec_map()
	 * to get the lock we need only to reinitialize mapcount to 1.
	 */
	if (!r->mm) {
		sz = ROUNDUP(mobj->size + r->page_offset, SMALL_PAGE_SIZE);
		r->mm = tee_mm_alloc(&tee_mm_shm, sz);
		if (!r->mm) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		res = core_mmu_map_pages(tee_mm_get_smem(r->mm), r->pages,
					 sz / SMALL_PAGE_SIZE,
					 MEM_AREA_NSEC_SHM);
		if (res) {
			tee_mm_free(r->mm);
			r->mm = NULL;
			goto out;
		}
	}

	refcount_set(&r->mapcount, 1);
out:
	cpu_spin_unlock_xrestore(&reg_shm_map_lock, exceptions);

	return res;
}

static TEE_Result mobj_reg_shm_dec_map(struct mobj *mobj)
{
	struct mobj_reg_shm *r = to_mobj_reg_shm(mobj);
	uint32_t exceptions = 0;

	if (!refcount_dec(&r->mapcount))
		return TEE_SUCCESS;

	exceptions = cpu_spin_lock_xsave(&reg_shm_map_lock);

	/*
	 * Check that another thread hasn't been able to:
	 * - increase the mapcount
	 * - or, increase the mapcount, decrease it again, and set r->mm to
	 *   NULL
	 * before we acquired the spinlock
	 */
	if (!refcount_val(&r->mapcount) && r->mm)
		reg_shm_unmap_helper(r);

	cpu_spin_unlock_xrestore(&reg_shm_map_lock, exceptions);

	return TEE_SUCCESS;
}

static bool mobj_reg_shm_matches(struct mobj *mobj, enum buf_is_attr attr);

static uint64_t mobj_reg_shm_get_cookie(struct mobj *mobj)
{
	return to_mobj_reg_shm(mobj)->cookie;
}

/*
 * When CFG_PREALLOC_RPC_CACHE is disabled, this variable is weak just
 * to ease breaking its dependency chain when added to the unpaged area.
 * When CFG_PREALLOC_RPC_CACHE is enabled, releasing RPC preallocated
 * shm mandates these resources to be unpaged.
 */
const struct mobj_ops mobj_reg_shm_ops
__weak __relrodata_unpaged("mobj_reg_shm_ops") = {
	.get_pa = mobj_reg_shm_get_pa,
	.get_phys_offs = mobj_reg_shm_get_phys_offs,
	.get_va = mobj_reg_shm_get_va,
	.get_mem_type = mobj_reg_shm_get_mem_type,
	.matches = mobj_reg_shm_matches,
	.free = mobj_reg_shm_free,
	.get_cookie = mobj_reg_shm_get_cookie,
	.inc_map = mobj_reg_shm_inc_map,
	.dec_map = mobj_reg_shm_dec_map,
};

#ifdef CFG_PREALLOC_RPC_CACHE
/* Releasing RPC preallocated shm mandates few resources to be unpaged */
DECLARE_KEEP_PAGER(mobj_reg_shm_get_cookie);
DECLARE_KEEP_PAGER(mobj_reg_shm_matches);
DECLARE_KEEP_PAGER(mobj_reg_shm_free);
#endif

static bool mobj_reg_shm_matches(struct mobj *mobj __maybe_unused,
				   enum buf_is_attr attr)
{
	assert(mobj->ops == &mobj_reg_shm_ops);

	return attr == CORE_MEM_NON_SEC || attr == CORE_MEM_REG_SHM;
}

static struct mobj_reg_shm *to_mobj_reg_shm(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_reg_shm_ops);
	return container_of(mobj, struct mobj_reg_shm, mobj);
}

struct mobj *mobj_reg_shm_alloc(paddr_t *pages, size_t num_pages,
				paddr_t page_offset, uint64_t cookie)
{
	struct mobj_reg_shm *mobj_reg_shm = NULL;
	size_t i = 0;
	uint32_t exceptions = 0;
	size_t s = 0;

	if (!num_pages || page_offset >= SMALL_PAGE_SIZE)
		return NULL;

	s = mobj_reg_shm_size(num_pages);
	if (!s)
		return NULL;
	mobj_reg_shm = calloc(1, s);
	if (!mobj_reg_shm)
		return NULL;

	mobj_reg_shm->mobj.ops = &mobj_reg_shm_ops;
	mobj_reg_shm->mobj.size = num_pages * SMALL_PAGE_SIZE - page_offset;
	mobj_reg_shm->mobj.phys_granule = SMALL_PAGE_SIZE;
	refcount_set(&mobj_reg_shm->mobj.refc, 1);
	mobj_reg_shm->cookie = cookie;
	mobj_reg_shm->guarded = true;
	mobj_reg_shm->page_offset = page_offset;
	memcpy(mobj_reg_shm->pages, pages, sizeof(*pages) * num_pages);

	/* Ensure loaded references match format and security constraints */
	for (i = 0; i < num_pages; i++) {
		if (mobj_reg_shm->pages[i] & SMALL_PAGE_MASK)
			goto err;

		/* Only Non-secure memory can be mapped there */
		if (!core_pbuf_is(CORE_MEM_NON_SEC, mobj_reg_shm->pages[i],
				  SMALL_PAGE_SIZE))
			goto err;
	}

	exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
	SLIST_INSERT_HEAD(&reg_shm_list, mobj_reg_shm, next);
	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);

	return &mobj_reg_shm->mobj;
err:
	free(mobj_reg_shm);
	return NULL;
}

void mobj_reg_shm_unguard(struct mobj *mobj)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);

	to_mobj_reg_shm(mobj)->guarded = false;
	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);
}

static struct mobj_reg_shm *reg_shm_find_unlocked(uint64_t cookie)
{
	struct mobj_reg_shm *mobj_reg_shm = NULL;

	SLIST_FOREACH(mobj_reg_shm, &reg_shm_list, next)
		if (mobj_reg_shm->cookie == cookie)
			return mobj_reg_shm;

	return NULL;
}

struct mobj *mobj_reg_shm_get_by_cookie(uint64_t cookie)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
	struct mobj_reg_shm *r = reg_shm_find_unlocked(cookie);

	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);
	if (!r)
		return NULL;

	return mobj_get(&r->mobj);
}

TEE_Result mobj_reg_shm_release_by_cookie(uint64_t cookie)
{
	uint32_t exceptions = 0;
	struct mobj_reg_shm *r = NULL;

	/*
	 * Try to find r and see can be released by this function, if so
	 * call mobj_put(). Otherwise this function is called either by
	 * wrong cookie and perhaps a second time, regardless return
	 * TEE_ERROR_BAD_PARAMETERS.
	 */
	exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
	r = reg_shm_find_unlocked(cookie);
	if (!r || r->guarded || r->releasing)
		r = NULL;
	else
		r->releasing = true;

	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);

	if (!r)
		return TEE_ERROR_BAD_PARAMETERS;

	mobj_put(&r->mobj);

	/*
	 * We've established that this function can release the cookie.
	 * Now we wait until mobj_reg_shm_free() is called by the last
	 * mobj_put() needed to free this mobj. Note that the call to
	 * mobj_put() above could very well be that call.
	 *
	 * Once mobj_reg_shm_free() is called it will set r->release_frees
	 * to true and we can free the mobj here.
	 */
	mutex_lock(&shm_mu);
	shm_release_waiters++;
	assert(shm_release_waiters);

	while (true) {
		exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
		if (r->release_frees) {
			reg_shm_free_helper(r);
			r = NULL;
		}
		cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);

		if (!r)
			break;
		condvar_wait(&shm_cv, &shm_mu);
	}

	assert(shm_release_waiters);
	shm_release_waiters--;
	mutex_unlock(&shm_mu);

	return TEE_SUCCESS;
}

struct mobj *mobj_mapped_shm_alloc(paddr_t *pages, size_t num_pages,
				  paddr_t page_offset, uint64_t cookie)
{
	struct mobj *mobj = mobj_reg_shm_alloc(pages, num_pages,
					       page_offset, cookie);

	if (!mobj)
		return NULL;

	if (mobj_inc_map(mobj)) {
		mobj_put(mobj);
		return NULL;
	}

	return mobj;
}

static TEE_Result mobj_mapped_shm_init(void)
{
	vaddr_t pool_start = 0;
	vaddr_t pool_end = 0;

	core_mmu_get_mem_by_type(MEM_AREA_SHM_VASPACE, &pool_start, &pool_end);
	if (!pool_start || !pool_end)
		panic("Can't find region for shmem pool");

	if (!tee_mm_init(&tee_mm_shm, pool_start, pool_end - pool_start,
			 SMALL_PAGE_SHIFT, TEE_MM_POOL_NO_FLAGS))
		panic("Could not create shmem pool");

	DMSG("Shared memory address range: %" PRIxVA ", %" PRIxVA,
	     pool_start, pool_end);
	return TEE_SUCCESS;
}

preinit(mobj_mapped_shm_init);
