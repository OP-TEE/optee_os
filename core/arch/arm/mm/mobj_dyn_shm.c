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
#include <kernel/tee_misc.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <optee_msg.h>
#include <sm/optee_smc.h>
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
	struct refcount refcount;
	struct refcount mapcount;
	int num_pages;
	bool guarded;
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

	full_offset = offst + mobj_reg_shm->page_offset;
	if (full_offset >= mobj->size)
		return TEE_ERROR_GENERIC;

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
KEEP_PAGER(mobj_reg_shm_get_pa);

static size_t mobj_reg_shm_get_phys_offs(struct mobj *mobj,
					 size_t granule __maybe_unused)
{
	assert(granule >= mobj->phys_granule);
	return to_mobj_reg_shm(mobj)->page_offset;
}

static void *mobj_reg_shm_get_va(struct mobj *mobj, size_t offst)
{
	struct mobj_reg_shm *mrs = to_mobj_reg_shm(mobj);

	if (!mrs->mm)
		return NULL;

	return (void *)(vaddr_t)(tee_mm_get_smem(mrs->mm) + offst +
				 mrs->page_offset);
}

static void reg_shm_unmap_helper(struct mobj_reg_shm *r)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&reg_shm_map_lock);

	if (r->mm) {
		core_mmu_unmap_pages(tee_mm_get_smem(r->mm),
				     r->mobj.size / SMALL_PAGE_SIZE);
		tee_mm_free(r->mm);
		r->mm = NULL;
	}

	cpu_spin_unlock_xrestore(&reg_shm_map_lock, exceptions);
}

static void reg_shm_free_helper(struct mobj_reg_shm *mobj_reg_shm)
{
	reg_shm_unmap_helper(mobj_reg_shm);
	SLIST_REMOVE(&reg_shm_list, mobj_reg_shm, mobj_reg_shm, next);
	free(mobj_reg_shm);
}

static void mobj_reg_shm_free(struct mobj *mobj)
{
	mobj_reg_shm_put(mobj);
}

static TEE_Result mobj_reg_shm_get_cattr(struct mobj *mobj __unused,
					 uint32_t *cattr)
{
	if (!cattr)
		return TEE_ERROR_GENERIC;

	*cattr = TEE_MATTR_CACHE_CACHED;

	return TEE_SUCCESS;
}

static bool mobj_reg_shm_matches(struct mobj *mobj, enum buf_is_attr attr);

static uint64_t mobj_reg_shm_get_cookie(struct mobj *mobj)
{
	return to_mobj_reg_shm(mobj)->cookie;
}

static const struct mobj_ops mobj_reg_shm_ops __rodata_unpaged = {
	.get_pa = mobj_reg_shm_get_pa,
	.get_phys_offs = mobj_reg_shm_get_phys_offs,
	.get_va = mobj_reg_shm_get_va,
	.get_cattr = mobj_reg_shm_get_cattr,
	.matches = mobj_reg_shm_matches,
	.free = mobj_reg_shm_free,
	.get_cookie = mobj_reg_shm_get_cookie,
};

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

static struct mobj_reg_shm *to_mobj_reg_shm_may_fail(struct mobj *mobj)
{
	if (mobj && mobj->ops != &mobj_reg_shm_ops)
		return NULL;

	return container_of(mobj, struct mobj_reg_shm, mobj);
}

struct mobj *mobj_reg_shm_alloc(paddr_t *pages, size_t num_pages,
				paddr_t page_offset, uint64_t cookie)
{
	struct mobj_reg_shm *mobj_reg_shm = NULL;
	size_t i = 0;
	uint32_t exceptions = 0;
	size_t s = 0;

	if (!num_pages)
		return NULL;

	s = mobj_reg_shm_size(num_pages);
	if (!s)
		return NULL;
	mobj_reg_shm = calloc(1, s);
	if (!mobj_reg_shm)
		return NULL;

	mobj_reg_shm->mobj.ops = &mobj_reg_shm_ops;
	mobj_reg_shm->mobj.size = num_pages * SMALL_PAGE_SIZE;
	mobj_reg_shm->mobj.phys_granule = SMALL_PAGE_SIZE;
	mobj_reg_shm->cookie = cookie;
	mobj_reg_shm->guarded = true;
	mobj_reg_shm->num_pages = num_pages;
	mobj_reg_shm->page_offset = page_offset;
	memcpy(mobj_reg_shm->pages, pages, sizeof(*pages) * num_pages);
	refcount_set(&mobj_reg_shm->refcount, 1);

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

	if (r) {
		/*
		 * Counter is supposed to be larger than 0, if it isn't
		 * we're in trouble.
		 */
		if (!refcount_inc(&r->refcount))
			panic();
	}

	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);

	if (r)
		return &r->mobj;

	return NULL;
}

void mobj_reg_shm_put(struct mobj *mobj)
{
	struct mobj_reg_shm *r = to_mobj_reg_shm(mobj);
	uint32_t exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);

	/*
	 * A put is supposed to match a get or the initial alloc, once
	 * we're at zero there's no more user and the original allocator is
	 * done too.
	 */
	if (refcount_dec(&r->refcount))
		reg_shm_free_helper(r);

	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);

	/*
	 * Note that we're reading this mutex protected variable without the
	 * mutex acquired. This isn't a problem since an eventually missed
	 * waiter who is waiting for this MOBJ will try again before hanging
	 * in condvar_wait().
	 */
	if (shm_release_waiters) {
		mutex_lock(&shm_mu);
		condvar_broadcast(&shm_cv);
		mutex_unlock(&shm_mu);
	}
}

static TEE_Result try_release_reg_shm(uint64_t cookie)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
	struct mobj_reg_shm *r = reg_shm_find_unlocked(cookie);

	if (!r || r->guarded)
		goto out;

	res = TEE_ERROR_BUSY;
	if (refcount_val(&r->refcount) == 1) {
		reg_shm_free_helper(r);
		res = TEE_SUCCESS;
	}
out:
	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);

	return res;
}

TEE_Result mobj_reg_shm_release_by_cookie(uint64_t cookie)
{
	TEE_Result res = try_release_reg_shm(cookie);

	if (res != TEE_ERROR_BUSY)
		return res;

	mutex_lock(&shm_mu);
	shm_release_waiters++;
	assert(shm_release_waiters);

	while (true) {
		res = try_release_reg_shm(cookie);
		if (res != TEE_ERROR_BUSY)
			break;
		condvar_wait(&shm_cv, &shm_mu);
	}

	assert(shm_release_waiters);
	shm_release_waiters--;
	mutex_unlock(&shm_mu);

	return res;
}

TEE_Result mobj_reg_shm_inc_map(struct mobj *mobj)
{
	TEE_Result res = TEE_SUCCESS;
	struct mobj_reg_shm *r = to_mobj_reg_shm_may_fail(mobj);

	if (!r)
		return TEE_ERROR_GENERIC;

	if (refcount_inc(&r->mapcount))
		return TEE_SUCCESS;

	uint32_t exceptions = cpu_spin_lock_xsave(&reg_shm_map_lock);

	if (refcount_val(&r->mapcount))
		goto out;

	r->mm = tee_mm_alloc(&tee_mm_shm, SMALL_PAGE_SIZE * r->num_pages);
	if (!r->mm) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = core_mmu_map_pages(tee_mm_get_smem(r->mm), r->pages,
				 r->num_pages, MEM_AREA_NSEC_SHM);
	if (res) {
		tee_mm_free(r->mm);
		r->mm = NULL;
		goto out;
	}

	refcount_set(&r->mapcount, 1);
out:
	cpu_spin_unlock_xrestore(&reg_shm_map_lock, exceptions);

	return res;
}

TEE_Result mobj_reg_shm_dec_map(struct mobj *mobj)
{
	struct mobj_reg_shm *r = to_mobj_reg_shm_may_fail(mobj);

	if (!r)
		return TEE_ERROR_GENERIC;

	if (!refcount_dec(&r->mapcount))
		return TEE_SUCCESS;

	uint32_t exceptions = cpu_spin_lock_xsave(&reg_shm_map_lock);

	if (refcount_val(&r->mapcount)) {
		core_mmu_unmap_pages(tee_mm_get_smem(r->mm),
				     r->mobj.size / SMALL_PAGE_SIZE);
		tee_mm_free(r->mm);
		r->mm = NULL;
	}

	cpu_spin_unlock_xrestore(&reg_shm_map_lock, exceptions);

	return TEE_SUCCESS;
}


struct mobj *mobj_mapped_shm_alloc(paddr_t *pages, size_t num_pages,
				  paddr_t page_offset, uint64_t cookie)
{
	struct mobj *mobj = mobj_reg_shm_alloc(pages, num_pages,
					       page_offset, cookie);

	if (!mobj)
		return NULL;

	if (mobj_reg_shm_inc_map(mobj)) {
		mobj_free(mobj);
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

	if (!tee_mm_init(&tee_mm_shm, pool_start, pool_end, SMALL_PAGE_SHIFT,
		    TEE_MM_POOL_NO_FLAGS))
		panic("Could not create shmem pool");

	DMSG("Shared memory address range: %" PRIxVA ", %" PRIxVA,
	     pool_start, pool_end);
	return TEE_SUCCESS;
}

service_init(mobj_mapped_shm_init);
