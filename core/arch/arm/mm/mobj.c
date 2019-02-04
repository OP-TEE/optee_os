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

struct mobj *mobj_sec_ddr;
struct mobj *mobj_tee_ram;

/*
 * mobj_phys implementation
 */

struct mobj_phys {
	struct mobj mobj;
	enum buf_is_attr battr;
	uint32_t cattr; /* Defined by TEE_MATTR_CACHE_* in tee_mmu_types.h */
	vaddr_t va;
	paddr_t pa;
};

static struct mutex shm_mu = MUTEX_INITIALIZER;
static struct condvar shm_cv = CONDVAR_INITIALIZER;
static size_t shm_release_waiters;

static struct mobj_phys *to_mobj_phys(struct mobj *mobj);

static void *mobj_phys_get_va(struct mobj *mobj, size_t offset)
{
	struct mobj_phys *moph = to_mobj_phys(mobj);

	if (!moph->va)
		return NULL;

	return (void *)(moph->va + offset);
}

static TEE_Result mobj_phys_get_pa(struct mobj *mobj, size_t offs,
				   size_t granule, paddr_t *pa)
{
	struct mobj_phys *moph = to_mobj_phys(mobj);
	paddr_t p;

	if (!pa)
		return TEE_ERROR_GENERIC;

	p = moph->pa + offs;

	if (granule) {
		if (granule != SMALL_PAGE_SIZE &&
		    granule != CORE_MMU_PGDIR_SIZE)
			return TEE_ERROR_GENERIC;
		p &= ~(granule - 1);
	}

	*pa = p;
	return TEE_SUCCESS;
}
KEEP_PAGER(mobj_phys_get_pa);

static TEE_Result mobj_phys_get_cattr(struct mobj *mobj, uint32_t *cattr)
{
	struct mobj_phys *moph = to_mobj_phys(mobj);

	if (!cattr)
		return TEE_ERROR_GENERIC;

	*cattr = moph->cattr;
	return TEE_SUCCESS;
}

static bool mobj_phys_matches(struct mobj *mobj, enum buf_is_attr attr)
{
	struct mobj_phys *moph = to_mobj_phys(mobj);
	enum buf_is_attr a;

	a = moph->battr;

	switch (attr) {
	case CORE_MEM_SEC:
		return a == CORE_MEM_SEC || a == CORE_MEM_TEE_RAM ||
		       a == CORE_MEM_TA_RAM || a == CORE_MEM_SDP_MEM;
	case CORE_MEM_NON_SEC:
		return a == CORE_MEM_NSEC_SHM;
	case CORE_MEM_TEE_RAM:
	case CORE_MEM_TA_RAM:
	case CORE_MEM_NSEC_SHM:
	case CORE_MEM_SDP_MEM:
		return attr == a;
	default:
		return false;
	}
}

static void mobj_phys_free(struct mobj *mobj)
{
	struct mobj_phys *moph = to_mobj_phys(mobj);

	free(moph);
}

static const struct mobj_ops mobj_phys_ops __rodata_unpaged = {
	.get_va = mobj_phys_get_va,
	.get_pa = mobj_phys_get_pa,
	.get_phys_offs = NULL, /* only offset 0 */
	.get_cattr = mobj_phys_get_cattr,
	.matches = mobj_phys_matches,
	.free = mobj_phys_free,
};

static struct mobj_phys *to_mobj_phys(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_phys_ops);
	return container_of(mobj, struct mobj_phys, mobj);
}

struct mobj *mobj_phys_alloc(paddr_t pa, size_t size, uint32_t cattr,
			     enum buf_is_attr battr)
{
	struct mobj_phys *moph;
	enum teecore_memtypes area_type;
	void *va;

	if ((pa & CORE_MMU_USER_PARAM_MASK) ||
	    (size & CORE_MMU_USER_PARAM_MASK)) {
		DMSG("Expect %#x alignment", CORE_MMU_USER_PARAM_SIZE);
		return NULL;
	}

	switch (battr) {
	case CORE_MEM_TEE_RAM:
		area_type = MEM_AREA_TEE_RAM_RW_DATA;
		break;
	case CORE_MEM_TA_RAM:
		area_type = MEM_AREA_TA_RAM;
		break;
	case CORE_MEM_NSEC_SHM:
		area_type = MEM_AREA_NSEC_SHM;
		break;
	case CORE_MEM_SDP_MEM:
		area_type = MEM_AREA_SDP_MEM;
		break;
	default:
		DMSG("can't allocate with specified attribute");
		return NULL;
	}

	/* Only SDP memory may not have a virtual address */
	va = phys_to_virt(pa, area_type);
	if (!va && battr != CORE_MEM_SDP_MEM)
		return NULL;

	moph = calloc(1, sizeof(*moph));
	if (!moph)
		return NULL;

	moph->battr = battr;
	moph->cattr = cattr;
	moph->mobj.size = size;
	moph->mobj.ops = &mobj_phys_ops;
	moph->pa = pa;
	moph->va = (vaddr_t)va;

	return &moph->mobj;
}

/*
 * mobj_virt implementation
 */

static void mobj_virt_assert_type(struct mobj *mobj);

static void *mobj_virt_get_va(struct mobj *mobj, size_t offset)
{
	mobj_virt_assert_type(mobj);

	return (void *)(vaddr_t)offset;
}

static const struct mobj_ops mobj_virt_ops __rodata_unpaged = {
	.get_va = mobj_virt_get_va,
};

static void mobj_virt_assert_type(struct mobj *mobj __maybe_unused)
{
	assert(mobj->ops == &mobj_virt_ops);
}

struct mobj mobj_virt = { .ops = &mobj_virt_ops, .size = SIZE_MAX };

/*
 * mobj_mm implementation
 */

struct mobj_mm {
	tee_mm_entry_t *mm;
	struct mobj *parent_mobj;
	struct mobj mobj;
};

static struct mobj_mm *to_mobj_mm(struct mobj *mobj);

static size_t mobj_mm_offs(struct mobj *mobj, size_t offs)
{
	tee_mm_entry_t *mm = to_mobj_mm(mobj)->mm;

	return (mm->offset << mm->pool->shift) + offs;
}

static void *mobj_mm_get_va(struct mobj *mobj, size_t offs)
{
	return mobj_get_va(to_mobj_mm(mobj)->parent_mobj,
			   mobj_mm_offs(mobj, offs));
}


static TEE_Result mobj_mm_get_pa(struct mobj *mobj, size_t offs,
				    size_t granule, paddr_t *pa)
{
	return mobj_get_pa(to_mobj_mm(mobj)->parent_mobj,
			   mobj_mm_offs(mobj, offs), granule, pa);
}
KEEP_PAGER(mobj_mm_get_pa);

static size_t mobj_mm_get_phys_offs(struct mobj *mobj, size_t granule)
{
	return mobj_get_phys_offs(to_mobj_mm(mobj)->parent_mobj, granule);
}

static TEE_Result mobj_mm_get_cattr(struct mobj *mobj, uint32_t *cattr)
{
	return mobj_get_cattr(to_mobj_mm(mobj)->parent_mobj, cattr);
}

static bool mobj_mm_matches(struct mobj *mobj, enum buf_is_attr attr)
{
	return mobj_matches(to_mobj_mm(mobj)->parent_mobj, attr);
}

static void mobj_mm_free(struct mobj *mobj)
{
	struct mobj_mm *m = to_mobj_mm(mobj);

	tee_mm_free(m->mm);
	free(m);
}

static const struct mobj_ops mobj_mm_ops __rodata_unpaged = {
	.get_va = mobj_mm_get_va,
	.get_pa = mobj_mm_get_pa,
	.get_phys_offs = mobj_mm_get_phys_offs,
	.get_cattr = mobj_mm_get_cattr,
	.matches = mobj_mm_matches,
	.free = mobj_mm_free,
};

static struct mobj_mm *to_mobj_mm(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_mm_ops);
	return container_of(mobj, struct mobj_mm, mobj);
}

struct mobj *mobj_mm_alloc(struct mobj *mobj_parent, size_t size,
			      tee_mm_pool_t *pool)
{
	struct mobj_mm *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;

	m->mm = tee_mm_alloc(pool, size);
	if (!m->mm) {
		free(m);
		return NULL;
	}

	m->parent_mobj = mobj_parent;
	m->mobj.size = size;
	m->mobj.ops = &mobj_mm_ops;

	return &m->mobj;
}

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
	size_t full_offset;
	paddr_t p;

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
	struct mobj_reg_shm *mobj_reg_shm;
	size_t i;
	uint32_t exceptions;
	size_t s;

	if (!num_pages)
		return NULL;

	s = mobj_reg_shm_size(num_pages);
	if (!s)
		return NULL;
	mobj_reg_shm = calloc(1, s);
	if (!mobj_reg_shm)
		return NULL;

	mobj_reg_shm->mobj.ops = &mobj_reg_shm_ops;
	mobj_reg_shm->mobj.size =  num_pages * SMALL_PAGE_SIZE;
	mobj_reg_shm->mobj.phys_granule = SMALL_PAGE_SIZE;
	mobj_reg_shm->cookie = cookie;
	mobj_reg_shm->guarded = true;
	mobj_reg_shm->num_pages = num_pages;
	mobj_reg_shm->page_offset = page_offset;
	memcpy(mobj_reg_shm->pages, pages, sizeof(*pages) * num_pages);
	refcount_set(&mobj_reg_shm->refcount, 1);

	/* Insure loaded references match format and security constraints */
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
	struct mobj_reg_shm *mobj_reg_shm;

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
	vaddr_t pool_start;
	vaddr_t pool_end;

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

/*
 * mobj_shm implementation. mobj_shm represents buffer in predefined shm region
 * - it is physically contiguous.
 * - it is identified in static physical layout as MEM_AREA_NSEC_SHM.
 * - it creates mobjs that match specific CORE_MEM_NSEC_SHM and non secure
 *   generic CORE_MEM_NON_SEC.
 */

struct mobj_shm {
	struct mobj mobj;
	paddr_t pa;
	uint64_t cookie;
};

static struct mobj_shm *to_mobj_shm(struct mobj *mobj);

static void *mobj_shm_get_va(struct mobj *mobj, size_t offset)
{
	struct mobj_shm *m = to_mobj_shm(mobj);

	if (offset >= mobj->size)
		return NULL;

	return phys_to_virt(m->pa + offset, MEM_AREA_NSEC_SHM);
}

static TEE_Result mobj_shm_get_pa(struct mobj *mobj, size_t offs,
				   size_t granule, paddr_t *pa)
{
	struct mobj_shm *m = to_mobj_shm(mobj);
	paddr_t p;

	if (!pa || offs >= mobj->size)
		return TEE_ERROR_GENERIC;

	p = m->pa + offs;

	if (granule) {
		if (granule != SMALL_PAGE_SIZE &&
		    granule != CORE_MMU_PGDIR_SIZE)
			return TEE_ERROR_GENERIC;
		p &= ~(granule - 1);
	}

	*pa = p;
	return TEE_SUCCESS;
}
KEEP_PAGER(mobj_shm_get_pa);

static size_t mobj_shm_get_phys_offs(struct mobj *mobj, size_t granule)
{
	assert(IS_POWER_OF_TWO(granule));
	return to_mobj_shm(mobj)->pa & (granule - 1);
}

static bool mobj_shm_matches(struct mobj *mobj __unused, enum buf_is_attr attr)
{
	return attr == CORE_MEM_NSEC_SHM || attr == CORE_MEM_NON_SEC;
}

static void mobj_shm_free(struct mobj *mobj)
{
	struct mobj_shm *m = to_mobj_shm(mobj);

	free(m);
}

static uint64_t mobj_shm_get_cookie(struct mobj *mobj)
{
	return to_mobj_shm(mobj)->cookie;
}

static const struct mobj_ops mobj_shm_ops __rodata_unpaged = {
	.get_va = mobj_shm_get_va,
	.get_pa = mobj_shm_get_pa,
	.get_phys_offs = mobj_shm_get_phys_offs,
	.matches = mobj_shm_matches,
	.free = mobj_shm_free,
	.get_cookie = mobj_shm_get_cookie,
};

static struct mobj_shm *to_mobj_shm(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_shm_ops);
	return container_of(mobj, struct mobj_shm, mobj);
}

struct mobj *mobj_shm_alloc(paddr_t pa, size_t size, uint64_t cookie)
{
	struct mobj_shm *m;

	if (!core_pbuf_is(CORE_MEM_NSEC_SHM, pa, size))
		return NULL;

	m = calloc(1, sizeof(*m));
	if (!m)
		return NULL;

	m->mobj.size = size;
	m->mobj.ops = &mobj_shm_ops;
	m->pa = pa;
	m->cookie = cookie;

	return &m->mobj;
}

#ifdef CFG_PAGED_USER_TA
/*
 * mobj_paged implementation
 */

static void mobj_paged_free(struct mobj *mobj);
static bool mobj_paged_matches(struct mobj *mobj, enum buf_is_attr attr);

static const struct mobj_ops mobj_paged_ops __rodata_unpaged = {
	.matches = mobj_paged_matches,
	.free = mobj_paged_free,
};

static void mobj_paged_free(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_paged_ops);
	free(mobj);
}

static bool mobj_paged_matches(struct mobj *mobj __maybe_unused,
				 enum buf_is_attr attr)
{
	assert(mobj->ops == &mobj_paged_ops);

	return attr == CORE_MEM_SEC || attr == CORE_MEM_TEE_RAM;
}

struct mobj *mobj_paged_alloc(size_t size)
{
	struct mobj *mobj = calloc(1, sizeof(*mobj));

	if (mobj) {
		mobj->size = size;
		mobj->ops = &mobj_paged_ops;
	}
	return mobj;
}

/*
 * mobj_seccpy_shm implementation
 */

struct mobj_seccpy_shm {
	struct user_ta_ctx *utc;
	vaddr_t va;
	struct mobj mobj;
};

static bool __maybe_unused mobj_is_seccpy_shm(struct mobj *mobj);

static struct mobj_seccpy_shm *to_mobj_seccpy_shm(struct mobj *mobj)
{
	assert(mobj_is_seccpy_shm(mobj));
	return container_of(mobj, struct mobj_seccpy_shm, mobj);
}

static void *mobj_seccpy_shm_get_va(struct mobj *mobj, size_t offs)
{
	struct mobj_seccpy_shm *m = to_mobj_seccpy_shm(mobj);

	if (&m->utc->ctx != thread_get_tsd()->ctx)
		return NULL;

	if (offs >= mobj->size)
		return NULL;
	return (void *)(m->va + offs);
}

static bool mobj_seccpy_shm_matches(struct mobj *mobj __maybe_unused,
				 enum buf_is_attr attr)
{
	assert(mobj_is_seccpy_shm(mobj));

	return attr == CORE_MEM_SEC || attr == CORE_MEM_TEE_RAM;
}

static void mobj_seccpy_shm_free(struct mobj *mobj)
{
	struct mobj_seccpy_shm *m = to_mobj_seccpy_shm(mobj);

	tee_pager_rem_uta_region(m->utc, m->va, mobj->size);
	tee_mmu_rem_rwmem(m->utc, mobj, m->va);
	free(m);
}

static void mobj_seccpy_shm_update_mapping(struct mobj *mobj,
					struct user_ta_ctx *utc, vaddr_t va)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct mobj_seccpy_shm *m = to_mobj_seccpy_shm(mobj);
	size_t s;

	if (utc == m->utc && va == m->va)
		return;

	s = ROUNDUP(mobj->size, SMALL_PAGE_SIZE);
	pgt_transfer(&tsd->pgt_cache, &m->utc->ctx, m->va, &utc->ctx, va, s);

	m->va = va;
	m->utc = utc;
}

static const struct mobj_ops mobj_seccpy_shm_ops __rodata_unpaged = {
	.get_va = mobj_seccpy_shm_get_va,
	.matches = mobj_seccpy_shm_matches,
	.free = mobj_seccpy_shm_free,
	.update_mapping = mobj_seccpy_shm_update_mapping,
};

static bool mobj_is_seccpy_shm(struct mobj *mobj)
{
	return mobj && mobj->ops == &mobj_seccpy_shm_ops;
}

struct mobj *mobj_seccpy_shm_alloc(size_t size)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct mobj_seccpy_shm *m;
	struct user_ta_ctx *utc;
	vaddr_t va = 0;

	if (!is_user_ta_ctx(tsd->ctx))
		return NULL;
	utc = to_user_ta_ctx(tsd->ctx);

	m = calloc(1, sizeof(*m));
	if (!m)
		return NULL;

	m->mobj.size = size;
	m->mobj.ops = &mobj_seccpy_shm_ops;

	if (tee_mmu_add_rwmem(utc, &m->mobj, &va) != TEE_SUCCESS)
		goto bad;

	if (!tee_pager_add_uta_area(utc, va, size))
		goto bad;

	m->va = va;
	m->utc = to_user_ta_ctx(tsd->ctx);
	return &m->mobj;
bad:
	if (va)
		tee_mmu_rem_rwmem(utc, &m->mobj, va);
	free(m);
	return NULL;
}

bool mobj_is_paged(struct mobj *mobj)
{
	return mobj->ops == &mobj_paged_ops ||
	       mobj->ops == &mobj_seccpy_shm_ops;
}
#endif /*CFG_PAGED_USER_TA*/

static TEE_Result mobj_init(void)
{
	mobj_sec_ddr = mobj_phys_alloc(tee_mm_sec_ddr.lo,
				       tee_mm_sec_ddr.hi - tee_mm_sec_ddr.lo,
				       OPTEE_SMC_SHM_CACHED, CORE_MEM_TA_RAM);
	if (!mobj_sec_ddr)
		panic("Failed to register secure ta ram");

	mobj_tee_ram = mobj_phys_alloc(TEE_RAM_START,
				       VCORE_UNPG_RW_PA + VCORE_UNPG_RW_SZ -
						TEE_RAM_START,
				       TEE_MATTR_CACHE_CACHED,
				       CORE_MEM_TEE_RAM);
	if (!mobj_tee_ram)
		panic("Failed to register tee ram");

	return TEE_SUCCESS;
}

driver_init_late(mobj_init);
