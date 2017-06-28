/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <keep.h>
#include <initcall.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
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
	paddr_t page_offset;
	int num_pages;
	paddr_t pages[];
};

#define MOBJ_REG_SHM_SIZE(nr_pages) \
	(sizeof(struct mobj_reg_shm) + sizeof(paddr_t) * (nr_pages))

static SLIST_HEAD(reg_shm_head, mobj_reg_shm) reg_shm_list =
	SLIST_HEAD_INITIALIZER(reg_shm_head);

static unsigned int reg_shm_slist_lock = SPINLOCK_UNLOCK;

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

static void mobj_reg_shm_free(struct mobj *mobj)
{
	struct mobj_reg_shm *mobj_reg_shm = to_mobj_reg_shm(mobj);
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
	SLIST_REMOVE(&reg_shm_list, mobj_reg_shm,
		     mobj_reg_shm, next);
	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);
	free(mobj_reg_shm);
}

static TEE_Result mobj_reg_shm_get_cattr(struct mobj *mobj __unused,
					 uint32_t *cattr)
{
	if (!cattr)
		return TEE_ERROR_GENERIC;

	*cattr = TEE_MATTR_CACHE_CACHED;

	return TEE_SUCCESS;
}

static const struct mobj_ops mobj_reg_shm_ops __rodata_unpaged = {
	.get_pa = mobj_reg_shm_get_pa,
	.get_cattr = mobj_reg_shm_get_cattr,
	.free = mobj_reg_shm_free,
};

static struct mobj_reg_shm *to_mobj_reg_shm(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_reg_shm_ops);
	return container_of(mobj, struct mobj_reg_shm, mobj);
}

struct mobj *mobj_reg_shm_alloc(paddr_t *pages, size_t num_pages,
				paddr_t page_offset, uint64_t cookie)
{
	struct mobj_reg_shm *mobj_reg_shm;
	size_t i;
	unsigned int exceptions;

	if (!num_pages)
		return NULL;

	mobj_reg_shm = calloc(1, MOBJ_REG_SHM_SIZE(num_pages));
	if (!mobj_reg_shm)
		return NULL;

	mobj_reg_shm->mobj.ops = &mobj_reg_shm_ops;
	mobj_reg_shm->mobj.size =  num_pages * SMALL_PAGE_SIZE;
	mobj_reg_shm->mobj.phys_granule = SMALL_PAGE_SIZE;
	mobj_reg_shm->cookie = cookie;
	mobj_reg_shm->num_pages = num_pages;
	mobj_reg_shm->page_offset = page_offset;
	memcpy(mobj_reg_shm->pages, pages, sizeof(*pages) * num_pages);

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

struct mobj *mobj_reg_shm_find_by_cookie(uint64_t cookie)
{
	struct mobj_reg_shm *mobj_reg_shm;
	unsigned int exceptions;

	exceptions = cpu_spin_lock_xsave(&reg_shm_slist_lock);
	SLIST_FOREACH(mobj_reg_shm, &reg_shm_list, next) {
		if (mobj_reg_shm->cookie == cookie) {
			cpu_spin_unlock_xrestore(&reg_shm_slist_lock,
						 exceptions);
			return &mobj_reg_shm->mobj;
		}
	}
	cpu_spin_unlock_xrestore(&reg_shm_slist_lock, exceptions);
	return NULL;
}

/*
 * mobj_mapped_shm implementation.
 * Used for registered SHM that is mapped to OP-TEE virtual address space
 */

struct mobj_mapped_shm {
	struct mobj mobj;
	tee_mm_entry_t *mm_entry;
	struct mobj *reg_shm;
};

static struct mobj_mapped_shm *to_mobj_mapped_shm(struct mobj *mobj);

static TEE_Result mobj_mapped_shm_get_pa(struct mobj *mobj, size_t offst,
				      size_t granule, paddr_t *pa)
{
	struct mobj_mapped_shm *mobj_mapped_shm = to_mobj_mapped_shm(mobj);

	return mobj_reg_shm_get_pa(mobj_mapped_shm->reg_shm, offst,
				   granule, pa);
}

static void *mobj_mapped_shm_get_va(struct mobj *mobj, size_t offst)
{
	struct mobj_mapped_shm *mobj_mapped_shm = to_mobj_mapped_shm(mobj);
	struct mobj_reg_shm *reg_shm =
		to_mobj_reg_shm(mobj_mapped_shm->reg_shm);

	return (void *)(tee_mm_get_smem(mobj_mapped_shm->mm_entry) + offst +
			reg_shm->page_offset);
}

static void mobj_mapped_shm_free(struct mobj *mobj)
{
	struct mobj_mapped_shm *mobj_mapped_shm = to_mobj_mapped_shm(mobj);
	vaddr_t va = tee_mm_get_smem(mobj_mapped_shm->mm_entry);

	core_mmu_unmap_pages(va, mobj->size / SMALL_PAGE_SIZE);
	tee_mm_free(mobj_mapped_shm->mm_entry);
	mobj_free(mobj_mapped_shm->reg_shm);
	free(mobj_mapped_shm);
}

static TEE_Result mobj_mapped_shm_get_cattr(struct mobj *mobj __unused,
					 uint32_t *cattr)
{
	if (!cattr)
		return TEE_ERROR_GENERIC;

	*cattr = TEE_MATTR_CACHE_CACHED;

	return TEE_SUCCESS;
}

static bool mobj_mapped_shm_matches(struct mobj *mobj, enum buf_is_attr attr);

static const struct mobj_ops mobj_mapped_shm_ops __rodata_unpaged = {
	.get_pa = mobj_mapped_shm_get_pa,
	.get_va = mobj_mapped_shm_get_va,
	.get_cattr = mobj_mapped_shm_get_cattr,
	.matches = mobj_mapped_shm_matches,
	.free = mobj_mapped_shm_free,
};

static bool mobj_mapped_shm_matches(struct mobj *mobj __maybe_unused,
				   enum buf_is_attr attr)
{
	assert(mobj->ops == &mobj_mapped_shm_ops);

	return attr == CORE_MEM_NON_SEC || attr == CORE_MEM_NSEC_SHM ||
		attr == CORE_MEM_REG_SHM;
}

static struct mobj_mapped_shm *to_mobj_mapped_shm(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_mapped_shm_ops);
	return container_of(mobj, struct mobj_mapped_shm, mobj);
}

struct mobj *mobj_mapped_shm_alloc(paddr_t *pages, size_t num_pages,
				  paddr_t page_offset, uint64_t cookie)
{
	struct mobj_mapped_shm *mobj_mapped_shm;
	vaddr_t vaddr;

	mobj_mapped_shm = calloc(1, sizeof(struct mobj_mapped_shm));
	if (!mobj_mapped_shm)
		return NULL;

	mobj_mapped_shm->reg_shm =
		mobj_reg_shm_alloc(pages, num_pages, page_offset, cookie);
	if (!mobj_mapped_shm->reg_shm)
		goto err;

	mobj_mapped_shm->mm_entry =
		tee_mm_alloc(&tee_mm_shm, SMALL_PAGE_SIZE * num_pages);
	if (!mobj_mapped_shm->mm_entry)
		goto err;

	vaddr = tee_mm_get_smem(mobj_mapped_shm->mm_entry);
	if (core_mmu_map_pages(vaddr,
			to_mobj_reg_shm(mobj_mapped_shm->reg_shm)->pages,
			num_pages, MEM_AREA_NSEC_SHM))
		goto err;

	mobj_mapped_shm->mobj.ops = &mobj_mapped_shm_ops;
	mobj_mapped_shm->mobj.size =  num_pages * SMALL_PAGE_SIZE;
	mobj_mapped_shm->mobj.phys_granule = SMALL_PAGE_SIZE;

	return &mobj_mapped_shm->mobj;
err:
	mobj_free(mobj_mapped_shm->reg_shm);
	tee_mm_free(mobj_mapped_shm->mm_entry);
	free(mobj_mapped_shm);

	return NULL;
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

static bool mobj_shm_matches(struct mobj *mobj __unused, enum buf_is_attr attr)
{
	return attr == CORE_MEM_NSEC_SHM || attr == CORE_MEM_NON_SEC;
}

static void mobj_shm_free(struct mobj *mobj)
{
	struct mobj_shm *m = to_mobj_shm(mobj);

	free(m);
}

static const struct mobj_ops mobj_shm_ops __rodata_unpaged = {
	.get_va = mobj_shm_get_va,
	.get_pa = mobj_shm_get_pa,
	.matches = mobj_shm_matches,
	.free = mobj_shm_free,
};

static struct mobj_shm *to_mobj_shm(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_shm_ops);
	return container_of(mobj, struct mobj_shm, mobj);
}

struct mobj *mobj_shm_alloc(paddr_t pa, size_t size)
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

	return &m->mobj;
}

#ifdef CFG_PAGED_USER_TA
/*
 * mobj_paged implementation
 */

static void mobj_paged_free(struct mobj *mobj);

static const struct mobj_ops mobj_paged_ops __rodata_unpaged = {
	.free = mobj_paged_free,
};

static void mobj_paged_free(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_paged_ops);
	free(mobj);
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
	size_t pgdir_offset;
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

	if (tee_mmu_add_rwmem(utc, &m->mobj, -1, &va) != TEE_SUCCESS)
		goto bad;

	if (!tee_pager_add_uta_area(utc, va, size))
		goto bad;

	m->va = va;
	m->pgdir_offset = va & CORE_MMU_PGDIR_MASK;
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
