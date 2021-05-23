// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2021, Linaro Limited
 */

#include <assert.h>
#include <config.h>
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
#include <mm/tee_pager.h>
#include <mm/vm.h>
#include <optee_msg.h>
#include <sm/optee_smc.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

struct mobj *mobj_sec_ddr;
struct mobj *mobj_tee_ram_rx;
struct mobj *mobj_tee_ram_rw;

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

	if (!moph->va || offset >= mobj->size)
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
DECLARE_KEEP_PAGER(mobj_phys_get_pa);

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

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct mobj_ops mobj_phys_ops __weak __rodata_unpaged("mobj_phys_ops") = {
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

static struct mobj *mobj_phys_init(paddr_t pa, size_t size, uint32_t cattr,
				   enum buf_is_attr battr,
				   enum teecore_memtypes area_type)
{
	void *va = NULL;
	struct mobj_phys *moph = NULL;
	struct tee_mmap_region *map = NULL;

	if ((pa & CORE_MMU_USER_PARAM_MASK) ||
	    (size & CORE_MMU_USER_PARAM_MASK)) {
		DMSG("Expect %#x alignment", CORE_MMU_USER_PARAM_SIZE);
		return NULL;
	}

	if (pa) {
		va = phys_to_virt(pa, area_type, size);
	} else {
		map = core_mmu_find_mapping_exclusive(area_type, size);
		if (!map)
			return NULL;

		pa = map->pa;
		va = (void *)map->va;
	}

	/* Only SDP memory may not have a virtual address */
	if (!va && battr != CORE_MEM_SDP_MEM)
		return NULL;

	moph = calloc(1, sizeof(*moph));
	if (!moph)
		return NULL;

	moph->battr = battr;
	moph->cattr = cattr;
	moph->mobj.size = size;
	moph->mobj.ops = &mobj_phys_ops;
	refcount_set(&moph->mobj.refc, 1);
	moph->pa = pa;
	moph->va = (vaddr_t)va;

	return &moph->mobj;
}

struct mobj *mobj_phys_alloc(paddr_t pa, size_t size, uint32_t cattr,
			     enum buf_is_attr battr)
{
	enum teecore_memtypes area_type;

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

	return mobj_phys_init(pa, size, cattr, battr, area_type);
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

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct mobj_ops mobj_virt_ops __weak __rodata_unpaged("mobj_virt_ops") = {
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
DECLARE_KEEP_PAGER(mobj_mm_get_pa);

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

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct mobj_ops mobj_mm_ops __weak __rodata_unpaged("mobj_mm_ops") = {
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
	refcount_set(&m->mobj.refc, 1);

	return &m->mobj;
}


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

	return phys_to_virt(m->pa + offset, MEM_AREA_NSEC_SHM,
			    mobj->size - offset);
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
DECLARE_KEEP_PAGER(mobj_shm_get_pa);

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

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct mobj_ops mobj_shm_ops __weak __rodata_unpaged("mobj_shm_ops") = {
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
	refcount_set(&m->mobj.refc, 1);
	m->pa = pa;
	m->cookie = cookie;

	return &m->mobj;
}

#ifdef CFG_PAGED_USER_TA
/*
 * mobj_seccpy_shm implementation
 */

struct mobj_seccpy_shm {
	struct user_ta_ctx *utc;
	vaddr_t va;
	struct mobj mobj;
	struct fobj *fobj;
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

	if (&m->utc->ta_ctx.ts_ctx != thread_get_tsd()->ctx)
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

	tee_pager_rem_um_region(&m->utc->uctx, m->va, mobj->size);
	vm_rem_rwmem(&m->utc->uctx, mobj, m->va);
	fobj_put(m->fobj);
	free(m);
}

static struct fobj *mobj_seccpy_shm_get_fobj(struct mobj *mobj)
{
	return fobj_get(to_mobj_seccpy_shm(mobj)->fobj);
}

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct mobj_ops mobj_seccpy_shm_ops
__weak __rodata_unpaged("mobj_seccpy_shm_ops") = {
	.get_va = mobj_seccpy_shm_get_va,
	.matches = mobj_seccpy_shm_matches,
	.free = mobj_seccpy_shm_free,
	.get_fobj = mobj_seccpy_shm_get_fobj,
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
	refcount_set(&m->mobj.refc, 1);

	if (vm_add_rwmem(&utc->uctx, &m->mobj, &va) != TEE_SUCCESS)
		goto bad;

	m->fobj = fobj_rw_paged_alloc(ROUNDUP(size, SMALL_PAGE_SIZE) /
				      SMALL_PAGE_SIZE);
	if (tee_pager_add_um_region(&utc->uctx, va, m->fobj,
				    TEE_MATTR_PRW | TEE_MATTR_URW))
		goto bad;

	m->va = va;
	m->utc = to_user_ta_ctx(tsd->ctx);
	return &m->mobj;
bad:
	if (va)
		vm_rem_rwmem(&utc->uctx, &m->mobj, va);
	fobj_put(m->fobj);
	free(m);
	return NULL;
}


#endif /*CFG_PAGED_USER_TA*/

struct mobj_with_fobj {
	struct fobj *fobj;
	struct file *file;
	struct mobj mobj;
};

const struct mobj_ops mobj_with_fobj_ops;

struct mobj *mobj_with_fobj_alloc(struct fobj *fobj, struct file *file)
{
	struct mobj_with_fobj *m = NULL;

	if (!fobj)
		return NULL;

	m = calloc(1, sizeof(*m));
	if (!m)
		return NULL;

	m->mobj.ops = &mobj_with_fobj_ops;
	refcount_set(&m->mobj.refc, 1);
	m->mobj.size = fobj->num_pages * SMALL_PAGE_SIZE;
	m->mobj.phys_granule = SMALL_PAGE_SIZE;
	m->fobj = fobj_get(fobj);
	m->file = file_get(file);

	return &m->mobj;
}

static struct mobj_with_fobj *to_mobj_with_fobj(struct mobj *mobj)
{
	assert(mobj && mobj->ops == &mobj_with_fobj_ops);

	return container_of(mobj, struct mobj_with_fobj, mobj);
}

static bool mobj_with_fobj_matches(struct mobj *mobj __maybe_unused,
				 enum buf_is_attr attr)
{
	assert(to_mobj_with_fobj(mobj));

	/*
	 * All fobjs are supposed to be mapped secure so classify it as
	 * CORE_MEM_SEC. Stay out of CORE_MEM_TEE_RAM etc, if that information
	 * needed it can probably be carried in another way than to put the
	 * burden directly on fobj.
	 */
	return attr == CORE_MEM_SEC;
}

static void mobj_with_fobj_free(struct mobj *mobj)
{
	struct mobj_with_fobj *m = to_mobj_with_fobj(mobj);

	fobj_put(m->fobj);
	file_put(m->file);
	free(m);
}

static struct fobj *mobj_with_fobj_get_fobj(struct mobj *mobj)
{
	return fobj_get(to_mobj_with_fobj(mobj)->fobj);
}

static TEE_Result mobj_with_fobj_get_cattr(struct mobj *mobj __unused,
					   uint32_t *cattr)
{
	if (!cattr)
		return TEE_ERROR_GENERIC;

	/* All fobjs are mapped as normal cached memory */
	*cattr = TEE_MATTR_CACHE_CACHED;

	return TEE_SUCCESS;
}

static TEE_Result mobj_with_fobj_get_pa(struct mobj *mobj, size_t offs,
					size_t granule, paddr_t *pa)
{
	struct mobj_with_fobj *f = to_mobj_with_fobj(mobj);
	paddr_t p = 0;

	if (!f->fobj->ops->get_pa) {
		assert(mobj_is_paged(mobj));
		return TEE_ERROR_NOT_SUPPORTED;
	}

	p = f->fobj->ops->get_pa(f->fobj, offs / SMALL_PAGE_SIZE) +
	    offs % SMALL_PAGE_SIZE;

	if (granule) {
		if (granule != SMALL_PAGE_SIZE &&
		    granule != CORE_MMU_PGDIR_SIZE)
			return TEE_ERROR_GENERIC;
		p &= ~(granule - 1);
	}

	*pa = p;

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(mobj_with_fobj_get_pa);

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct mobj_ops mobj_with_fobj_ops
__weak __rodata_unpaged("mobj_with_fobj_ops") = {
	.matches = mobj_with_fobj_matches,
	.free = mobj_with_fobj_free,
	.get_fobj = mobj_with_fobj_get_fobj,
	.get_cattr = mobj_with_fobj_get_cattr,
	.get_pa = mobj_with_fobj_get_pa,
};

#ifdef CFG_PAGED_USER_TA
bool mobj_is_paged(struct mobj *mobj)
{
	if (mobj->ops == &mobj_seccpy_shm_ops)
		return true;

	if (mobj->ops == &mobj_with_fobj_ops &&
	    !to_mobj_with_fobj(mobj)->fobj->ops->get_pa)
		return true;

	return false;
}
#endif /*CFG_PAGED_USER_TA*/

static TEE_Result mobj_init(void)
{
	mobj_sec_ddr = mobj_phys_alloc(tee_mm_sec_ddr.lo,
				       tee_mm_sec_ddr.hi - tee_mm_sec_ddr.lo,
				       OPTEE_SMC_SHM_CACHED, CORE_MEM_TA_RAM);
	if (!mobj_sec_ddr)
		panic("Failed to register secure ta ram");

	if (IS_ENABLED(CFG_CORE_RWDATA_NOEXEC)) {
		mobj_tee_ram_rx = mobj_phys_init(0,
						 VCORE_UNPG_RX_SZ,
						 TEE_MATTR_CACHE_CACHED,
						 CORE_MEM_TEE_RAM,
						 MEM_AREA_TEE_RAM_RX);
		if (!mobj_tee_ram_rx)
			panic("Failed to register tee ram rx");

		mobj_tee_ram_rw = mobj_phys_init(0,
						 VCORE_UNPG_RW_SZ,
						 TEE_MATTR_CACHE_CACHED,
						 CORE_MEM_TEE_RAM,
						 MEM_AREA_TEE_RAM_RW_DATA);
		if (!mobj_tee_ram_rw)
			panic("Failed to register tee ram rw");
	} else {
		mobj_tee_ram_rw = mobj_phys_init(TEE_RAM_START,
						 VCORE_UNPG_RW_PA +
						 VCORE_UNPG_RW_SZ -
						 TEE_RAM_START,
						 TEE_MATTR_CACHE_CACHED,
						 CORE_MEM_TEE_RAM,
						 MEM_AREA_TEE_RAM_RW_DATA);
		if (!mobj_tee_ram_rw)
			panic("Failed to register tee ram");

		mobj_tee_ram_rx = mobj_tee_ram_rw;
	}

	return TEE_SUCCESS;
}

driver_init_late(mobj_init);
