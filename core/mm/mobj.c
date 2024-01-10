// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2022, Linaro Limited
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
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/tee_pager.h>
#include <optee_msg.h>
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
	/* Defined by TEE_MATTR_MEM_TYPE_* in tee_mmu_types.h */
	uint32_t mem_type;
	vaddr_t va;
	paddr_t pa;
};

static struct mobj_phys *to_mobj_phys(struct mobj *mobj);

static void *mobj_phys_get_va(struct mobj *mobj, size_t offset, size_t len)
{
	struct mobj_phys *moph = to_mobj_phys(mobj);

	if (!moph->va || !mobj_check_offset_and_len(mobj, offset, len))
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

static TEE_Result mobj_phys_get_mem_type(struct mobj *mobj, uint32_t *mem_type)
{
	struct mobj_phys *moph = to_mobj_phys(mobj);

	if (!mem_type)
		return TEE_ERROR_GENERIC;

	*mem_type = moph->mem_type;
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
const struct mobj_ops mobj_phys_ops
__weak __relrodata_unpaged("mobj_phys_ops") = {
	.get_va = mobj_phys_get_va,
	.get_pa = mobj_phys_get_pa,
	.get_phys_offs = NULL, /* only offset 0 */
	.get_mem_type = mobj_phys_get_mem_type,
	.matches = mobj_phys_matches,
	.free = mobj_phys_free,
};

static struct mobj_phys *to_mobj_phys(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_phys_ops);
	return container_of(mobj, struct mobj_phys, mobj);
}

static struct mobj *mobj_phys_init(paddr_t pa, size_t size, uint32_t mem_type,
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
	moph->mem_type = mem_type;
	moph->mobj.size = size;
	moph->mobj.ops = &mobj_phys_ops;
	refcount_set(&moph->mobj.refc, 1);
	moph->pa = pa;
	moph->va = (vaddr_t)va;

	return &moph->mobj;
}

struct mobj *mobj_phys_alloc(paddr_t pa, size_t size, uint32_t mem_type,
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

	return mobj_phys_init(pa, size, mem_type, battr, area_type);
}

/*
 * mobj_virt implementation
 */

static void mobj_virt_assert_type(struct mobj *mobj);

static void *mobj_virt_get_va(struct mobj *mobj, size_t offset,
			      size_t len __maybe_unused)
{
	mobj_virt_assert_type(mobj);
	assert(mobj_check_offset_and_len(mobj, offset, len));

	return (void *)(vaddr_t)offset;
}

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct mobj_ops mobj_virt_ops
__weak __relrodata_unpaged("mobj_virt_ops") = {
	.get_va = mobj_virt_get_va,
};

static void mobj_virt_assert_type(struct mobj *mobj __maybe_unused)
{
	assert(mobj->ops == &mobj_virt_ops);
}

struct mobj mobj_virt = { .ops = &mobj_virt_ops, .size = SIZE_MAX };

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

static void *mobj_shm_get_va(struct mobj *mobj, size_t offset, size_t len)
{
	struct mobj_shm *m = to_mobj_shm(mobj);

	if (!mobj_check_offset_and_len(mobj, offset, len))
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

static TEE_Result mobj_shm_get_mem_type(struct mobj *mobj __unused,
					uint32_t *mem_type)
{
	if (!mem_type)
		return TEE_ERROR_GENERIC;

	*mem_type = TEE_MATTR_MEM_TYPE_CACHED;

	return TEE_SUCCESS;
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
const struct mobj_ops mobj_shm_ops
__weak __relrodata_unpaged("mobj_shm_ops") = {
	.get_va = mobj_shm_get_va,
	.get_pa = mobj_shm_get_pa,
	.get_phys_offs = mobj_shm_get_phys_offs,
	.get_mem_type = mobj_shm_get_mem_type,
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
	m->mobj.phys_granule = SMALL_PAGE_SIZE;
	refcount_set(&m->mobj.refc, 1);
	m->pa = pa;
	m->cookie = cookie;

	return &m->mobj;
}

struct mobj_with_fobj {
	struct fobj *fobj;
	struct file *file;
	struct mobj mobj;
	uint8_t mem_type;
};

const struct mobj_ops mobj_with_fobj_ops;

struct mobj *mobj_with_fobj_alloc(struct fobj *fobj, struct file *file,
				  uint32_t mem_type)
{
	struct mobj_with_fobj *m = NULL;

	assert(!(mem_type & ~TEE_MATTR_MEM_TYPE_MASK));

	if (!fobj)
		return NULL;
	if (mem_type > UINT8_MAX)
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
	m->mem_type = mem_type;

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

static TEE_Result mobj_with_fobj_get_mem_type(struct mobj *mobj,
					      uint32_t *mem_type)
{
	struct mobj_with_fobj *m = to_mobj_with_fobj(mobj);

	if (!mem_type)
		return TEE_ERROR_GENERIC;

	*mem_type = m->mem_type;

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
__weak __relrodata_unpaged("mobj_with_fobj_ops") = {
	.matches = mobj_with_fobj_matches,
	.free = mobj_with_fobj_free,
	.get_fobj = mobj_with_fobj_get_fobj,
	.get_mem_type = mobj_with_fobj_get_mem_type,
	.get_pa = mobj_with_fobj_get_pa,
};

#ifdef CFG_PAGED_USER_TA
bool mobj_is_paged(struct mobj *mobj)
{
	if (mobj->ops == &mobj_with_fobj_ops &&
	    !to_mobj_with_fobj(mobj)->fobj->ops->get_pa)
		return true;

	return false;
}
#endif /*CFG_PAGED_USER_TA*/

static TEE_Result mobj_init(void)
{
	mobj_sec_ddr = mobj_phys_alloc(tee_mm_sec_ddr.lo,
				       tee_mm_sec_ddr.size,
				       TEE_MATTR_MEM_TYPE_CACHED,
				       CORE_MEM_TA_RAM);
	if (!mobj_sec_ddr)
		panic("Failed to register secure ta ram");

	if (IS_ENABLED(CFG_CORE_RWDATA_NOEXEC)) {
		mobj_tee_ram_rx = mobj_phys_init(0,
						 VCORE_UNPG_RX_SZ,
						 TEE_MATTR_MEM_TYPE_CACHED,
						 CORE_MEM_TEE_RAM,
						 MEM_AREA_TEE_RAM_RX);
		if (!mobj_tee_ram_rx)
			panic("Failed to register tee ram rx");

		mobj_tee_ram_rw = mobj_phys_init(0,
						 VCORE_UNPG_RW_SZ,
						 TEE_MATTR_MEM_TYPE_CACHED,
						 CORE_MEM_TEE_RAM,
						 MEM_AREA_TEE_RAM_RW_DATA);
		if (!mobj_tee_ram_rw)
			panic("Failed to register tee ram rw");
	} else {
		mobj_tee_ram_rw = mobj_phys_init(TEE_RAM_START,
						 VCORE_UNPG_RW_PA +
						 VCORE_UNPG_RW_SZ -
						 TEE_RAM_START,
						 TEE_MATTR_MEM_TYPE_CACHED,
						 CORE_MEM_TEE_RAM,
						 MEM_AREA_TEE_RAM_RW_DATA);
		if (!mobj_tee_ram_rw)
			panic("Failed to register tee ram");

		mobj_tee_ram_rx = mobj_tee_ram_rw;
	}

	return TEE_SUCCESS;
}

driver_init_late(mobj_init);
