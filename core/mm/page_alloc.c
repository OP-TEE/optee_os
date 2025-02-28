// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Linaro Limited
 */

#include <kernel/boot.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <mm/core_mmu.h>
#include <mm/page_alloc.h>
#include <mm/phys_mem.h>
#include <mm/tee_mm.h>
#include <string.h>
#include <types_ext.h>

static tee_mm_pool_t core_virt_nex_pool __nex_bss;
static tee_mm_pool_t core_virt_tee_pool;

static void init_virt_pool(tee_mm_pool_t *pool, uint32_t flags,
			   enum teecore_memtypes memtype)
{
	vaddr_t start = 0;
	vaddr_t end = 0;

	core_mmu_get_mem_by_type(memtype, &start, &end);
	if (!start || !end)
		panic();

	if (!tee_mm_init(pool, start, end - start, SMALL_PAGE_SHIFT, flags))
		panic();
}

void nex_page_alloc_init(void)
{
	init_virt_pool(&core_virt_nex_pool, TEE_MM_POOL_NEX_MALLOC,
		       MEM_AREA_NEX_DYN_VASPACE);
}

void page_alloc_init(void)
{
	init_virt_pool(&core_virt_tee_pool, TEE_MM_POOL_NO_FLAGS,
		       MEM_AREA_TEE_DYN_VASPACE);
}

vaddr_t virt_page_alloc(size_t count, uint32_t flags)
{
	enum teecore_memtypes memtype = 0;
	TEE_Result res = TEE_SUCCESS;
	tee_mm_pool_t *pool = NULL;
	tee_mm_entry_t *mmv = NULL;
	tee_mm_entry_t *mmp = NULL;
	size_t vcount = count;
	size_t pcount = count;
	vaddr_t va = 0;
	paddr_t pa = 0;

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION) && (flags & MAF_NEX)) {
		pool = &core_virt_nex_pool;
		memtype = MEM_AREA_NEX_DYN_VASPACE;
	} else {
		pool = &core_virt_tee_pool;
		memtype = MEM_AREA_TEE_DYN_VASPACE;
	}

	if (flags & MAF_GUARD_HEAD)
		vcount++;
	if (flags & MAF_GUARD_TAIL)
		vcount++;

	/* We're allocating one extra page to use as unmapped guard */
	mmv = tee_mm_alloc_flags(pool, vcount * SMALL_PAGE_SIZE, flags);
	if (!mmv)
		return 0;
	va = tee_mm_get_smem(mmv);
	if (flags & MAF_GUARD_HEAD)
		va += SMALL_PAGE_SIZE;

	mmp = phys_mem_alloc_flags(pcount * SMALL_PAGE_SIZE, flags);
	if (!mmp)
		goto err_free_mmv;
	pa = tee_mm_get_smem(mmp);
	assert(pa);

	res = core_mmu_map_contiguous_pages(va, pa, pcount, memtype);
	if (res)
		goto err;

	if (flags & MAF_ZERO_INIT)
		memset((void *)va, 0, pcount * SMALL_PAGE_SIZE);

	return va;
err:
	tee_mm_free(mmp);
err_free_mmv:
	tee_mm_free(mmv);
	return 0;
}
