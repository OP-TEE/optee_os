/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

/*
 * This core mmu supports static section mapping (1MByte).
 *       It should should finer mapping (4kByte coarse pages).
 *       It should also allow core to map/unmap (and va/pa) at run-time.
 */
#include <platform_config.h>

#include <stdlib.h>
#include <assert.h>
#include <kernel/tz_proc.h>
#include <kernel/tz_ssvce.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <mm/core_memprot.h>
#include <mm/tee_pager.h>
#include <trace.h>
#include <kernel/tee_misc.h>
#include <kernel/panic.h>
#include <kernel/tee_ta_manager.h>
#include <util.h>
#include "core_mmu_private.h"
#include <kernel/tz_ssvce_pl310.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/thread.h>
#include <arm.h>

#define MAX_MMAP_REGIONS	10

/* Default NSec shared memory allocated from NSec world */
unsigned long default_nsec_shm_size __data; /* XXX __data is a workaround */
unsigned long default_nsec_shm_paddr __data; /* XXX __data is a workaround */

/* platform handler for core_pbuf_is()  */
static unsigned long bootcfg_pbuf_is = 1;	/* NOT is BSS */
typedef bool(*platform_pbuf_is_t) (unsigned long attr, unsigned long paddr,
				   size_t size);

/*
 * WARNING: resources accessed during the initialization
 * (sequence core_init_mmu()) are accessed *before* BSS is zero-initialised.
 * Be careful NOT to load data that can be 'reset' to zero after
 * core_init_mmu(), due to BSS init loop.
 */
static struct map_area *static_memory_map = (void *)1;	/* not in BSS */
static struct map_area *map_tee_ram = (void *)1;	/* not in BSS */
static struct map_area *map_ta_ram = (void *)1;	/* not in BSS */
static struct map_area *map_nsec_shm = (void *)1;	/* not in BSS */

/* check if target buffer fits in a core default map area */
static bool pbuf_inside_map_area(unsigned long p, size_t l,
				 struct map_area *map)
{
	return core_is_buffer_inside(p, l, map->pa, map->size);
}

static struct map_area *find_map_by_type(enum teecore_memtypes type)
{
	struct map_area *map;

	for (map = static_memory_map; map->type != MEM_AREA_NOTYPE; map++)
		if (map->type == type)
			return map;
	return NULL;
}

static struct map_area *find_map_by_va(void *va)
{
	struct map_area *map = static_memory_map;
	unsigned long a = (unsigned long)va;

	while (map->type != MEM_AREA_NOTYPE) {
		if ((a >= map->va) && (a <= (map->va - 1 + map->size)))
			return map;
		map++;
	}
	return NULL;
}

static struct map_area *find_map_by_pa(unsigned long pa)
{
	struct map_area *map = static_memory_map;

	while (map->type != MEM_AREA_NOTYPE) {
		if ((pa >= map->pa) && (pa < (map->pa + map->size)))
			return map;
		map++;
	}
	return NULL;
}

static void insert_mmap(struct tee_mmap_region *mm, size_t max_elem,
		struct tee_mmap_region *mme)
{
	size_t n;

	for (n = 0; n < (max_elem - 1); n++) {
		if (!mm[n].size) {
			mm[n] = *mme;
			return;
		}

		if (core_is_buffer_intersect(mme->va, mme->size, mm[n].va,
					     mm[n].size)) {
			vaddr_t end_va;

			/* Check that the overlapping maps are compatible */
			if (mme->attr != mm[n].attr ||
			    (mme->pa - mme->va) != (mm[n].pa - mm[n].va)) {
				EMSG("Incompatible mmap regions");
				panic();
			}

			/* Grow the current map */
			end_va = MAX(mme->va + mme->size,
				     mm[n].va + mm[n].size);
			mm[n].va = MIN(mme->va, mm[n].va);
			mm[n].pa = MIN(mme->pa, mm[n].pa);
			mm[n].size = end_va - mm[n].va;
			return;
		}

		if (mme->va < mm[n].va) {
			memmove(mm + n + 1, mm + n,
				(max_elem - n - 1) * sizeof(*mm));
			mm[n] = *mme;
			/*
			 * Panics if the terminating element was
			 * overwritten.
			 */
			if (mm[max_elem - 1].size)
				break;
			return;
		}
	}
	EMSG("Too many mmap regions");
	panic();
}

static void core_mmu_mmap_init(struct tee_mmap_region *mm, size_t max_elem,
		struct map_area *map)
{
	struct tee_mmap_region mme;
	size_t n;

	memset(mm, 0, max_elem * sizeof(struct tee_mmap_region));

	for (n = 0; map[n].type != MEM_AREA_NOTYPE; n++) {
		mme.pa = map[n].pa;
		mme.va = map[n].pa;
		mme.size = map[n].size;

		mme.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PR |
			   TEE_MATTR_GLOBAL;

		if (map[n].device || !map[n].cached)
			mme.attr |= TEE_MATTR_CACHE_NONCACHE <<
				    TEE_MATTR_CACHE_SHIFT;
		else
			mme.attr |= TEE_MATTR_CACHE_CACHED <<
				    TEE_MATTR_CACHE_SHIFT;

		if (map[n].rw)
			mme.attr |= TEE_MATTR_PW;

		if (map[n].exec)
			mme.attr |= TEE_MATTR_PX;

		if (map[n].secure)
			mme.attr |= TEE_MATTR_SECURE;

		insert_mmap(mm, max_elem, &mme);
	}
}



/*
 * core_init_mmu_map - init tee core default memory mapping
 *
 * this routine sets the static default tee core mapping.
 *
 * If an error happend: core_init_mmu_map is expected to reset.
 */
void core_init_mmu_map(void)
{
	struct tee_mmap_region mm[MAX_MMAP_REGIONS + 1];
	struct map_area *map, *in;

	/* get memory bootcfg from system */
	in = bootcfg_get_memory();
	if (!in) {
		EMSG("Invalid memory map");
		TEE_ASSERT(0);
	}
	bootcfg_pbuf_is = (unsigned long)bootcfg_get_pbuf_is_handler();
	if (bootcfg_pbuf_is == 0) {
		EMSG("invalid platform handler for pbuf_is");
		TEE_ASSERT(0);
	}

	/* we must find at least a PUB_RAM area and a TEE_RAM area */
	map_tee_ram = NULL;
	map_ta_ram = NULL;
	map_nsec_shm = NULL;

	/* map what needs to be mapped (non-null size and non INTRAM/EXTRAM) */
	map = in;
	while (map->type != MEM_AREA_NOTYPE) {
		if (map->va)
			panic();

		map->va = map->pa;	/* 1-to-1 pa = va mapping */
		if (map->type == MEM_AREA_TEE_RAM)
			map_tee_ram = map;
		else if (map->type == MEM_AREA_TA_RAM)
			map_ta_ram = map;
		else if (map->type == MEM_AREA_NSEC_SHM)
			map_nsec_shm = map;

		map++;
	}

	if ((map_tee_ram == NULL) || (map_ta_ram == NULL) ||
	    (map_nsec_shm == NULL)) {
		EMSG("mapping area missing");
		TEE_ASSERT(0);
	}

	static_memory_map = in;

	core_mmu_mmap_init(mm, ARRAY_SIZE(mm), in);

	core_init_mmu_tables(mm);
}

/* routines to retrieve shared mem configuration */
bool core_mmu_is_shm_cached(void)
{
	return map_nsec_shm ? map_nsec_shm->cached : false;
}

bool core_mmu_mattr_is_ok(uint32_t mattr)
{
	/*
	 * Keep in sync with core_mmu_lpae.c:mattr_to_desc and
	 * core_mmu_v7.c:mattr_to_texcb
	 */

	switch ((mattr >> TEE_MATTR_CACHE_SHIFT) & TEE_MATTR_CACHE_MASK) {
	case TEE_MATTR_CACHE_NONCACHE:
	case TEE_MATTR_CACHE_CACHED:
		return true;
	default:
		return false;
	}
}

/*
 * test attributes of target physical buffer
 *
 * Flags: pbuf_is(SECURE, NOT_SECURE, RAM, IOMEM, KEYVAULT).
 *
 */
bool core_pbuf_is(uint32_t attr, tee_paddr_t pbuf, size_t len)
{
	struct map_area *map;

	/* Empty buffers complies with anything */
	if (len == 0)
		return true;

	switch (attr) {
	case CORE_MEM_SEC:
		return ((platform_pbuf_is_t)bootcfg_pbuf_is)(attr, pbuf, len);
	case CORE_MEM_NON_SEC:
		return ((platform_pbuf_is_t)bootcfg_pbuf_is)(attr, pbuf, len);
	case CORE_MEM_TEE_RAM:
		return pbuf_inside_map_area(pbuf, len, map_tee_ram);
	case CORE_MEM_TA_RAM:
		return pbuf_inside_map_area(pbuf, len, map_ta_ram);
	case CORE_MEM_NSEC_SHM:
		return pbuf_inside_map_area(pbuf, len, map_nsec_shm);
	case CORE_MEM_MULTPURPOSE:
		return ((platform_pbuf_is_t)bootcfg_pbuf_is)(attr, pbuf, len);
	case CORE_MEM_EXTRAM:
		return ((platform_pbuf_is_t)bootcfg_pbuf_is)(attr, pbuf, len);
	case CORE_MEM_CACHED:
		map = find_map_by_pa(pbuf);
		if (map == NULL || !pbuf_inside_map_area(pbuf, len, map))
			return false;
		return map->cached;
	default:
		return false;
	}
}

/* test attributes of target virtual buffer (in core mapping) */
bool core_vbuf_is(uint32_t attr, const void *vbuf, size_t len)
{
	paddr_t p;

	/* Empty buffers complies with anything */
	if (len == 0)
		return true;

	p = virt_to_phys((void *)vbuf);
	if (!p)
		return false;

	return core_pbuf_is(attr, p, len);
}


/* core_va2pa - teecore exported service */
int core_va2pa_helper(void *va, paddr_t *pa)
{
	struct map_area *map;

	map = find_map_by_va(va);
	if (map == NULL)
		return -1;

	*pa = ((uintptr_t)va & (map->region_size - 1)) |
	    ((map->pa + (uintptr_t)va - map->va) & ~(map->region_size - 1));
	return 0;
}

static void *map_pa2va(struct map_area *map, paddr_t pa)
{
	if (!map)
		return NULL;
	return (void *)((pa & (map->region_size - 1)) |
		(((map->va + pa - map->pa)) & ~(map->region_size - 1)));
}

/*
 * teecore gets some memory area definitions
 */
void core_mmu_get_mem_by_type(unsigned int type, vaddr_t *s, vaddr_t *e)
{
	struct map_area *map = find_map_by_type(type);

	if (map) {
		*s = map->va;
		*e = map->va + map->size;
	} else {
		*s = 0;
		*e = 0;
	}
}

int core_tlb_maintenance(int op, unsigned int a)
{
	/*
	 * We're doing TLB invalidation because we've changed mapping.
	 * The dsb() makes sure that written data is visible.
	 */
	dsb();

	switch (op) {
	case TLBINV_UNIFIEDTLB:
		secure_mmu_unifiedtlbinvall();
		break;
	case TLBINV_CURRENT_ASID:
		secure_mmu_unifiedtlbinv_curasid();
		break;
	case TLBINV_BY_ASID:
		secure_mmu_unifiedtlbinv_byasid(a);
		break;
	case TLBINV_BY_MVA:
		EMSG("TLB_INV_SECURE_MVA is not yet supported!");
		while (1)
			;
		secure_mmu_unifiedtlbinvbymva(a);
		break;
	default:
		return 1;
	}
	return 0;
}

unsigned int cache_maintenance_l1(int op, void *va, size_t len)
{
	switch (op) {
	case DCACHE_CLEAN:
		arm_cl1_d_cleanbysetway();
		break;
	case DCACHE_AREA_CLEAN:
		if (len)
			arm_cl1_d_cleanbyva(va, (char *)va + len - 1);
		break;
	case DCACHE_INVALIDATE:
		arm_cl1_d_invbysetway();
		break;
	case DCACHE_AREA_INVALIDATE:
		if (len)
			arm_cl1_d_invbyva(va, (char *)va + len - 1);
		break;
	case ICACHE_INVALIDATE:
		arm_cl1_i_inv_all();
		break;
	case ICACHE_AREA_INVALIDATE:
		if (len)
			arm_cl1_i_inv(va, (char *)va + len - 1);
		break;
	case WRITE_BUFFER_DRAIN:
		DMSG("unsupported operation 0x%X (WRITE_BUFFER_DRAIN)",
		     (unsigned int)op);
		return -1;
	case DCACHE_CLEAN_INV:
		arm_cl1_d_cleaninvbysetway();
		break;
	case DCACHE_AREA_CLEAN_INV:
		if (len)
			arm_cl1_d_cleaninvbyva(va, (char *)va + len - 1);
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
	return TEE_SUCCESS;
}

#ifdef CFG_PL310
unsigned int cache_maintenance_l2(int op, paddr_t pa, size_t len)
{
	unsigned int ret = TEE_SUCCESS;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_IRQ);

	tee_l2cc_mutex_lock();
	switch (op) {
	case L2CACHE_INVALIDATE:
		arm_cl2_invbyway();
		break;
	case L2CACHE_AREA_INVALIDATE:
		if (len)
			arm_cl2_invbypa(pa, pa + len - 1);
		break;
	case L2CACHE_CLEAN:
		arm_cl2_cleanbyway();
		break;
	case L2CACHE_AREA_CLEAN:
		if (len)
			arm_cl2_cleanbypa(pa, pa + len - 1);
		break;
	case L2CACHE_CLEAN_INV:
		arm_cl2_cleaninvbyway();
		break;
	case L2CACHE_AREA_CLEAN_INV:
		if (len)
			arm_cl2_cleaninvbypa(pa, pa + len - 1);
		break;
	default:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	tee_l2cc_mutex_unlock();
	thread_set_exceptions(exceptions);
	return ret;
}
#endif /*CFG_PL310*/

static bool arm_va2pa_helper(void *va, paddr_t *pa)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	paddr_t par;
	paddr_t par_pa_mask;
	bool ret = false;

#ifdef ARM32
	write_ats1cpw((vaddr_t)va);
	isb();
#ifdef CFG_WITH_LPAE
	par = read_par64();
	par_pa_mask = PAR64_PA_MASK;
#else
	par = read_par32();
	par_pa_mask = PAR32_PA_MASK;
#endif
#endif /*ARM32*/

#ifdef ARM64
	write_at_s1e1r((vaddr_t)va);
	isb();
	par = read_par_el1();
	par_pa_mask = PAR_PA_MASK;
#endif
	if (par & PAR_F)
		goto out;
	*pa = (par & (par_pa_mask << PAR_PA_SHIFT)) |
		((vaddr_t)va & ((1 << PAR_PA_SHIFT) - 1));

	ret = true;
out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

#if defined(CFG_TEE_CORE_DEBUG) && CFG_TEE_CORE_DEBUG != 0
static void check_pa_matches_va(void *va, paddr_t pa)
{
	TEE_Result res;
	vaddr_t user_va_base;
	size_t user_va_size;
	vaddr_t v = (vaddr_t)va;
	paddr_t p = 0;

	core_mmu_get_user_va_range(&user_va_base, &user_va_size);
	if (v >= user_va_base && v < (user_va_base + user_va_size)) {
		if (!core_mmu_user_mapping_is_active()) {
			TEE_ASSERT(pa == 0);
			return;
		}

		res = tee_mmu_user_va2pa_helper(
			to_user_ta_ctx(tee_mmu_get_ctx()), va, &p);
		if (res == TEE_SUCCESS)
			TEE_ASSERT(pa == p);
		else
			TEE_ASSERT(pa == 0);
		return;
	}
#ifdef CFG_WITH_PAGER
	if (v >= (CFG_TEE_LOAD_ADDR & ~CORE_MMU_PGDIR_MASK) &&
	    v <= (CFG_TEE_LOAD_ADDR | CORE_MMU_PGDIR_MASK)) {
		struct core_mmu_table_info *ti = &tee_pager_tbl_info;
		uint32_t a;

		/*
		 * Lookups in the page table managed by the pager is
		 * dangerous for addresses in the paged area as those pages
		 * changes all the time. But some ranges are safe, rw areas
		 * when the page is populated for instance.
		 */
		core_mmu_get_entry(ti, core_mmu_va2idx(ti, v), &p, &a);
		if (a & TEE_MATTR_VALID_BLOCK) {
			paddr_t mask = ((1 << ti->shift) - 1);

			p |= v & mask;
			TEE_ASSERT(pa == p);
		} else
			TEE_ASSERT(pa == 0);
		return;
	}
#endif
	if (v >= TEE_MMU_KMAP_START_VA && v < TEE_MMU_KMAP_END_VA) {
		void *void_pa;

		res = tee_mmu_kmap_va2pa_helper(va, &void_pa);
		if (res == TEE_SUCCESS)
			TEE_ASSERT(pa == (paddr_t)(uintptr_t)void_pa);
		else
			TEE_ASSERT(pa == 0);
		return;
	}
	if (!core_va2pa_helper(va, &p))
		TEE_ASSERT(pa == p);
	else
		TEE_ASSERT(pa == 0);
}
#else
static void check_pa_matches_va(void *va __unused, paddr_t pa __unused)
{
}
#endif

paddr_t virt_to_phys(void *va)
{
	paddr_t pa;

	if (!arm_va2pa_helper(va, &pa))
		pa = 0;
	check_pa_matches_va(va, pa);
	return pa;
}

#if defined(CFG_TEE_CORE_DEBUG) && CFG_TEE_CORE_DEBUG != 0
static void check_va_matches_pa(paddr_t pa, void *va)
{
	TEE_ASSERT(!va || virt_to_phys(va) == pa);
}
#else
static void check_va_matches_pa(paddr_t pa __unused, void *va __unused)
{
}
#endif

static void *phys_to_virt_ta_vaspace(paddr_t pa)
{
	TEE_Result res;
	void *va = NULL;

	if (!core_mmu_user_mapping_is_active())
		return NULL;

	res = tee_mmu_user_pa2va_helper(to_user_ta_ctx(tee_mmu_get_ctx()),
					pa, &va);
	if (res != TEE_SUCCESS)
		return NULL;
	return va;
}

static void *phys_to_virt_kmap_vaspace(paddr_t pa)
{
	void *va = NULL;
	TEE_Result res;

	res = tee_mmu_kmap_pa2va_helper((void *)(uintptr_t)pa, &va);
	if (res != TEE_SUCCESS)
		return NULL;
	return va;
}

#ifdef CFG_WITH_PAGER
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	unsigned idx;
	unsigned end_idx;
	uint32_t a;
	paddr_t p;

	end_idx = core_mmu_va2idx(ti, CFG_TEE_RAM_START +
				      CFG_TEE_RAM_VA_SIZE);
	/* Most addresses are mapped lineary, try that first if possible. */
	idx = core_mmu_va2idx(ti, pa);
	if (idx >= core_mmu_va2idx(ti, CFG_TEE_RAM_START) &&
	    idx < end_idx) {
		core_mmu_get_entry(ti, idx, &p, &a);
		if ((a & TEE_MATTR_VALID_BLOCK) && p == pa)
			return (void *)core_mmu_idx2va(ti, idx);
	}

	for (idx = core_mmu_va2idx(ti, CFG_TEE_RAM_START);
	     idx < end_idx; idx++) {
		core_mmu_get_entry(ti, idx, &p, &a);
		if ((a & TEE_MATTR_VALID_BLOCK) && p == pa)
			return (void *)core_mmu_idx2va(ti, idx);
	}

	return NULL;
}
#else
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	return map_pa2va(find_map_by_type(MEM_AREA_TEE_RAM), pa);
}
#endif

void *phys_to_virt(paddr_t pa, enum teecore_memtypes m)
{
	void *va;

	switch (m) {
	case MEM_AREA_TA_VASPACE:
		va = phys_to_virt_ta_vaspace(pa);
		break;
	case MEM_AREA_KMAP_VASPACE:
		va = phys_to_virt_kmap_vaspace(pa);
		break;
	case MEM_AREA_TEE_RAM:
		va = phys_to_virt_tee_ram(pa);
		break;
	default:
		va = map_pa2va(find_map_by_type(m), pa);
	}
	check_va_matches_pa(pa, va);
	return va;
}
