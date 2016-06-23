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
 * This core mmu supports static section mapping (1MByte) and finer mapping
 * with 4k pages.
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
#include <mm/pgt_cache.h>
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
#define RES_VASPACE_SIZE	(CORE_MMU_PGDIR_SIZE * 10)

/*
 * These variables are initialized before .bss is cleared. To avoid
 * resetting them when .bss is cleared we're storing them in .data instead,
 * even if they initially are zero.
 */

/* Default NSec shared memory allocated from NSec world */
unsigned long default_nsec_shm_size __data;
unsigned long default_nsec_shm_paddr __data;

static struct tee_mmap_region static_memory_map[MAX_MMAP_REGIONS + 1] __data;
static bool mem_map_inited __data;

static struct tee_mmap_region *map_tee_ram __data;
static struct tee_mmap_region *map_ta_ram __data;
static struct tee_mmap_region *map_nsec_shm __data;

/* Define the platform's memory layout. */
struct memaccess_area {
	paddr_t paddr;
	size_t size;
};
#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area ddr[] = {
	MEMACCESS_AREA(DRAM0_BASE, DRAM0_SIZE),
#ifdef DRAM1_BASE
	MEMACCESS_AREA(DRAM1_BASE, DRAM1_SIZE),
#endif
};

static struct memaccess_area secure_only[] = {
#ifdef TZSRAM_BASE
	MEMACCESS_AREA(TZSRAM_BASE, TZSRAM_SIZE),
#endif
	MEMACCESS_AREA(TZDRAM_BASE, TZDRAM_SIZE),
};

static struct memaccess_area nsec_shared[] = {
	MEMACCESS_AREA(CFG_SHMEM_START, CFG_SHMEM_SIZE),
};

register_phys_mem(MEM_AREA_TEE_RAM, CFG_TEE_RAM_START, CFG_TEE_RAM_PH_SIZE);
register_phys_mem(MEM_AREA_TA_RAM, CFG_TA_RAM_START, CFG_TA_RAM_SIZE);
register_phys_mem(MEM_AREA_NSEC_SHM, CFG_SHMEM_START, CFG_SHMEM_SIZE);
#ifdef DEVICE0_PA_BASE
register_phys_mem(DEVICE0_TYPE, DEVICE0_PA_BASE, DEVICE0_SIZE);
#endif
#ifdef DEVICE1_PA_BASE
register_phys_mem(DEVICE1_TYPE, DEVICE1_PA_BASE, DEVICE1_SIZE);
#endif
#ifdef DEVICE2_PA_BASE
register_phys_mem(DEVICE2_TYPE, DEVICE2_PA_BASE, DEVICE2_SIZE);
#endif
#ifdef DEVICE3_PA_BASE
register_phys_mem(DEVICE3_TYPE, DEVICE3_PA_BASE, DEVICE3_SIZE);
#endif
#ifdef DEVICE4_PA_BASE
register_phys_mem(DEVICE4_TYPE, DEVICE4_PA_BASE, DEVICE4_SIZE);
#endif
#ifdef DEVICE5_PA_BASE
register_phys_mem(DEVICE5_TYPE, DEVICE5_PA_BASE, DEVICE5_SIZE);
#endif
#ifdef DEVICE6_PA_BASE
register_phys_mem(DEVICE6_TYPE, DEVICE6_PA_BASE, DEVICE6_SIZE);
#endif

register_phys_mem(MEM_AREA_RES_VASPACE, 0, RES_VASPACE_SIZE);

static bool _pbuf_intersects(struct memaccess_area *a, size_t alen,
			     paddr_t pa, size_t size)
{
	size_t n;

	for (n = 0; n < alen; n++)
		if (core_is_buffer_intersect(pa, size, a[n].paddr, a[n].size))
			return true;
	return false;
}
#define pbuf_intersects(a, pa, size) \
	_pbuf_intersects((a), ARRAY_SIZE(a), (pa), (size))

static bool _pbuf_is_inside(struct memaccess_area *a, size_t alen,
			    paddr_t pa, size_t size)
{
	size_t n;

	for (n = 0; n < alen; n++)
		if (core_is_buffer_inside(pa, size, a[n].paddr, a[n].size))
			return true;
	return false;
}
#define pbuf_is_inside(a, pa, size) \
	_pbuf_is_inside((a), ARRAY_SIZE(a), (pa), (size))

static bool pbuf_is_multipurpose(paddr_t paddr, size_t size)
{
	if (pbuf_intersects(secure_only, paddr, size))
		return false;
	if (pbuf_intersects(nsec_shared, paddr, size))
		return false;

	return pbuf_is_inside(ddr, paddr, size);
}

static bool pa_is_in_map(struct tee_mmap_region *map, paddr_t pa)
{
	if (!map)
		return false;
	return (pa >= map->pa && pa <= (map->pa + map->size - 1));
}

static bool va_is_in_map(struct tee_mmap_region *map, vaddr_t va)
{
	if (!map)
		return false;
	return (va >= map->va && va <= (map->va + map->size - 1));
}

/* check if target buffer fits in a core default map area */
static bool pbuf_inside_map_area(unsigned long p, size_t l,
				 struct tee_mmap_region *map)
{
	return core_is_buffer_inside(p, l, map->pa, map->size);
}

static struct tee_mmap_region *find_map_by_type(enum teecore_memtypes type)
{
	struct tee_mmap_region *map;

	for (map = static_memory_map; map->type != MEM_AREA_NOTYPE; map++)
		if (map->type == type)
			return map;
	return NULL;
}

static struct tee_mmap_region *find_map_by_type_and_pa(
			enum teecore_memtypes type, paddr_t pa)
{
	struct tee_mmap_region *map;

	for (map = static_memory_map; map->type != MEM_AREA_NOTYPE; map++) {
		if (map->type != type)
			continue;
		if (pa_is_in_map(map, pa))
			return map;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_va(void *va)
{
	struct tee_mmap_region *map = static_memory_map;
	unsigned long a = (unsigned long)va;

	while (map->type != MEM_AREA_NOTYPE) {
		if ((a >= map->va) && (a <= (map->va - 1 + map->size)))
			return map;
		map++;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_pa(unsigned long pa)
{
	struct tee_mmap_region *map = static_memory_map;

	while (map->type != MEM_AREA_NOTYPE) {
		if ((pa >= map->pa) && (pa < (map->pa + map->size)))
			return map;
		map++;
	}
	return NULL;
}

extern const struct core_mmu_phys_mem __start_phys_mem_map_section;
extern const struct core_mmu_phys_mem __end_phys_mem_map_section;

static void add_phys_mem(struct tee_mmap_region *memory_map, size_t num_elems,
			 const struct core_mmu_phys_mem *mem, size_t *last)
{
	size_t n = 0;
	paddr_t pa;
	size_t size;

	/*
	 * When all entries are added we'd like to have it in a sorted
	 * array first based on memory type and secondly on physical
	 * address. If some ranges of memory of the same type overlaps of
	 * are next to each others they are coalesced into one entry. This
	 * makes it easier later when building the translation tables.
	 *
	 * Note that it's valid to have the same physical memory as several
	 * different memory types, for instance the same device memory
	 * mapped as both secure and non-secure. This will probably not
	 * happen often in practice.
	 */
	DMSG("%s %d 0x%08" PRIxPA " size 0x%08zx",
	     mem->name, mem->type, mem->addr, mem->size);
	while (true) {
		if (n >= (num_elems - 1)) {
			EMSG("Out of entries (%zu) in memory_map", num_elems);
			panic();
		}
		if (n == *last)
			break;
		pa = memory_map[n].pa;
		size = memory_map[n].size;
		if (mem->addr >= pa && mem->addr <= (pa + (size - 1)) &&
		    mem->type == memory_map[n].type) {
			DMSG("Physical mem map overlaps 0x%" PRIxPA, mem->addr);
			memory_map[n].pa = MIN(pa, mem->addr);
			memory_map[n].size = MAX(size, mem->size) +
					     (pa - memory_map[n].pa);
			return;
		}
		if (mem->type < memory_map[n].type ||
		    (mem->type == memory_map[n].type && mem->addr < pa))
			break; /* found the spot where to inseart this memory */
		n++;
	}

	memmove(memory_map + n + 1, memory_map + n,
		sizeof(struct tee_mmap_region) * (*last - n));
	(*last)++;
	memory_map[n].type = mem->type;
	memory_map[n].pa = mem->addr;
	memory_map[n].size = mem->size;
}

static uint32_t type_to_attr(enum teecore_memtypes t)
{
	const uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW |
			      TEE_MATTR_GLOBAL;
	const uint32_t cached = TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT;
	const uint32_t noncache = TEE_MATTR_CACHE_NONCACHE <<
				  TEE_MATTR_CACHE_SHIFT;

	switch (t) {
	case MEM_AREA_TEE_RAM:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PX | cached;
	case MEM_AREA_TA_RAM:
		return attr | TEE_MATTR_SECURE | cached;
	case MEM_AREA_NSEC_SHM:
		return attr | cached;
	case MEM_AREA_IO_NSEC:
		return attr | noncache;
	case MEM_AREA_IO_SEC:
		return attr | TEE_MATTR_SECURE | noncache;
	case MEM_AREA_RES_VASPACE:
		return 0;
	default:
		panic();
	}
}

static void init_mem_map(struct tee_mmap_region *memory_map, size_t num_elems)
{
	const struct core_mmu_phys_mem *mem;
	struct tee_mmap_region *map;
	size_t last = 0;
	vaddr_t va;
	size_t n;

	for (mem = &__start_phys_mem_map_section;
	     mem < &__end_phys_mem_map_section; mem++) {
		struct core_mmu_phys_mem m = *mem;

		if (m.type == MEM_AREA_IO_NSEC || m.type == MEM_AREA_IO_SEC) {
			m.addr = ROUNDDOWN(m.addr, CORE_MMU_PGDIR_SIZE);
			m.size = ROUNDUP(m.size + (mem->addr - m.addr),
					 CORE_MMU_PGDIR_SIZE);
		}
		add_phys_mem(memory_map, num_elems, &m, &last);
	}
	memory_map[last].type = MEM_AREA_NOTYPE;

	/*
	 * bootcfg_memory_map is sorted in order first by type and last by
	 * address. This puts TEE_RAM first and TA_RAM second
	 *
	 */

	map = memory_map;
	assert(map->type == MEM_AREA_TEE_RAM);
	map->va = map->pa;
#ifdef CFG_WITH_PAGER
	map->region_size = SMALL_PAGE_SIZE,
#else
	map->region_size = CORE_MMU_PGDIR_SIZE,
#endif
	map->attr = type_to_attr(map->type);

	if (core_mmu_place_tee_ram_at_top(map->pa)) {
		va = map->va;
		map++;
		while (map->type != MEM_AREA_NOTYPE) {
			map->attr = type_to_attr(map->type);
			map->region_size = CORE_MMU_PGDIR_SIZE,
			va = ROUNDDOWN(va - map->size, CORE_MMU_PGDIR_SIZE);
			map->va = va;
			map++;
		}
		/*
		 * The memory map should be sorted by virtual address
		 * when this function returns. As we're assigning va in
		 * the oposite direction we need to reverse the list.
		 */
		for (n = 0; n < last / 2; n++) {
			struct tee_mmap_region r;

			r = memory_map[last - n - 1];
			memory_map[last - n - 1] = memory_map[n];
			memory_map[n] = r;
		}
	} else {
		va = ROUNDUP(map->va + map->size, CORE_MMU_PGDIR_SIZE);
		map++;
		while (map->type != MEM_AREA_NOTYPE) {
			map->attr = type_to_attr(map->type);
			map->region_size = CORE_MMU_PGDIR_SIZE,
			map->va = va;
			va = ROUNDUP(va + map->size, CORE_MMU_PGDIR_SIZE);
			map++;
		}
	}

	for (map = memory_map; map->type != MEM_AREA_NOTYPE; map++)
		DMSG("type va %d 0x%08" PRIxVA "..0x%08" PRIxVA
		     " pa 0x%08" PRIxPA "..0x%08" PRIxPA " size %#zx",
		     map->type, (vaddr_t)map->va,
		     (vaddr_t)map->va + map->size - 1, (paddr_t)map->pa,
		     (paddr_t)map->pa + map->size - 1, map->size);
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
	struct tee_mmap_region *map;
	size_t n;

	for (n = 0; n < ARRAY_SIZE(secure_only); n++) {
		if (pbuf_intersects(nsec_shared, secure_only[n].paddr,
				    secure_only[n].size)) {
			EMSG("Invalid memory access configuration: sec/nsec");
			panic();
		}
	}

	if (!mem_map_inited)
		init_mem_map(static_memory_map, ARRAY_SIZE(static_memory_map));

	map = static_memory_map;
	while (map->type != MEM_AREA_NOTYPE) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size)) {
				EMSG("TEE_RAM does not fit in secure_only");
				panic();
			}
			map_tee_ram = map;
			break;
		case MEM_AREA_TA_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size)) {
				EMSG("TA_RAM does not fit in secure_only");
				panic();
			}
			map_ta_ram = map;
			break;
		case MEM_AREA_NSEC_SHM:
			if (!pbuf_is_inside(nsec_shared, map->pa, map->size)) {
				EMSG("NSEC_SHM does not fit in nsec_shared");
				panic();
			}
			map_nsec_shm = map;
			break;
		case MEM_AREA_IO_SEC:
		case MEM_AREA_IO_NSEC:
		case MEM_AREA_RES_VASPACE:
			break;
		default:
			EMSG("Uhandled memtype %d", map->type);
			panic();
		}
		map++;
	}

	/* Check that we have the mandatory memory areas defined */
	if (!map_tee_ram || !map_ta_ram || !map_nsec_shm) {
		EMSG("mapping area missing");
		panic();
	}

	core_init_mmu_tables(static_memory_map);
}

/* routines to retrieve shared mem configuration */
bool core_mmu_is_shm_cached(void)
{
	if (!map_nsec_shm)
		return false;
	return map_nsec_shm->attr >> TEE_MATTR_CACHE_SHIFT ==
	       TEE_MATTR_CACHE_CACHED;
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
	struct tee_mmap_region *map;

	/* Empty buffers complies with anything */
	if (len == 0)
		return true;

	switch (attr) {
	case CORE_MEM_SEC:
		return pbuf_is_inside(secure_only, pbuf, len);
	case CORE_MEM_NON_SEC:
		return pbuf_is_inside(nsec_shared, pbuf, len);
	case CORE_MEM_TEE_RAM:
		return pbuf_inside_map_area(pbuf, len, map_tee_ram);
	case CORE_MEM_TA_RAM:
		return pbuf_inside_map_area(pbuf, len, map_ta_ram);
	case CORE_MEM_NSEC_SHM:
		return pbuf_inside_map_area(pbuf, len, map_nsec_shm);
	case CORE_MEM_MULTPURPOSE:
		return pbuf_is_multipurpose(pbuf, len);
	case CORE_MEM_EXTRAM:
		return pbuf_is_inside(ddr, pbuf, len);
	case CORE_MEM_CACHED:
		map = find_map_by_pa(pbuf);
		if (map == NULL || !pbuf_inside_map_area(pbuf, len, map))
			return false;
		return map->attr >> TEE_MATTR_CACHE_SHIFT ==
		       TEE_MATTR_CACHE_CACHED;
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
	struct tee_mmap_region *map;

	map = find_map_by_va(va);
	if (!va_is_in_map(map, (vaddr_t)va))
		return -1;

	*pa = ((uintptr_t)va & (map->region_size - 1)) |
	    ((map->pa + (uintptr_t)va - map->va) & ~(map->region_size - 1));
	return 0;
}

static void *map_pa2va(struct tee_mmap_region *map, paddr_t pa)
{
	if (!pa_is_in_map(map, pa))
		return NULL;
	return (void *)((pa & (map->region_size - 1)) |
		(((map->va + pa - map->pa)) & ~(map->region_size - 1)));
}

/*
 * teecore gets some memory area definitions
 */
void core_mmu_get_mem_by_type(unsigned int type, vaddr_t *s, vaddr_t *e)
{
	struct tee_mmap_region *map = find_map_by_type(type);

	if (map) {
		*s = map->va;
		*e = map->va + map->size;
	} else {
		*s = 0;
		*e = 0;
	}
}

enum teecore_memtypes core_mmu_get_type_by_pa(paddr_t pa)
{
	struct tee_mmap_region *map = find_map_by_pa(pa);

	if (!map)
		return MEM_AREA_NOTYPE;
	return map->type;
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
		arm_cl2_invbyway(pl310_base());
		break;
	case L2CACHE_AREA_INVALIDATE:
		if (len)
			arm_cl2_invbypa(pl310_base(), pa, pa + len - 1);
		break;
	case L2CACHE_CLEAN:
		arm_cl2_cleanbyway(pl310_base());
		break;
	case L2CACHE_AREA_CLEAN:
		if (len)
			arm_cl2_cleanbypa(pl310_base(), pa, pa + len - 1);
		break;
	case L2CACHE_CLEAN_INV:
		arm_cl2_cleaninvbyway(pl310_base());
		break;
	case L2CACHE_AREA_CLEAN_INV:
		if (len)
			arm_cl2_cleaninvbypa(pl310_base(), pa, pa + len - 1);
		break;
	default:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	tee_l2cc_mutex_unlock();
	thread_set_exceptions(exceptions);
	return ret;
}
#endif /*CFG_PL310*/

void core_mmu_set_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
			paddr_t pa, uint32_t attr)
{
	assert(idx < tbl_info->num_entries);
	core_mmu_set_entry_primitive(tbl_info->table, tbl_info->level,
				     idx, pa, attr);
}

void core_mmu_get_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
			paddr_t *pa, uint32_t *attr)
{
	assert(idx < tbl_info->num_entries);
	core_mmu_get_entry_primitive(tbl_info->table, tbl_info->level,
				     idx, pa, attr);
}

static void set_region(struct core_mmu_table_info *tbl_info,
		struct tee_mmap_region *region)
{
	unsigned end;
	unsigned idx;
	paddr_t pa;

	/* va, len and pa should be block aligned */
	assert(!core_mmu_get_block_offset(tbl_info, region->va));
	assert(!core_mmu_get_block_offset(tbl_info, region->size));
	assert(!core_mmu_get_block_offset(tbl_info, region->pa));

	idx = core_mmu_va2idx(tbl_info, region->va);
	end = core_mmu_va2idx(tbl_info, region->va + region->size);
	pa = region->pa;

	while (idx < end) {
		core_mmu_set_entry(tbl_info, idx, pa, region->attr);
		idx++;
		pa += 1 << tbl_info->shift;
	}
}

#ifdef CFG_SMALL_PAGE_USER_TA
static void set_pg_region(struct core_mmu_table_info *dir_info,
			struct tee_mmap_region *region, struct pgt **pgt,
			struct core_mmu_table_info *pg_info)
{
	struct tee_mmap_region r = *region;
	vaddr_t end = r.va + r.size;
	uint32_t pgt_attr = (r.attr & TEE_MATTR_SECURE) | TEE_MATTR_TABLE;

	while (r.va < end) {
		if (!pg_info->table ||
		     r.va >= (pg_info->va_base + CORE_MMU_PGDIR_SIZE)) {
			/*
			 * We're assigning a new translation table.
			 */
			unsigned int idx;

			assert(*pgt); /* We should have alloced enough */

			/* Virtual addresses must grow */
			assert(r.va > pg_info->va_base);

			idx = core_mmu_va2idx(dir_info, r.va);
			pg_info->table = (*pgt)->tbl;
			pg_info->va_base = core_mmu_idx2va(dir_info, idx);
			*pgt = SLIST_NEXT(*pgt, link);

			memset(pg_info->table, 0, PGT_SIZE);
			core_mmu_set_entry(dir_info, idx,
					   virt_to_phys(pg_info->table),
					    pgt_attr);
		}

		r.size = MIN(CORE_MMU_PGDIR_SIZE - (r.va - pg_info->va_base),
			     end - r.va);
		set_region(pg_info, &r);
		r.va += r.size;
		r.pa += r.size;
	}
}

void core_mmu_populate_user_map(struct core_mmu_table_info *dir_info,
				struct user_ta_ctx *utc)
{
	struct core_mmu_table_info pg_info;
	struct pgt_cache *pgt_cache = &thread_get_tsd()->pgt_cache;
	struct pgt *pgt;
	size_t n;
	vaddr_t base;
	vaddr_t end;

	if (!utc->mmu->size)
		return;	/* Nothing to map */

	/* Find the last valid entry */
	n = utc->mmu->size;
	while (true) {
		n--;
		if (utc->mmu->table[n].size)
			break;
		if (!n)
			return;	/* Nothing to map */
	}

	/*
	 * Allocate all page tables in advance.
	 */
	base = ROUNDDOWN(utc->mmu->table[0].va, CORE_MMU_PGDIR_SIZE);
	end = ROUNDUP(utc->mmu->table[n].va + utc->mmu->table[n].size,
		      CORE_MMU_PGDIR_SIZE);
	pgt_alloc(pgt_cache, (end - base) >> CORE_MMU_PGDIR_SHIFT);
	pgt = SLIST_FIRST(pgt_cache);

	core_mmu_set_info_table(&pg_info, dir_info->level + 1, 0, NULL);

	for (n = 0; n < utc->mmu->size; n++) {
		if (!utc->mmu->table[n].size)
			continue;
		set_pg_region(dir_info, utc->mmu->table + n, &pgt, &pg_info);
	}
}

#else
void core_mmu_populate_user_map(struct core_mmu_table_info *dir_info,
				struct user_ta_ctx *utc)
{
	unsigned n;

	for (n = 0; n < utc->mmu->size; n++) {
		if (!utc->mmu->table[n].size)
			continue;
		set_region(dir_info, utc->mmu->table + n);
	}
}
#endif

bool core_mmu_add_mapping(enum teecore_memtypes type, paddr_t addr, size_t len)
{
	struct core_mmu_table_info tbl_info;
	struct tee_mmap_region *map;
	size_t n;
	size_t granule;
	paddr_t p;
	size_t l;

	if (!len)
		return true;

	/* Check if the memory is already mapped */
	map = find_map_by_type_and_pa(type, addr);
	if (map && pbuf_inside_map_area(addr, len, map))
		return true;

	/* Find the reserved va space used for late mappings */
	map = find_map_by_type(MEM_AREA_RES_VASPACE);
	if (!map)
		return false;

	if (!core_mmu_find_table(map->va, UINT_MAX, &tbl_info))
		return false;

	granule = 1 << tbl_info.shift;
	p = ROUNDDOWN(addr, granule);
	l = ROUNDUP(len + addr - p, granule);
	/*
	 * Something is wrong, we can't fit the va range into the selected
	 * table. The reserved va range is possibly missaligned with
	 * granule.
	 */
	if (core_mmu_va2idx(&tbl_info, map->va + len) >= tbl_info.num_entries)
		return false;

	/* Find end of the memory map */
	n = 0;
	while (static_memory_map[n].type != MEM_AREA_NOTYPE)
		n++;

	if (n < (ARRAY_SIZE(static_memory_map) - 1)) {
		/* There's room for another entry */
		static_memory_map[n].va = map->va;
		static_memory_map[n].size = l;
		static_memory_map[n + 1].type = MEM_AREA_NOTYPE;
		map->va += l;
		map->size -= l;
		map = static_memory_map + n;
	} else {
		/*
		 * There isn't room for another entry, steal the reserved
		 * entry as it's not useful for anything else any longer.
		 */
		map->size = l;
	}
	map->type = type;
	map->region_size = granule;
	map->attr = type_to_attr(type);
	map->pa = p;

	set_region(&tbl_info, map);
	return true;
}

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
	if (v >= user_va_base && v <= (user_va_base - 1 + user_va_size)) {
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
	if (v >= CFG_TEE_LOAD_ADDR && v < core_mmu_linear_map_end) {
		TEE_ASSERT(v == pa);
		return;
	}
	if (v >= (CFG_TEE_LOAD_ADDR & ~CORE_MMU_PGDIR_MASK) &&
	    v <= (CFG_TEE_LOAD_ADDR | CORE_MMU_PGDIR_MASK)) {
		struct core_mmu_table_info *ti = &tee_pager_tbl_info;
		uint32_t a;

		/*
		 * Lookups in the page table managed by the pager is
		 * dangerous for addresses in the paged area as those pages
		 * changes all the time. But some ranges are safe,
		 * rw-locked areas when the page is populated for instance.
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

#ifdef CFG_WITH_PAGER
vaddr_t core_mmu_linear_map_end;
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	unsigned idx;
	unsigned end_idx;
	uint32_t a;
	paddr_t p;

	if (pa >= CFG_TEE_LOAD_ADDR && pa < core_mmu_linear_map_end)
		return (void *)(vaddr_t)pa;

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
	return map_pa2va(find_map_by_type_and_pa(MEM_AREA_TEE_RAM, pa), pa);
}
#endif

void *phys_to_virt(paddr_t pa, enum teecore_memtypes m)
{
	void *va;

	switch (m) {
	case MEM_AREA_TA_VASPACE:
		va = phys_to_virt_ta_vaspace(pa);
		break;
	case MEM_AREA_TEE_RAM:
		va = phys_to_virt_tee_ram(pa);
		break;
	default:
		va = map_pa2va(find_map_by_type_and_pa(m, pa), pa);
	}
	check_va_matches_pa(pa, va);
	return va;
}

bool cpu_mmu_enabled(void)
{
	uint32_t sctlr;

#ifdef ARM32
	sctlr =  read_sctlr();
#else
	sctlr =  read_sctlr_el1();
#endif

	return sctlr & SCTLR_M ? true : false;
}
