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

#include <arm.h>
#include <assert.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tz_ssvce.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <stdlib.h>
#include <trace.h>
#include <util.h>

#include "core_mmu_private.h"

#define MAX_MMAP_REGIONS	10
#define RES_VASPACE_SIZE	(CORE_MMU_PGDIR_SIZE * 10)

/*
 * These variables are initialized before .bss is cleared. To avoid
 * resetting them when .bss is cleared we're storing them in .data instead,
 * even if they initially are zero.
 */

/* Default NSec shared memory allocated from NSec world */
unsigned long default_nsec_shm_size __early_bss;
unsigned long default_nsec_shm_paddr __early_bss;

static struct tee_mmap_region
	static_memory_map[MAX_MMAP_REGIONS + 1] __early_bss;
static bool mem_map_inited __early_bss;

static struct tee_mmap_region *map_tee_ram __early_bss;
static struct tee_mmap_region *map_ta_ram __early_bss;
static struct tee_mmap_region *map_nsec_shm __early_bss;

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

#ifdef CFG_TEE_SDP_MEM_BASE
register_sdp_mem(CFG_TEE_SDP_MEM_BASE, CFG_TEE_SDP_MEM_SIZE);
#endif

register_phys_mem(MEM_AREA_TEE_RAM, CFG_TEE_RAM_START, CFG_TEE_RAM_PH_SIZE);
register_phys_mem(MEM_AREA_TA_RAM, CFG_TA_RAM_START, CFG_TA_RAM_SIZE);
register_phys_mem(MEM_AREA_NSEC_SHM, CFG_SHMEM_START, CFG_SHMEM_SIZE);

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

#ifdef CFG_SECURE_DATA_PATH
extern const struct core_mmu_phys_mem __start_phys_sdp_mem_section;
extern const struct core_mmu_phys_mem __end_phys_sdp_mem_section;

static bool pbuf_is_sdp_mem(paddr_t pbuf, size_t len)
{
	const struct core_mmu_phys_mem *mem;

	for (mem = &__start_phys_sdp_mem_section;
	     mem < &__end_phys_sdp_mem_section; mem++)
		if (core_is_buffer_inside(pbuf, len, mem->addr, mem->size))
			return true;

	return false;
}

#define MSG_SDP_INSTERSECT(pa1, sz1, pa2, sz2) \
	EMSG("[%" PRIxPA " %" PRIxPA "] intersecs [%" PRIxPA " %" PRIxPA "]", \
			pa1, pa1 + sz1, pa2, pa2 + sz2)

/* Check SDP memories comply with registered memories */
static void verify_sdp_mem_areas(struct tee_mmap_region *mem_map, size_t len)
{
	const struct core_mmu_phys_mem *mem;
	const struct core_mmu_phys_mem *mem2;
	const struct core_mmu_phys_mem *start = &__start_phys_sdp_mem_section;
	const struct core_mmu_phys_mem *end = &__end_phys_sdp_mem_section;
	struct tee_mmap_region *mmap;
	size_t n;

	if (start == end) {
		IMSG("Secure data path enabled without any SDP memory area");
		return;
	}

	for (mem = start; mem < end; mem++)
		DMSG("SDP memory [%" PRIxPA " %" PRIxPA "]",
			mem->addr, mem->addr + mem->size);

	/* Check SDP memories do not intersect each other */
	for (mem = start; mem < end - 1; mem++) {
		for (mem2 = mem + 1; mem2 < end; mem2++) {
			if (core_is_buffer_intersect(mem2->addr, mem2->size,
						     mem->addr, mem->size)) {
				MSG_SDP_INSTERSECT(mem2->addr, mem2->size,
						   mem->addr, mem->size);
				panic("SDP memory intersection");
			}
		}
	}

	/*
	 * Check SDP memories do not intersect any mapped memory.
	 * This is called before reserved VA space is loaded in mem_map.
	 */
	for (mem = start; mem < end; mem++) {
		for (mmap = mem_map, n = 0; n < len; mmap++, n++) {
			if (core_is_buffer_intersect(mem->addr, mem->size,
						     mmap->pa, mmap->size)) {
				MSG_SDP_INSTERSECT(mem->addr, mem->size,
						   mmap->pa, mmap->size);
				panic("SDP memory intersection");
			}
		}
	}
}

struct mobj **core_sdp_mem_create_mobjs(void)
{
	const struct core_mmu_phys_mem *mem;
	struct mobj **mobj_base;
	struct mobj **mobj;
	int cnt = &__end_phys_sdp_mem_section - &__start_phys_sdp_mem_section;

	/* SDP mobjs table must end with a NULL entry */
	mobj_base = calloc(cnt + 1, sizeof(struct mobj *));
	if (!mobj_base)
		panic("Out of memory");

	for (mem = &__start_phys_sdp_mem_section, mobj = mobj_base;
	     mem < &__end_phys_sdp_mem_section; mem++, mobj++) {
		 *mobj = mobj_phys_alloc(mem->addr, mem->size,
					 TEE_MATTR_CACHE_CACHED,
					 CORE_MEM_SDP_MEM);
		if (!*mobj)
			panic("can't create SDP physical memory object");
	}
	return mobj_base;
}
#else /* CFG_SECURE_DATA_PATH */
static bool pbuf_is_sdp_mem(paddr_t pbuf __unused, size_t len __unused)
{
	return false;
}

static void verify_sdp_mem_areas(struct tee_mmap_region *mem_map __unused,
				 size_t len __unused)
{
}
#endif /* CFG_SECURE_DATA_PATH */

extern const struct core_mmu_phys_mem __start_phys_mem_map_section;
extern const struct core_mmu_phys_mem __end_phys_mem_map_section;

static void add_phys_mem(struct tee_mmap_region *memory_map, size_t num_elems,
			 const struct core_mmu_phys_mem *mem, size_t *last)
{
	size_t n = 0;
	paddr_t pa;
	size_t size;

	/*
	 * If some ranges of memory of the same type do overlap
	 * each others they are coalesced into one entry. To help this
	 * added entries are sorted by increasing physical.
	 *
	 * Note that it's valid to have the same physical memory as several
	 * different memory types, for instance the same device memory
	 * mapped as both secure and non-secure. This will probably not
	 * happen often in practice.
	 */
	DMSG("%s type %s 0x%08" PRIxPA " size 0x%08zx",
	     mem->name, teecore_memtype_name(mem->type), mem->addr, mem->size);
	while (true) {
		if (n >= (num_elems - 1)) {
			EMSG("Out of entries (%zu) in memory_map", num_elems);
			panic();
		}
		if (n == *last)
			break;
		pa = memory_map[n].pa;
		size = memory_map[n].size;
		if (mem->type == memory_map[n].type &&
		    ((mem->addr >= pa && mem->addr <= (pa + (size - 1))) ||
		    (pa >= mem->addr && pa <= (mem->addr + (mem->size - 1))))) {
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
	memset(memory_map + n, 0, sizeof(memory_map[0]));
	memory_map[n].type = mem->type;
	memory_map[n].pa = mem->addr;
	memory_map[n].size = mem->size;
}

static void add_va_space(struct tee_mmap_region *memory_map, size_t num_elems,
			 enum teecore_memtypes type, size_t size, size_t *last)
{
	size_t n = 0;

	DMSG("type %s size 0x%08zx", teecore_memtype_name(type), size);
	while (true) {
		if (n >= (num_elems - 1)) {
			EMSG("Out of entries (%zu) in memory_map", num_elems);
			panic();
		}
		if (n == *last)
			break;
		if (type < memory_map[n].type)
			break;
		n++;
	}

	memmove(memory_map + n + 1, memory_map + n,
		sizeof(struct tee_mmap_region) * (*last - n));
	(*last)++;
	memset(memory_map + n, 0, sizeof(memory_map[0]));
	memory_map[n].type = type;
	memory_map[n].size = size;
}

uint32_t core_mmu_type_to_attr(enum teecore_memtypes t)
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
	case MEM_AREA_RAM_NSEC:
		return attr | cached;
	case MEM_AREA_RAM_SEC:
		return attr | TEE_MATTR_SECURE | cached;
	case MEM_AREA_RES_VASPACE:
		return 0;
	default:
		panic("invalid type");
	}
}

static bool __maybe_unused map_is_tee_ram(const struct tee_mmap_region *mm)
{
	return mm->type == MEM_AREA_TEE_RAM;
}

static bool map_is_flat_mapped(const struct tee_mmap_region *mm)
{
	return map_is_tee_ram(mm);
}

static bool __maybe_unused map_is_secure(const struct tee_mmap_region *mm)
{
	return !!(core_mmu_type_to_attr(mm->type) & TEE_MATTR_SECURE);
}

static bool __maybe_unused map_is_pgdir(const struct tee_mmap_region *mm)
{
	return mm->region_size == CORE_MMU_PGDIR_SIZE;
}

static int cmp_mmap_by_lower_va(const void *a, const void *b)
{
	const struct tee_mmap_region *mm_a = a;
	const struct tee_mmap_region *mm_b = b;

	return mm_a->va - mm_b->va;
}

static int __maybe_unused cmp_mmap_by_secure_attr(const void *a, const void *b)
{
	const struct tee_mmap_region *mm_a = a;
	const struct tee_mmap_region *mm_b = b;

	/* unmapped areas are special */
	if (!core_mmu_type_to_attr(mm_a->type) ||
	    !core_mmu_type_to_attr(mm_b->type))
		return 0;

	return map_is_secure(mm_b) - map_is_secure(mm_a);
}

static int cmp_mmap_by_bigger_region_size(const void *a, const void *b)
{
	const struct tee_mmap_region *mm_a = a;
	const struct tee_mmap_region *mm_b = b;

	return mm_b->region_size - mm_a->region_size;
}

static void dump_mmap_table(struct tee_mmap_region *memory_map)
{
	struct tee_mmap_region *map;

	for (map = memory_map; map->type != MEM_AREA_NOTYPE; map++) {
		vaddr_t __maybe_unused vstart;

		vstart = map->va + ((vaddr_t)map->pa & (map->region_size - 1));
		DMSG("type %-12s va 0x%08" PRIxVA "..0x%08" PRIxVA
		     " pa 0x%08" PRIxPA "..0x%08" PRIxPA " size 0x%08zx (%s)",
		     teecore_memtype_name(map->type), vstart,
		     vstart + map->size - 1, map->pa,
		     (paddr_t)(map->pa + map->size - 1), map->size,
		     map->region_size == SMALL_PAGE_SIZE ? "smallpg" : "pgdir");
	}
}

static void init_mem_map(struct tee_mmap_region *memory_map, size_t num_elems)
{
	const struct core_mmu_phys_mem *mem;
	struct tee_mmap_region *map;
	size_t last = 0;
	size_t __maybe_unused count = 0;
	vaddr_t va;
	vaddr_t __maybe_unused end;

	for (mem = &__start_phys_mem_map_section;
	     mem < &__end_phys_mem_map_section; mem++) {
		struct core_mmu_phys_mem m = *mem;

		if (!m.size)
			continue;

		/* Only unmapped virtual range may have a null phys addr */
		assert(m.addr || !core_mmu_type_to_attr(m.type));

		if (m.type == MEM_AREA_IO_NSEC || m.type == MEM_AREA_IO_SEC) {
			m.addr = ROUNDDOWN(m.addr, CORE_MMU_PGDIR_SIZE);
			m.size = ROUNDUP(m.size + (mem->addr - m.addr),
					 CORE_MMU_PGDIR_SIZE);
		}
		add_phys_mem(memory_map, num_elems, &m, &last);
	}

	verify_sdp_mem_areas(memory_map, num_elems);

	add_va_space(memory_map, num_elems, MEM_AREA_RES_VASPACE,
		     RES_VASPACE_SIZE, &last);

	memory_map[last].type = MEM_AREA_NOTYPE;

	/*
	 * Assign region sizes, note that MEM_AREA_TEE_RAM always uses
	 * SMALL_PAGE_SIZE if paging is enabled.
	 */
	for (map = memory_map; map->type != MEM_AREA_NOTYPE; map++) {
		paddr_t mask = map->pa | map->size;

		if (!(mask & CORE_MMU_PGDIR_MASK))
			map->region_size = CORE_MMU_PGDIR_SIZE;
		else if (!(mask & SMALL_PAGE_MASK))
			map->region_size = SMALL_PAGE_SIZE;
		else
			panic("Impossible memory alignment");

#ifdef CFG_WITH_PAGER
		if (map_is_tee_ram(map))
			map->region_size = SMALL_PAGE_SIZE;
#endif
	}

	/*
	 * To ease mapping and lower use of xlat tables, sort mapping
	 * description moving small-page regions after the pgdir regions.
	 */
	qsort(memory_map, last, sizeof(struct tee_mmap_region),
		cmp_mmap_by_bigger_region_size);

#if !defined(CFG_WITH_LPAE)
	/*
	 * 32bit MMU descriptors cannot mix secure and non-secure mapping in
	 * the same level2 table. Hence sort secure mapping from non-secure
	 * mapping.
	 */
	for (count = 0, map = memory_map; map_is_pgdir(map); count++, map++)
		;

	qsort(memory_map + count, last - count, sizeof(struct tee_mmap_region),
		cmp_mmap_by_secure_attr);
#endif

	/*
	 * Map flat mapped addresses first.
	 * 'va' will store the lower address of the flat-mapped areas to later
	 * setup the virtual mapping of the non flat-mapped areas.
	 */
	va = (vaddr_t)~0UL;
	end = 0;
	for (map = memory_map; map->type != MEM_AREA_NOTYPE; map++) {
		if (!map_is_flat_mapped(map))
			continue;

		map->attr = core_mmu_type_to_attr(map->type);
		map->va = map->pa;
		va = MIN(va, ROUNDDOWN(map->va, map->region_size));
		end = MAX(end, ROUNDUP(map->va + map->size, map->region_size));
	}
	assert(va >= CFG_TEE_RAM_START);
	assert(end <= CFG_TEE_RAM_START + CFG_TEE_RAM_VA_SIZE);

	if (core_mmu_place_tee_ram_at_top(va)) {
		/* Map non-flat mapped addresses below flat mapped addresses */
		for (map = memory_map; map->type != MEM_AREA_NOTYPE; map++) {
			if (map_is_flat_mapped(map))
				continue;

			map->attr = core_mmu_type_to_attr(map->type);
			va -= map->size;
			va = ROUNDDOWN(va, map->region_size);
			map->va = va;
		}
	} else {
		/* Map non-flat mapped addresses above flat mapped addresses */
		va = ROUNDUP(va + CFG_TEE_RAM_VA_SIZE, CORE_MMU_PGDIR_SIZE);
		for (map = memory_map; map->type != MEM_AREA_NOTYPE; map++) {
			if (map_is_flat_mapped(map))
				continue;

			map->attr = core_mmu_type_to_attr(map->type);
			va = ROUNDUP(va, map->region_size);
			map->va = va;
			va += map->size;
		}
	}

	qsort(memory_map, last, sizeof(struct tee_mmap_region),
		cmp_mmap_by_lower_va);

	dump_mmap_table(memory_map);
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
				    secure_only[n].size))
			panic("Invalid memory access config: sec/nsec");
	}

	if (!mem_map_inited)
		init_mem_map(static_memory_map, ARRAY_SIZE(static_memory_map));

	map = static_memory_map;
	while (map->type != MEM_AREA_NOTYPE) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size))
				panic("TEE_RAM can't fit in secure_only");

			map_tee_ram = map;
			break;
		case MEM_AREA_TA_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size))
				panic("TA_RAM can't fit in secure_only");
			map_ta_ram = map;
			break;
		case MEM_AREA_NSEC_SHM:
			if (!pbuf_is_inside(nsec_shared, map->pa, map->size))
				panic("NS_SHM can't fit in nsec_shared");
			map_nsec_shm = map;
			break;
		case MEM_AREA_IO_SEC:
		case MEM_AREA_IO_NSEC:
		case MEM_AREA_RAM_SEC:
		case MEM_AREA_RAM_NSEC:
		case MEM_AREA_RES_VASPACE:
			break;
		default:
			EMSG("Uhandled memtype %d", map->type);
			panic();
		}
		map++;
	}

	/* Check that we have the mandatory memory areas defined */
	if (!map_tee_ram || !map_ta_ram || !map_nsec_shm)
		panic("mandatory area(s) not found");

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
bool core_pbuf_is(uint32_t attr, paddr_t pbuf, size_t len)
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
	case CORE_MEM_SDP_MEM:
		return pbuf_is_sdp_mem(pbuf, len);
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
		((map->va + pa - map->pa) & ~((vaddr_t)map->region_size - 1)));
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

TEE_Result cache_op_inner(enum cache_op op, void *va, size_t len)
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
TEE_Result cache_op_outer(enum cache_op op, paddr_t pa, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	tee_l2cc_mutex_lock();
	switch (op) {
	case DCACHE_INVALIDATE:
		arm_cl2_invbyway(pl310_base());
		break;
	case DCACHE_AREA_INVALIDATE:
		if (len)
			arm_cl2_invbypa(pl310_base(), pa, pa + len - 1);
		break;
	case DCACHE_CLEAN:
		arm_cl2_cleanbyway(pl310_base());
		break;
	case DCACHE_AREA_CLEAN:
		if (len)
			arm_cl2_cleanbypa(pl310_base(), pa, pa + len - 1);
		break;
	case DCACHE_CLEAN_INV:
		arm_cl2_cleaninvbyway(pl310_base());
		break;
	case DCACHE_AREA_CLEAN_INV:
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
			struct tee_ta_region *region, struct pgt **pgt,
			struct core_mmu_table_info *pg_info)
{
	struct tee_mmap_region r = {
		.va = region->va,
		.size = region->size,
		.attr = region->attr,
	};
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
#ifdef CFG_PAGED_USER_TA
			assert((*pgt)->vabase == pg_info->va_base);
#endif
			*pgt = SLIST_NEXT(*pgt, link);

			core_mmu_set_entry(dir_info, idx,
					   virt_to_phys(pg_info->table),
					   pgt_attr);
		}

		r.size = MIN(CORE_MMU_PGDIR_SIZE - (r.va - pg_info->va_base),
			     end - r.va);
		if (!mobj_is_paged(region->mobj)) {
			size_t granule = BIT(pg_info->shift);
			size_t offset = r.va - region->va + region->offset;

			if (mobj_get_pa(region->mobj, offset, granule,
					&r.pa) != TEE_SUCCESS)
				panic("Failed to get PA of unpaged mobj");
			set_region(pg_info, &r);
		}
		r.va += r.size;
	}
}

void core_mmu_populate_user_map(struct core_mmu_table_info *dir_info,
				struct user_ta_ctx *utc)
{
	struct core_mmu_table_info pg_info;
	struct pgt_cache *pgt_cache = &thread_get_tsd()->pgt_cache;
	struct pgt *pgt;
	size_t n;

	/* Find the last valid entry */
	n = ARRAY_SIZE(utc->mmu->regions);
	while (true) {
		n--;
		if (utc->mmu->regions[n].size)
			break;
		if (!n)
			return;	/* Nothing to map */
	}

	/*
	 * Allocate all page tables in advance.
	 */
	pgt_alloc(pgt_cache, &utc->ctx, utc->mmu->regions[0].va,
		  utc->mmu->regions[n].va + utc->mmu->regions[n].size - 1);
	pgt = SLIST_FIRST(pgt_cache);

	core_mmu_set_info_table(&pg_info, dir_info->level + 1, 0, NULL);

	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++)
		mobj_update_mapping(utc->mmu->regions[n].mobj, utc,
				    utc->mmu->regions[n].va);

	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		if (!utc->mmu->regions[n].size)
			continue;
		set_pg_region(dir_info, utc->mmu->regions + n, &pgt, &pg_info);
	}
}

#else
void core_mmu_populate_user_map(struct core_mmu_table_info *dir_info,
				struct user_ta_ctx *utc)
{
	unsigned n;
	struct tee_mmap_region r;
	size_t offset;
	size_t granule = BIT(dir_info->shift);

	memset(&r, 0, sizeof(r));
	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		if (!utc->mmu->regions[n].size)
			continue;

		offset = utc->mmu->regions[n].offset;
		r.va = utc->mmu->regions[n].va;
		r.size = utc->mmu->regions[n].size;
		r.attr = utc->mmu->regions[n].attr;

		if (mobj_get_pa(utc->mmu->regions[n].mobj, offset, granule,
				&r.pa) != TEE_SUCCESS)
			panic("Failed to get PA of unpaged mobj");

		set_region(dir_info, &r);
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
	map->attr = core_mmu_type_to_attr(type);
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
	write_ats1cpr((vaddr_t)va);
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

#ifdef CFG_WITH_PAGER
static vaddr_t get_linear_map_end(void)
{
	/* this is synced with the generic linker file kern.ld.S */
	return (vaddr_t)__heap2_end;
}
#endif

#if defined(CFG_TEE_CORE_DEBUG)
static void check_pa_matches_va(void *va, paddr_t pa)
{
	TEE_Result res;
	vaddr_t v = (vaddr_t)va;
	paddr_t p = 0;

	if (core_mmu_user_va_range_is_defined()) {
		vaddr_t user_va_base;
		size_t user_va_size;

		core_mmu_get_user_va_range(&user_va_base, &user_va_size);
		if (v >= user_va_base &&
		    v <= (user_va_base - 1 + user_va_size)) {
			if (!core_mmu_user_mapping_is_active()) {
				if (pa)
					panic("issue in linear address space");
				return;
			}

			res = tee_mmu_user_va2pa_helper(
				to_user_ta_ctx(tee_mmu_get_ctx()), va, &p);
			if (res == TEE_SUCCESS && pa != p)
				panic("bad pa");
			if (res != TEE_SUCCESS && pa)
				panic("false pa");
			return;
		}
	}
#ifdef CFG_WITH_PAGER
	if (v >= CFG_TEE_LOAD_ADDR && v < get_linear_map_end()) {
		if (v != pa)
			panic("issue in linear address space");
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
			if (pa != p)
				panic();
		} else
			if (pa)
				panic();
		return;
	}
#endif
	if (!core_va2pa_helper(va, &p)) {
		if (pa != p)
			panic();
	} else {
		if (pa)
			panic();
	}
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

#if defined(CFG_TEE_CORE_DEBUG)
static void check_va_matches_pa(paddr_t pa, void *va)
{
	if (va && virt_to_phys(va) != pa)
		panic();
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
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	unsigned idx;
	unsigned end_idx;
	uint32_t a;
	paddr_t p;

	if (pa >= CFG_TEE_LOAD_ADDR && pa < get_linear_map_end())
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

void *phys_to_virt_io(paddr_t pa)
{
	struct tee_mmap_region *map;
	void *va;

	map = find_map_by_type_and_pa(MEM_AREA_IO_SEC, pa);
	if (!map)
		map = find_map_by_type_and_pa(MEM_AREA_IO_NSEC, pa);
	if (!map)
		return NULL;
	va = map_pa2va(map, pa);
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
