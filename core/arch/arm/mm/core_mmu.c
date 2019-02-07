// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <bitstring.h>
#include <kernel/cache_helpers.h>
#include <kernel/generic_boot.h>
#include <kernel/linker.h>
#include <kernel/panic.h>
#include <kernel/virtualization.h>
#include <kernel/spinlock.h>
#include <kernel/tlb_helpers.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
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

#ifndef DEBUG_XLAT_TABLE
#define DEBUG_XLAT_TABLE 0
#endif

#define SHM_VASPACE_SIZE	(1024 * 1024 * 32)

/*
 * These variables are initialized before .bss is cleared. To avoid
 * resetting them when .bss is cleared we're storing them in .data instead,
 * even if they initially are zero.
 */

#ifdef CFG_CORE_RESERVED_SHM
/* Default NSec shared memory allocated from NSec world */
unsigned long default_nsec_shm_size __nex_bss;
unsigned long default_nsec_shm_paddr __nex_bss;
#endif

static struct tee_mmap_region
	static_memory_map[CFG_MMAP_REGIONS + 1] __nex_bss;

/* Define the platform's memory layout. */
struct memaccess_area {
	paddr_t paddr;
	size_t size;
};
#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area secure_only[] __nex_data = {
#ifdef TZSRAM_BASE
	MEMACCESS_AREA(TZSRAM_BASE, TZSRAM_SIZE),
#endif
	MEMACCESS_AREA(TZDRAM_BASE, TZDRAM_SIZE),
};

static struct memaccess_area nsec_shared[] __nex_data = {
#ifdef CFG_CORE_RESERVED_SHM
	MEMACCESS_AREA(TEE_SHMEM_START, TEE_SHMEM_SIZE),
#endif
};

#if defined(CFG_SECURE_DATA_PATH)
#ifdef CFG_TEE_SDP_MEM_BASE
register_sdp_mem(CFG_TEE_SDP_MEM_BASE, CFG_TEE_SDP_MEM_SIZE);
#endif
#ifdef TEE_SDP_TEST_MEM_BASE
register_sdp_mem(TEE_SDP_TEST_MEM_BASE, TEE_SDP_TEST_MEM_SIZE);
#endif
#endif

#ifdef CFG_CORE_RWDATA_NOEXEC
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, TEE_RAM_START,
		     VCORE_UNPG_RX_PA - TEE_RAM_START);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RX, VCORE_UNPG_RX_PA, VCORE_UNPG_RX_SZ);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, VCORE_UNPG_RO_PA, VCORE_UNPG_RO_SZ);

#ifdef CFG_VIRTUALIZATION
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, VCORE_UNPG_RW_PA, VCORE_UNPG_RW_SZ);
register_phys_mem_ul(MEM_AREA_NEX_RAM_RW, VCORE_NEX_RW_PA, VCORE_NEX_RW_SZ);
#else
register_phys_mem_ul(MEM_AREA_TEE_RAM_RW, VCORE_UNPG_RW_PA, VCORE_UNPG_RW_SZ);
#endif

#ifdef CFG_WITH_PAGER
register_phys_mem_ul(MEM_AREA_TEE_RAM_RX, VCORE_INIT_RX_PA, VCORE_INIT_RX_SZ);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, VCORE_INIT_RO_PA, VCORE_INIT_RO_SZ);
#endif /*CFG_WITH_PAGER*/
#else /*!CFG_CORE_RWDATA_NOEXEC*/
register_phys_mem(MEM_AREA_TEE_RAM, TEE_RAM_START, TEE_RAM_PH_SIZE);
#endif /*!CFG_CORE_RWDATA_NOEXEC*/

#ifdef CFG_VIRTUALIZATION
register_phys_mem(MEM_AREA_SEC_RAM_OVERALL, TZDRAM_BASE, TZDRAM_SIZE);
#endif

#if defined(CFG_CORE_SANITIZE_KADDRESS) && defined(CFG_WITH_PAGER)
/* Asan ram is part of MEM_AREA_TEE_RAM_RW when pager is disabled */
register_phys_mem_ul(MEM_AREA_TEE_ASAN, ASAN_MAP_PA, ASAN_MAP_SZ);
#endif

#ifndef CFG_VIRTUALIZATION
/* Every guest will have own TA RAM if virtualization support is enabled */
register_phys_mem(MEM_AREA_TA_RAM, TA_RAM_START, TA_RAM_SIZE);
#endif
#ifdef CFG_CORE_RESERVED_SHM
register_phys_mem(MEM_AREA_NSEC_SHM, TEE_SHMEM_START, TEE_SHMEM_SIZE);
#endif

/*
 * Two ASIDs per context, one for kernel mode and one for user mode. ASID 0
 * and 1 are reserved and not used. This means a maximum of 126 loaded user
 * mode contexts. This value can be increased but not beyond the maximum
 * ASID, which is architecture dependent (max 255 for ARMv7-A and ARMv8-A
 * Aarch32). This constant defines number of ASID pairs.
 */
#define MMU_NUM_ASID_PAIRS		64

static bitstr_t bit_decl(g_asid, MMU_NUM_ASID_PAIRS) __nex_bss;
static unsigned int g_asid_spinlock __nex_bss = SPINLOCK_UNLOCK;

static unsigned int mmu_spinlock;

static uint32_t mmu_lock(void)
{
	return cpu_spin_lock_xsave(&mmu_spinlock);
}

static void mmu_unlock(uint32_t exceptions)
{
	cpu_spin_unlock_xrestore(&mmu_spinlock, exceptions);
}

static struct tee_mmap_region *get_memory_map(void)
{
#ifdef CFG_VIRTUALIZATION
	struct tee_mmap_region *map = virt_get_memory_map();

	if (map)
		return map;
#endif
	return static_memory_map;

}

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

	for (map = get_memory_map(); !core_mmap_is_end_of_table(map); map++)
		if (map->type == type)
			return map;
	return NULL;
}

static struct tee_mmap_region *find_map_by_type_and_pa(
			enum teecore_memtypes type, paddr_t pa)
{
	struct tee_mmap_region *map;

	for (map = get_memory_map(); !core_mmap_is_end_of_table(map); map++) {
		if (map->type != type)
			continue;
		if (pa_is_in_map(map, pa))
			return map;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_va(void *va)
{
	struct tee_mmap_region *map = get_memory_map();
	unsigned long a = (unsigned long)va;

	while (!core_mmap_is_end_of_table(map)) {
		if ((a >= map->va) && (a <= (map->va - 1 + map->size)))
			return map;
		map++;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_pa(unsigned long pa)
{
	struct tee_mmap_region *map = get_memory_map();

	while (!core_mmap_is_end_of_table(map)) {
		if ((pa >= map->pa) && (pa < (map->pa + map->size)))
			return map;
		map++;
	}
	return NULL;
}

static bool pbuf_is_special_mem(paddr_t pbuf, size_t len,
				const struct core_mmu_phys_mem *start,
				const struct core_mmu_phys_mem *end)
{
	const struct core_mmu_phys_mem *mem;

	for (mem = start; mem < end; mem++) {
		if (core_is_buffer_inside(pbuf, len, mem->addr, mem->size))
			return true;
	}

	return false;
}

#ifdef CFG_CORE_DYN_SHM
static void carve_out_phys_mem(struct core_mmu_phys_mem **mem, size_t *nelems,
			       paddr_t pa, size_t size)
{
	struct core_mmu_phys_mem *m = *mem;
	size_t n = 0;

	while (true) {
		if (n >= *nelems) {
			DMSG("No need to carve out %#" PRIxPA " size %#zx",
			     pa, size);
			return;
		}
		if (core_is_buffer_inside(pa, size, m[n].addr, m[n].size))
			break;
		if (!core_is_buffer_outside(pa, size, m[n].addr, m[n].size))
			panic();
		n++;
	}

	if (pa == m[n].addr && size == m[n].size) {
		/* Remove this entry */
		(*nelems)--;
		memmove(m + n, m + n + 1, sizeof(*m) * (*nelems - n));
		m = realloc(m, sizeof(*m) * *nelems);
		if (!m)
			panic();
		*mem = m;
	} else if (pa == m[n].addr) {
		m[n].addr += size;
	} else if ((pa + size) == (m[n].addr + m[n].size)) {
		m[n].size -= size;
	} else {
		/* Need to split the memory entry */
		m = realloc(m, sizeof(*m) * (*nelems + 1));
		if (!m)
			panic();
		*mem = m;
		memmove(m + n + 1, m + n, sizeof(*m) * (*nelems - n));
		(*nelems)++;
		m[n].size = pa - m[n].addr;
		m[n + 1].size -= size + m[n].size;
		m[n + 1].addr = pa + size;
	}
}

static void check_phys_mem_is_outside(struct core_mmu_phys_mem *start,
				      size_t nelems,
				      struct tee_mmap_region *map)
{
	size_t n;

	for (n = 0; n < nelems; n++) {
		if (!core_is_buffer_outside(start[n].addr, start[n].size,
					    map->pa, map->size)) {
			EMSG("Non-sec mem (%#" PRIxPA ":%#" PRIxPASZ
			     ") overlaps map (type %d %#" PRIxPA ":%#zx)",
			     start[n].addr, start[n].size,
			     map->type, map->pa, map->size);
			panic();
		}
	}
}

static const struct core_mmu_phys_mem *discovered_nsec_ddr_start __nex_bss;
static size_t discovered_nsec_ddr_nelems __nex_bss;

static int cmp_pmem_by_addr(const void *a, const void *b)
{
	const struct core_mmu_phys_mem *pmem_a = a;
	const struct core_mmu_phys_mem *pmem_b = b;

	return CMP_TRILEAN(pmem_a->addr, pmem_b->addr);
}

void core_mmu_set_discovered_nsec_ddr(struct core_mmu_phys_mem *start,
				      size_t nelems)
{
	struct core_mmu_phys_mem *m = start;
	size_t num_elems = nelems;
	struct tee_mmap_region *map = static_memory_map;
	const struct core_mmu_phys_mem __maybe_unused *pmem;
	paddr_t pa;

	assert(!discovered_nsec_ddr_start);
	assert(m && num_elems);

	qsort(m, num_elems, sizeof(*m), cmp_pmem_by_addr);

	/*
	 * Non-secure shared memory and also secure data
	 * path memory are supposed to reside inside
	 * non-secure memory. Since NSEC_SHM and SDP_MEM
	 * are used for a specific purpose make holes for
	 * those memory in the normal non-secure memory.
	 *
	 * This has to be done since for instance QEMU
	 * isn't aware of which memory range in the
	 * non-secure memory is used for NSEC_SHM.
	 */

#ifdef CFG_SECURE_DATA_PATH
	for (pmem = phys_sdp_mem_begin; pmem < phys_sdp_mem_end; pmem++)
		carve_out_phys_mem(&m, &num_elems, pmem->addr, pmem->size);
#endif

	for (map = static_memory_map; core_mmap_is_end_of_table(map); map++) {
		if (map->type == MEM_AREA_NSEC_SHM)
			carve_out_phys_mem(&m, &num_elems, map->pa, map->size);
		else
			check_phys_mem_is_outside(m, num_elems, map);
	}

	discovered_nsec_ddr_start = m;
	discovered_nsec_ddr_nelems = num_elems;

	if (ADD_OVERFLOW(m[num_elems - 1].addr, m[num_elems - 1].size - 1, &pa))
		panic();
	core_mmu_set_max_pa(pa);
}

static bool get_discovered_nsec_ddr(const struct core_mmu_phys_mem **start,
				    const struct core_mmu_phys_mem **end)
{
	if (!discovered_nsec_ddr_start)
		return false;

	*start = discovered_nsec_ddr_start;
	*end = discovered_nsec_ddr_start + discovered_nsec_ddr_nelems;

	return true;
}

static bool pbuf_is_nsec_ddr(paddr_t pbuf, size_t len)
{
	const struct core_mmu_phys_mem *start;
	const struct core_mmu_phys_mem *end;

	if (!get_discovered_nsec_ddr(&start, &end)) {
		start = phys_nsec_ddr_begin;
		end = phys_nsec_ddr_end;
	}

	return pbuf_is_special_mem(pbuf, len, start, end);
}

bool core_mmu_nsec_ddr_is_defined(void)
{
	const struct core_mmu_phys_mem *start;
	const struct core_mmu_phys_mem *end;

	if (!get_discovered_nsec_ddr(&start, &end)) {
		start = phys_nsec_ddr_begin;
		end = phys_nsec_ddr_end;
	}

	return start != end;
}
#else
static bool pbuf_is_nsec_ddr(paddr_t pbuf __unused, size_t len __unused)
{
	return false;
}
#endif /*CFG_CORE_DYN_SHM*/

#define MSG_MEM_INSTERSECT(pa1, sz1, pa2, sz2) \
	EMSG("[%" PRIxPA " %" PRIx64 "] intersects [%" PRIxPA " %" PRIx64 "]", \
			pa1, (uint64_t)pa1 + sz1, pa2, (uint64_t)pa2 + sz2)

#ifdef CFG_SECURE_DATA_PATH
static bool pbuf_is_sdp_mem(paddr_t pbuf, size_t len)
{
	return pbuf_is_special_mem(pbuf, len, phys_sdp_mem_begin,
				   phys_sdp_mem_end);
}

struct mobj **core_sdp_mem_create_mobjs(void)
{
	const struct core_mmu_phys_mem *mem;
	struct mobj **mobj_base;
	struct mobj **mobj;
	int cnt = phys_sdp_mem_end - phys_sdp_mem_begin;

	/* SDP mobjs table must end with a NULL entry */
	mobj_base = calloc(cnt + 1, sizeof(struct mobj *));
	if (!mobj_base)
		panic("Out of memory");

	for (mem = phys_sdp_mem_begin, mobj = mobj_base;
	     mem < phys_sdp_mem_end; mem++, mobj++) {
		*mobj = mobj_phys_alloc(mem->addr, mem->size,
					TEE_MATTR_CACHE_CACHED,
					CORE_MEM_SDP_MEM);
		if (!*mobj)
			panic("can't create SDP physical memory object");
	}
	return mobj_base;
}

static void check_sdp_intersection_with_nsec_ddr(void)
{
	const struct core_mmu_phys_mem *sdp_start = phys_sdp_mem_begin;
	const struct core_mmu_phys_mem *sdp_end = phys_sdp_mem_end;
	const struct core_mmu_phys_mem *ddr_start = phys_nsec_ddr_begin;
	const struct core_mmu_phys_mem *ddr_end = phys_nsec_ddr_end;
	const struct core_mmu_phys_mem *sdp;
	const struct core_mmu_phys_mem *nsec_ddr;

	if (sdp_start == sdp_end || ddr_start == ddr_end)
		return;

	for (sdp = sdp_start; sdp < sdp_end; sdp++) {
		for (nsec_ddr = ddr_start; nsec_ddr < ddr_end; nsec_ddr++) {
			if (core_is_buffer_intersect(sdp->addr, sdp->size,
					     nsec_ddr->addr, nsec_ddr->size)) {
				MSG_MEM_INSTERSECT(sdp->addr, sdp->size,
						   nsec_ddr->addr,
						   nsec_ddr->size);
				panic("SDP <-> NSEC DDR memory intersection");
			}
		}
	}
}

#else /* CFG_SECURE_DATA_PATH */
static bool pbuf_is_sdp_mem(paddr_t pbuf __unused, size_t len __unused)
{
	return false;
}

#endif /* CFG_SECURE_DATA_PATH */

/* Check special memories comply with registered memories */
static void verify_special_mem_areas(struct tee_mmap_region *mem_map,
				     size_t len,
				     const struct core_mmu_phys_mem *start,
				     const struct core_mmu_phys_mem *end,
				     const char *area_name __maybe_unused)
{
	const struct core_mmu_phys_mem *mem;
	const struct core_mmu_phys_mem *mem2;
	struct tee_mmap_region *mmap;
	size_t n;

	if (start == end) {
		DMSG("No %s memory area defined", area_name);
		return;
	}

	for (mem = start; mem < end; mem++)
		DMSG("%s memory [%" PRIxPA " %" PRIx64 "]",
		     area_name, mem->addr, (uint64_t)mem->addr + mem->size);

	/* Check memories do not intersect each other */
	for (mem = start; mem < end - 1; mem++) {
		for (mem2 = mem + 1; mem2 < end; mem2++) {
			if (core_is_buffer_intersect(mem2->addr, mem2->size,
						     mem->addr, mem->size)) {
				MSG_MEM_INSTERSECT(mem2->addr, mem2->size,
						   mem->addr, mem->size);
				panic("Special memory intersection");
			}
		}
	}

	/*
	 * Check memories do not intersect any mapped memory.
	 * This is called before reserved VA space is loaded in mem_map.
	 *
	 * Only exception is with MEM_AREA_RAM_NSEC and MEM_AREA_NSEC_SHM,
	 * which may overlap since they are used for the same purpose
	 * except that MEM_AREA_NSEC_SHM is always mapped and
	 * MEM_AREA_RAM_NSEC only uses a dynamic mapping.
	 */
	for (mem = start; mem < end; mem++) {
		for (mmap = mem_map, n = 0; n < len; mmap++, n++) {
			if (mem->type == MEM_AREA_RAM_NSEC &&
			    mmap->type == MEM_AREA_NSEC_SHM)
				continue;
			if (core_is_buffer_intersect(mem->addr, mem->size,
						     mmap->pa, mmap->size)) {
				MSG_MEM_INSTERSECT(mem->addr, mem->size,
						   mmap->pa, mmap->size);
				panic("Special memory intersection");
			}
		}
	}
}

static void add_phys_mem(struct tee_mmap_region *memory_map, size_t num_elems,
			 const struct core_mmu_phys_mem *mem, size_t *last)
{
	size_t n = 0;
	paddr_t pa;
	paddr_size_t size;

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
	DMSG("%s type %s 0x%08" PRIxPA " size 0x%08" PRIxPASZ,
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
		    ((pa <= (mem->addr + (mem->size - 1))) &&
		    (mem->addr <= (pa + (size - 1))))) {
			DMSG("Physical mem map overlaps 0x%" PRIxPA, mem->addr);
			memory_map[n].pa = MIN(pa, mem->addr);
			memory_map[n].size = MAX(size, mem->size) +
					     (pa - memory_map[n].pa);
			return;
		}
		if (mem->type < memory_map[n].type ||
		    (mem->type == memory_map[n].type && mem->addr < pa))
			break; /* found the spot where to insert this memory */
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
	const uint32_t attr = TEE_MATTR_VALID_BLOCK;
	const uint32_t cached = TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT;
	const uint32_t noncache = TEE_MATTR_CACHE_NONCACHE <<
				  TEE_MATTR_CACHE_SHIFT;

	switch (t) {
	case MEM_AREA_TEE_RAM:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRWX | cached;
	case MEM_AREA_TEE_RAM_RX:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRX | cached;
	case MEM_AREA_TEE_RAM_RO:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PR | cached;
	case MEM_AREA_TEE_RAM_RW:
	case MEM_AREA_NEX_RAM_RW:
	case MEM_AREA_TEE_ASAN:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | cached;
	case MEM_AREA_TEE_COHERENT:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRWX | noncache;
	case MEM_AREA_TA_RAM:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | cached;
	case MEM_AREA_NSEC_SHM:
		return attr | TEE_MATTR_PRW | cached;
	case MEM_AREA_IO_NSEC:
		return attr | TEE_MATTR_PRW | noncache;
	case MEM_AREA_IO_SEC:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | noncache;
	case MEM_AREA_RAM_NSEC:
		return attr | TEE_MATTR_PRW | cached;
	case MEM_AREA_RAM_SEC:
	case MEM_AREA_SEC_RAM_OVERALL:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | cached;
	case MEM_AREA_RES_VASPACE:
	case MEM_AREA_SHM_VASPACE:
		return 0;
	case MEM_AREA_PAGER_VASPACE:
		return TEE_MATTR_SECURE;
	default:
		panic("invalid type");
	}
}

static bool __maybe_unused map_is_tee_ram(const struct tee_mmap_region *mm)
{
	switch (mm->type) {
	case MEM_AREA_TEE_RAM:
	case MEM_AREA_TEE_RAM_RX:
	case MEM_AREA_TEE_RAM_RO:
	case MEM_AREA_TEE_RAM_RW:
	case MEM_AREA_NEX_RAM_RW:
	case MEM_AREA_TEE_ASAN:
		return true;
	default:
		return false;
	}
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

	return CMP_TRILEAN(mm_a->va, mm_b->va);
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

	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
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

#if DEBUG_XLAT_TABLE

static void dump_xlat_table(vaddr_t va, int level)
{
	struct core_mmu_table_info tbl_info;
	unsigned int idx = 0;
	paddr_t pa;
	uint32_t attr;

	core_mmu_find_table(NULL, va, level, &tbl_info);
	va = tbl_info.va_base;
	for (idx = 0; idx < tbl_info.num_entries; idx++) {
		core_mmu_get_entry(&tbl_info, idx, &pa, &attr);
		if (attr || level > 1) {
			if (attr & TEE_MATTR_TABLE) {
#ifdef CFG_WITH_LPAE
				DMSG_RAW("%*s [LVL%d] VA:0x%010" PRIxVA
					" TBL:0x%010" PRIxPA "\n",
					level * 2, "", level, va, pa);
#else
				DMSG_RAW("%*s [LVL%d] VA:0x%010" PRIxVA
					" TBL:0x%010" PRIxPA " %s\n",
					level * 2, "", level, va, pa,
					attr & TEE_MATTR_SECURE ? " S" : "NS");
#endif
				dump_xlat_table(va, level + 1);
			} else if (attr) {
				DMSG_RAW("%*s [LVL%d] VA:0x%010" PRIxVA
					" PA:0x%010" PRIxPA " %s-%s-%s-%s",
					level * 2, "", level, va, pa,
					attr & (TEE_MATTR_CACHE_CACHED <<
					TEE_MATTR_CACHE_SHIFT) ? "MEM" : "DEV",
					attr & TEE_MATTR_PW ? "RW" : "RO",
					attr & TEE_MATTR_PX ? "X " : "XN",
					attr & TEE_MATTR_SECURE ? " S" : "NS");
			} else {
				DMSG_RAW("%*s [LVL%d] VA:0x%010" PRIxVA
					    " INVALID\n",
					    level * 2, "", level, va);
			}
		}
		va += 1 << tbl_info.shift;
	}
}

#else

static void dump_xlat_table(vaddr_t va __unused, int level __unused)
{
}

#endif

static void add_pager_vaspace(struct tee_mmap_region *mmap, size_t num_elems,
			      vaddr_t begin, vaddr_t *end, size_t *last)
{
	size_t size = TEE_RAM_VA_SIZE - (*end - begin);
	size_t n;
	size_t pos = 0;

	if (!size)
		return;

	if (*last >= (num_elems - 1)) {
		EMSG("Out of entries (%zu) in memory map", num_elems);
		panic();
	}

	for (n = 0; !core_mmap_is_end_of_table(mmap + n); n++)
		if (map_is_flat_mapped(mmap + n))
			pos = n + 1;

	assert(pos <= *last);
	memmove(mmap + pos + 1, mmap + pos,
		sizeof(struct tee_mmap_region) * (*last - pos));
	(*last)++;
	memset(mmap + pos, 0, sizeof(mmap[0]));
	mmap[pos].type = MEM_AREA_PAGER_VASPACE;
	mmap[pos].va = *end;
	mmap[pos].size = size;
	mmap[pos].region_size = SMALL_PAGE_SIZE;
	mmap[pos].attr = core_mmu_type_to_attr(MEM_AREA_PAGER_VASPACE);

	*end += size;
}

static void init_mem_map(struct tee_mmap_region *memory_map, size_t num_elems)
{
	const struct core_mmu_phys_mem *mem;
	struct tee_mmap_region *map;
	size_t last = 0;
	size_t __maybe_unused count = 0;
	vaddr_t va;
	vaddr_t end;
	bool __maybe_unused va_is_secure = true; /* any init value fits */

	for (mem = phys_mem_map_begin; mem < phys_mem_map_end; mem++) {
		struct core_mmu_phys_mem m = *mem;

		/* Discard null size entries */
		if (!m.size)
			continue;

		/* Only unmapped virtual range may have a null phys addr */
		assert(m.addr || !core_mmu_type_to_attr(m.type));

		add_phys_mem(memory_map, num_elems, &m, &last);
	}

#ifdef CFG_SECURE_DATA_PATH
	verify_special_mem_areas(memory_map, num_elems, phys_sdp_mem_begin,
				 phys_sdp_mem_end, "SDP");

	check_sdp_intersection_with_nsec_ddr();
#endif

	verify_special_mem_areas(memory_map, num_elems, phys_nsec_ddr_begin,
				 phys_nsec_ddr_end, "NSEC DDR");

	add_va_space(memory_map, num_elems, MEM_AREA_RES_VASPACE,
		     CFG_RESERVED_VASPACE_SIZE, &last);

	add_va_space(memory_map, num_elems, MEM_AREA_SHM_VASPACE,
		     SHM_VASPACE_SIZE, &last);

	memory_map[last].type = MEM_AREA_END;

	/*
	 * Assign region sizes, note that MEM_AREA_TEE_RAM always uses
	 * SMALL_PAGE_SIZE if paging is enabled.
	 */
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
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
	 * 'va' (resp. 'end') will store the lower (reps. higher) address of
	 * the flat-mapped areas to later setup the virtual mapping of the non
	 * flat-mapped areas.
	 */
	va = (vaddr_t)~0UL;
	end = 0;
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
		if (!map_is_flat_mapped(map))
			continue;

		map->attr = core_mmu_type_to_attr(map->type);
		map->va = map->pa;
		va = MIN(va, ROUNDDOWN(map->va, map->region_size));
		end = MAX(end, ROUNDUP(map->va + map->size, map->region_size));
	}
	assert(va >= TEE_RAM_VA_START);
	assert(end <= TEE_RAM_VA_START + TEE_RAM_VA_SIZE);

	add_pager_vaspace(memory_map, num_elems, va, &end, &last);

	assert(!((va | end) & SMALL_PAGE_MASK));

	if (core_mmu_place_tee_ram_at_top(va)) {
		/* Map non-flat mapped addresses below flat mapped addresses */
		for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
			if (map->va)
				continue;

#if !defined(CFG_WITH_LPAE)
			if (va_is_secure != map_is_secure(map)) {
				va_is_secure = !va_is_secure;
				va = ROUNDDOWN(va, CORE_MMU_PGDIR_SIZE);
			}
#endif
			map->attr = core_mmu_type_to_attr(map->type);
			va -= map->size;
			va = ROUNDDOWN(va, map->region_size);
			/*
			 * Make sure that va is aligned with pa for
			 * efficient pgdir mapping. Basically pa &
			 * pgdir_mask should be == va & pgdir_mask
			 */
			if (map->size > 2 * CORE_MMU_PGDIR_SIZE)
				va -= CORE_MMU_PGDIR_SIZE -
					((map->pa - va) & CORE_MMU_PGDIR_MASK);
			map->va = va;
		}
	} else {
		/* Map non-flat mapped addresses above flat mapped addresses */
		va = end;
		for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
			if (map->va)
				continue;

#if !defined(CFG_WITH_LPAE)
			if (va_is_secure != map_is_secure(map)) {
				va_is_secure = !va_is_secure;
				va = ROUNDUP(va, CORE_MMU_PGDIR_SIZE);
			}
#endif
			map->attr = core_mmu_type_to_attr(map->type);
			va = ROUNDUP(va, map->region_size);
			/*
			 * Make sure that va is aligned with pa for
			 * efficient pgdir mapping. Basically pa &
			 * pgdir_mask should be == va & pgdir_mask
			 */
			if (map->size > 2 * CORE_MMU_PGDIR_SIZE)
				va += (map->pa - va) & CORE_MMU_PGDIR_MASK;

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

	COMPILE_TIME_ASSERT(CFG_MMAP_REGIONS >= 13);
	init_mem_map(static_memory_map, ARRAY_SIZE(static_memory_map));

	map = static_memory_map;
	while (!core_mmap_is_end_of_table(map)) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
		case MEM_AREA_TEE_RAM_RX:
		case MEM_AREA_TEE_RAM_RO:
		case MEM_AREA_TEE_RAM_RW:
		case MEM_AREA_NEX_RAM_RW:
			if (!pbuf_is_inside(secure_only, map->pa, map->size))
				panic("TEE_RAM can't fit in secure_only");
			break;
		case MEM_AREA_TA_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size))
				panic("TA_RAM can't fit in secure_only");
			break;
		case MEM_AREA_NSEC_SHM:
			if (!pbuf_is_inside(nsec_shared, map->pa, map->size))
				panic("NS_SHM can't fit in nsec_shared");
			break;
		case MEM_AREA_SEC_RAM_OVERALL:
		case MEM_AREA_TEE_COHERENT:
		case MEM_AREA_TEE_ASAN:
		case MEM_AREA_IO_SEC:
		case MEM_AREA_IO_NSEC:
		case MEM_AREA_RAM_SEC:
		case MEM_AREA_RAM_NSEC:
		case MEM_AREA_RES_VASPACE:
		case MEM_AREA_SHM_VASPACE:
		case MEM_AREA_PAGER_VASPACE:
			break;
		default:
			EMSG("Uhandled memtype %d", map->type);
			panic();
		}
		map++;
	}

	core_init_mmu(static_memory_map);
	dump_xlat_table(0x0, 1);
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
		return pbuf_is_inside(nsec_shared, pbuf, len) ||
			pbuf_is_nsec_ddr(pbuf, len);
	case CORE_MEM_TEE_RAM:
		return core_is_buffer_inside(pbuf, len, TEE_RAM_START,
							TEE_RAM_PH_SIZE);
	case CORE_MEM_TA_RAM:
		return core_is_buffer_inside(pbuf, len, TA_RAM_START,
							TA_RAM_SIZE);
	case CORE_MEM_NSEC_SHM:
		return core_is_buffer_inside(pbuf, len, TEE_SHMEM_START,
							TEE_SHMEM_SIZE);
	case CORE_MEM_SDP_MEM:
		return pbuf_is_sdp_mem(pbuf, len);
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
static int __maybe_unused core_va2pa_helper(void *va, paddr_t *pa)
{
	struct tee_mmap_region *map;

	map = find_map_by_va(va);
	if (!va_is_in_map(map, (vaddr_t)va))
		return -1;

	/*
	 * We can calculate PA for static map. Virtual address ranges
	 * reserved to core dynamic mapping return a 'match' (return 0;)
	 * together with an invalid null physical address.
	 */
	if (map->pa)
		*pa = map->pa + (vaddr_t)va  - map->va;
	else
		*pa = 0;

	return 0;
}

static void *map_pa2va(struct tee_mmap_region *map, paddr_t pa)
{
	if (!pa_is_in_map(map, pa))
		return NULL;

	return (void *)(vaddr_t)(map->va + pa - map->pa);
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
		return MEM_AREA_MAXTYPE;
	return map->type;
}

int __deprecated core_tlb_maintenance(int op, unsigned long a)
{
	switch (op) {
	case TLBINV_UNIFIEDTLB:
		tlbi_all();
		break;
	case TLBINV_CURRENT_ASID:
#ifdef ARM32
		tlbi_asid(read_contextidr());
#endif
#ifdef ARM64
		tlbi_asid(read_contextidr_el1());
#endif
		break;
	case TLBINV_BY_ASID:
		tlbi_asid(a);
		break;
	case TLBINV_BY_MVA:
		panic();
	default:
		return 1;
	}
	return 0;
}

void tlbi_mva_range(vaddr_t va, size_t size, size_t granule)
{
	size_t sz = size;

	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);

	dsb_ishst();
	while (sz) {
		tlbi_mva_allasid_nosync(va);
		if (sz < granule)
			break;
		sz -= granule;
		va += granule;
	}
	dsb_ish();
	isb();
}

TEE_Result cache_op_inner(enum cache_op op, void *va, size_t len)
{
	switch (op) {
	case DCACHE_CLEAN:
		dcache_op_all(DCACHE_OP_CLEAN);
		break;
	case DCACHE_AREA_CLEAN:
		dcache_clean_range(va, len);
		break;
	case DCACHE_INVALIDATE:
		dcache_op_all(DCACHE_OP_INV);
		break;
	case DCACHE_AREA_INVALIDATE:
		dcache_inv_range(va, len);
		break;
	case ICACHE_INVALIDATE:
		icache_inv_all();
		break;
	case ICACHE_AREA_INVALIDATE:
		icache_inv_range(va, len);
		break;
	case DCACHE_CLEAN_INV:
		dcache_op_all(DCACHE_OP_CLEAN_INV);
		break;
	case DCACHE_AREA_CLEAN_INV:
		dcache_cleaninv_range(va, len);
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

static void set_pg_region(struct core_mmu_table_info *dir_info,
			struct vm_region *region, struct pgt **pgt,
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

			r.size = MIN(r.size,
				     mobj_get_phys_granule(region->mobj));
			r.size = ROUNDUP(r.size, SMALL_PAGE_SIZE);

			if (mobj_get_pa(region->mobj, offset, granule,
					&r.pa) != TEE_SUCCESS)
				panic("Failed to get PA of unpaged mobj");
			set_region(pg_info, &r);
		}
		r.va += r.size;
	}
}

static bool can_map_at_level(paddr_t paddr, vaddr_t vaddr,
			     size_t size_left, paddr_t block_size,
			     struct tee_mmap_region *mm __maybe_unused)
{

	/* VA and PA are aligned to block size at current level */
	if ((vaddr | paddr) & (block_size - 1))
		return false;

	/* Remainder fits into block at current level */
	if (size_left < block_size)
		return false;

#ifdef CFG_WITH_PAGER
	/*
	 * If pager is enabled, we need to map tee ram
	 * regions with small pages only
	 */
	if (map_is_tee_ram(mm) && block_size != SMALL_PAGE_SIZE)
		return false;
#endif

	return true;
}

void core_mmu_map_region(struct mmu_partition *prtn, struct tee_mmap_region *mm)
{
	struct core_mmu_table_info tbl_info;
	unsigned int idx;
	vaddr_t vaddr = mm->va;
	paddr_t paddr = mm->pa;
	ssize_t size_left = mm->size;
	int level;
	bool table_found;
	uint32_t old_attr;

	assert(!((vaddr | paddr) & SMALL_PAGE_MASK));

	while (size_left > 0) {
		level = 1;

		while (true) {
			assert(level <= CORE_MMU_PGDIR_LEVEL);

			table_found = core_mmu_find_table(prtn, vaddr, level,
							  &tbl_info);
			if (!table_found)
				panic("can't find table for mapping");

			idx = core_mmu_va2idx(&tbl_info, vaddr);

			if (!can_map_at_level(paddr, vaddr, size_left,
					      1 << tbl_info.shift, mm)) {
				/*
				 * This part of the region can't be mapped at
				 * this level. Need to go deeper.
				 */
				if (!core_mmu_entry_to_finer_grained(&tbl_info,
					      idx, mm->attr & TEE_MATTR_SECURE))
					panic("Can't divide MMU entry");
				level++;
				continue;
			}

			/* We can map part of the region at current level */
			core_mmu_get_entry(&tbl_info, idx, NULL, &old_attr);
			if (old_attr)
				panic("Page is already mapped");

			core_mmu_set_entry(&tbl_info, idx, paddr, mm->attr);
			paddr += 1 << tbl_info.shift;
			vaddr += 1 << tbl_info.shift;
			size_left -= 1 << tbl_info.shift;

			break;
		}
	}
}

TEE_Result core_mmu_map_pages(vaddr_t vstart, paddr_t *pages, size_t num_pages,
			      enum teecore_memtypes memtype)
{
	TEE_Result ret;
	struct core_mmu_table_info tbl_info;
	struct tee_mmap_region *mm;
	unsigned int idx;
	uint32_t old_attr;
	uint32_t exceptions;
	vaddr_t vaddr = vstart;
	size_t i;
	bool secure;

	assert(!(core_mmu_type_to_attr(memtype) & TEE_MATTR_PX));

	secure = core_mmu_type_to_attr(memtype) & TEE_MATTR_SECURE;

	if (vaddr & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = mmu_lock();

	mm = find_map_by_va((void *)vaddr);
	if (!mm || !va_is_in_map(mm, vaddr + num_pages * SMALL_PAGE_SIZE - 1))
		panic("VA does not belong to any known mm region");

	if (!core_mmu_is_dynamic_vaspace(mm))
		panic("Trying to map into static region");

	for (i = 0; i < num_pages; i++) {
		if (pages[i] & SMALL_PAGE_MASK) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		while (true) {
			if (!core_mmu_find_table(NULL, vaddr, UINT_MAX,
						 &tbl_info))
				panic("Can't find pagetable for vaddr ");

			idx = core_mmu_va2idx(&tbl_info, vaddr);
			if (tbl_info.shift == SMALL_PAGE_SHIFT)
				break;

			/* This is supertable. Need to divide it. */
			if (!core_mmu_entry_to_finer_grained(&tbl_info, idx,
							     secure))
				panic("Failed to spread pgdir on small tables");
		}

		core_mmu_get_entry(&tbl_info, idx, NULL, &old_attr);
		if (old_attr)
			panic("Page is already mapped");

		core_mmu_set_entry(&tbl_info, idx, pages[i],
				   core_mmu_type_to_attr(memtype));
		vaddr += SMALL_PAGE_SIZE;
	}

	/*
	 * Make sure all the changes to translation tables are visible
	 * before returning. TLB doesn't need to be invalidated as we are
	 * guaranteed that there's no valid mapping in this range.
	 */
	dsb_ishst();
	mmu_unlock(exceptions);

	return TEE_SUCCESS;
err:
	mmu_unlock(exceptions);

	if (i)
		core_mmu_unmap_pages(vstart, i);

	return ret;
}

void core_mmu_unmap_pages(vaddr_t vstart, size_t num_pages)
{
	struct core_mmu_table_info tbl_info;
	struct tee_mmap_region *mm;
	size_t i;
	unsigned int idx;
	uint32_t exceptions;

	exceptions = mmu_lock();

	mm = find_map_by_va((void *)vstart);
	if (!mm || !va_is_in_map(mm, vstart + num_pages * SMALL_PAGE_SIZE - 1))
		panic("VA does not belong to any known mm region");

	if (!core_mmu_is_dynamic_vaspace(mm))
		panic("Trying to unmap static region");

	for (i = 0; i < num_pages; i++, vstart += SMALL_PAGE_SIZE) {
		if (!core_mmu_find_table(NULL, vstart, UINT_MAX, &tbl_info))
			panic("Can't find pagetable");

		if (tbl_info.shift != SMALL_PAGE_SHIFT)
			panic("Invalid pagetable level");

		idx = core_mmu_va2idx(&tbl_info, vstart);
		core_mmu_set_entry(&tbl_info, idx, 0, 0);
	}
	tlbi_all();

	mmu_unlock(exceptions);
}

void core_mmu_populate_user_map(struct core_mmu_table_info *dir_info,
				struct user_ta_ctx *utc)
{
	struct core_mmu_table_info pg_info;
	struct pgt_cache *pgt_cache = &thread_get_tsd()->pgt_cache;
	struct pgt *pgt;
	struct vm_region *r;
	struct vm_region *r_last;

	/* Find the first and last valid entry */
	r = TAILQ_FIRST(&utc->vm_info->regions);
	if (!r)
		return; /* Nothing to map */
	r_last = TAILQ_LAST(&utc->vm_info->regions, vm_region_head);

	/*
	 * Allocate all page tables in advance.
	 */
	pgt_alloc(pgt_cache, &utc->ctx, r->va,
		  r_last->va + r_last->size - 1);
	pgt = SLIST_FIRST(pgt_cache);

	core_mmu_set_info_table(&pg_info, dir_info->level + 1, 0, NULL);

	TAILQ_FOREACH(r, &utc->vm_info->regions, link)
		set_pg_region(dir_info, r, &pgt, &pg_info);
}

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

	if (!core_mmu_find_table(NULL, map->va, UINT_MAX, &tbl_info))
		return false;

	granule = 1 << tbl_info.shift;
	p = ROUNDDOWN(addr, granule);
	l = ROUNDUP(len + addr - p, granule);

	/* Ban overflowing virtual addresses */
	if (map->size < l)
		return false;

	/*
	 * Something is wrong, we can't fit the va range into the selected
	 * table. The reserved va range is possibly missaligned with
	 * granule.
	 */
	if (core_mmu_va2idx(&tbl_info, map->va + len) >= tbl_info.num_entries)
		return false;

	/* Find end of the memory map */
	n = 0;
	while (!core_mmap_is_end_of_table(static_memory_map + n))
		n++;

	if (n < (ARRAY_SIZE(static_memory_map) - 1)) {
		/* There's room for another entry */
		static_memory_map[n].va = map->va;
		static_memory_map[n].size = l;
		static_memory_map[n + 1].type = MEM_AREA_END;
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

	/* Make sure the new entry is visible before continuing. */
	dsb_ishst();

	return true;
}

unsigned int asid_alloc(void)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);
	unsigned int r;
	int i;

	bit_ffc(g_asid, MMU_NUM_ASID_PAIRS, &i);
	if (i == -1) {
		r = 0;
	} else {
		bit_set(g_asid, i);
		r = (i + 1) * 2;
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
	return r;
}

void asid_free(unsigned int asid)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);

	/* Only even ASIDs are supposed to be allocated */
	assert(!(asid & 1));

	if (asid) {
		int i = (asid - 1) / 2;

		assert(i < MMU_NUM_ASID_PAIRS && bit_test(g_asid, i));
		bit_clear(g_asid, i);
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
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
	struct core_mmu_table_info ti __maybe_unused;

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
	if (is_unpaged(va)) {
		if (v != pa)
			panic("issue in linear address space");
		return;
	}

	if (tee_pager_get_table_info(v, &ti)) {
		uint32_t a;

		/*
		 * Lookups in the page table managed by the pager is
		 * dangerous for addresses in the paged area as those pages
		 * changes all the time. But some ranges are safe,
		 * rw-locked areas when the page is populated for instance.
		 */
		core_mmu_get_entry(&ti, core_mmu_va2idx(&ti, v), &p, &a);
		if (a & TEE_MATTR_VALID_BLOCK) {
			paddr_t mask = ((1 << ti.shift) - 1);

			p |= v & mask;
			if (pa != p)
				panic();
		} else
			if (pa)
				panic();
		return;
	}
#endif

#ifndef CFG_VIRTUALIZATION
	if (!core_va2pa_helper(va, &p)) {
		/* Verfiy only the static mapping (case non null phys addr) */
		if (p && pa != p) {
			DMSG("va %p maps 0x%" PRIxPA ", expect 0x%" PRIxPA,
					va, p, pa);
			panic();
		}
	} else {
		if (pa) {
			DMSG("va %p unmapped, expect 0x%" PRIxPA, va, pa);
			panic();
		}
	}
#endif
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
	paddr_t p;

	if (!va)
		return;

	p = virt_to_phys(va);
	if (p != pa) {
		DMSG("va %p maps 0x%" PRIxPA " expect 0x%" PRIxPA, va, p, pa);
		panic();
	}
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
	if (pa >= TEE_LOAD_ADDR && pa < get_linear_map_end())
		return (void *)(vaddr_t)pa;
	return tee_pager_phys_to_virt(pa);
}
#else
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	struct tee_mmap_region *mmap;

	mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM, pa);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_NEX_RAM_RW, pa);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RW, pa);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RO, pa);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RX, pa);

	return map_pa2va(mmap, pa);
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
	case MEM_AREA_TEE_RAM_RX:
	case MEM_AREA_TEE_RAM_RO:
	case MEM_AREA_TEE_RAM_RW:
	case MEM_AREA_NEX_RAM_RW:
		va = phys_to_virt_tee_ram(pa);
		break;
	case MEM_AREA_SHM_VASPACE:
		/* Find VA from PA in dynamic SHM is not yet supported */
		va = NULL;
		break;
	default:
		va = map_pa2va(find_map_by_type_and_pa(m, pa), pa);
	}
	if (m != MEM_AREA_SEC_RAM_OVERALL)
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

vaddr_t core_mmu_get_va(paddr_t pa, enum teecore_memtypes type)
{
	if (cpu_mmu_enabled())
		return (vaddr_t)phys_to_virt(pa, type);

	return (vaddr_t)pa;
}

#ifdef CFG_WITH_PAGER
bool is_unpaged(void *va)
{
	vaddr_t v = (vaddr_t)va;

	return v >= TEE_TEXT_VA_START && v < get_linear_map_end();
}
#else
bool is_unpaged(void *va __unused)
{
	return true;
}
#endif

#ifdef CFG_VIRTUALIZATION
void core_mmu_init_virtualization(void)
{
	virt_init_memory(static_memory_map);
}
#endif
