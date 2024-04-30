// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, 2022 Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 */

#include <assert.h>
#include <config.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/linker.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/tee_misc.h>
#include <kernel/tlb_helpers.h>
#include <kernel/user_mode_ctx.h>
#include <kernel/virtualization.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_pager.h>
#include <mm/vm.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#ifndef DEBUG_XLAT_TABLE
#define DEBUG_XLAT_TABLE 0
#endif

#define SHM_VASPACE_SIZE	(1024 * 1024 * 32)

#ifdef CFG_CORE_PHYS_RELOCATABLE
unsigned long core_mmu_tee_load_pa __nex_bss;
#else
const unsigned long core_mmu_tee_load_pa = TEE_LOAD_ADDR;
#endif

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

static struct tee_mmap_region static_memory_map[CFG_MMAP_REGIONS
#if defined(CFG_CORE_ASLR) || defined(CFG_CORE_PHYS_RELOCATABLE)
						+ 1
#endif
						+ 1] __nex_bss;

/* Define the platform's memory layout. */
struct memaccess_area {
	paddr_t paddr;
	size_t size;
};

#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area secure_only[] __nex_data = {
#ifdef CFG_CORE_PHYS_RELOCATABLE
	MEMACCESS_AREA(0, 0),
#else
#ifdef TRUSTED_SRAM_BASE
	MEMACCESS_AREA(TRUSTED_SRAM_BASE, TRUSTED_SRAM_SIZE),
#endif
	MEMACCESS_AREA(TRUSTED_DRAM_BASE, TRUSTED_DRAM_SIZE),
#endif
};

static struct memaccess_area nsec_shared[] __nex_data = {
#ifdef CFG_CORE_RESERVED_SHM
	MEMACCESS_AREA(TEE_SHMEM_START, TEE_SHMEM_SIZE),
#endif
};

#if defined(CFG_SECURE_DATA_PATH)
static const char *tz_sdp_match = "linaro,secure-heap";
static struct memaccess_area sec_sdp;
#ifdef CFG_TEE_SDP_MEM_BASE
register_sdp_mem(CFG_TEE_SDP_MEM_BASE, CFG_TEE_SDP_MEM_SIZE);
#endif
#ifdef TEE_SDP_TEST_MEM_BASE
register_sdp_mem(TEE_SDP_TEST_MEM_BASE, TEE_SDP_TEST_MEM_SIZE);
#endif
#endif

#ifdef CFG_CORE_RESERVED_SHM
register_phys_mem(MEM_AREA_NSEC_SHM, TEE_SHMEM_START, TEE_SHMEM_SIZE);
#endif
static unsigned int mmu_spinlock;

static uint32_t mmu_lock(void)
{
	return cpu_spin_lock_xsave(&mmu_spinlock);
}

static void mmu_unlock(uint32_t exceptions)
{
	cpu_spin_unlock_xrestore(&mmu_spinlock, exceptions);
}

void core_mmu_get_secure_memory(paddr_t *base, paddr_size_t *size)
{
	/*
	 * The first range is always used to cover OP-TEE core memory, but
	 * depending on configuration it may cover more than that.
	 */
	*base = secure_only[0].paddr;
	*size = secure_only[0].size;
}

void core_mmu_set_secure_memory(paddr_t base, size_t size)
{
#ifdef CFG_CORE_PHYS_RELOCATABLE
	static_assert(ARRAY_SIZE(secure_only) == 1);
#endif
	runtime_assert(IS_ENABLED(CFG_CORE_PHYS_RELOCATABLE));
	assert(!secure_only[0].size);
	assert(base && size);

	DMSG("Physical secure memory base %#"PRIxPA" size %#zx", base, size);
	secure_only[0].paddr = base;
	secure_only[0].size = size;
}

void core_mmu_get_ta_range(paddr_t *base, size_t *size)
{
	paddr_t b = 0;
	size_t s = 0;

	static_assert(!(TEE_RAM_VA_SIZE % SMALL_PAGE_SIZE));
#ifdef TA_RAM_START
	b = TA_RAM_START;
	s = TA_RAM_SIZE;
#else
	static_assert(ARRAY_SIZE(secure_only) <= 2);
	if (ARRAY_SIZE(secure_only) == 1) {
		vaddr_t load_offs = 0;

		assert(core_mmu_tee_load_pa >= secure_only[0].paddr);
		load_offs = core_mmu_tee_load_pa - secure_only[0].paddr;

		assert(secure_only[0].size >
		       load_offs + TEE_RAM_VA_SIZE + TEE_SDP_TEST_MEM_SIZE);
		b = secure_only[0].paddr + load_offs + TEE_RAM_VA_SIZE;
		s = secure_only[0].size - load_offs - TEE_RAM_VA_SIZE -
		    TEE_SDP_TEST_MEM_SIZE;
	} else {
		assert(secure_only[1].size > TEE_SDP_TEST_MEM_SIZE);
		b = secure_only[1].paddr;
		s = secure_only[1].size - TEE_SDP_TEST_MEM_SIZE;
	}
#endif
	if (base)
		*base = b;
	if (size)
		*size = s;
}

static struct tee_mmap_region *get_memory_map(void)
{
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		struct tee_mmap_region *map = virt_get_memory_map();

		if (map)
			return map;
	}

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

static bool pa_is_in_map(struct tee_mmap_region *map, paddr_t pa, size_t len)
{
	paddr_t end_pa = 0;

	if (!map)
		return false;

	if (SUB_OVERFLOW(len, 1, &end_pa) || ADD_OVERFLOW(pa, end_pa, &end_pa))
		return false;

	return (pa >= map->pa && end_pa <= map->pa + map->size - 1);
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

static struct tee_mmap_region *
find_map_by_type_and_pa(enum teecore_memtypes type, paddr_t pa, size_t len)
{
	struct tee_mmap_region *map;

	for (map = get_memory_map(); !core_mmap_is_end_of_table(map); map++) {
		if (map->type != type)
			continue;
		if (pa_is_in_map(map, pa, len))
			return map;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_va(void *va)
{
	struct tee_mmap_region *map = get_memory_map();
	unsigned long a = (unsigned long)va;

	while (!core_mmap_is_end_of_table(map)) {
		if (a >= map->va && a <= (map->va - 1 + map->size))
			return map;
		map++;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_pa(unsigned long pa)
{
	struct tee_mmap_region *map = get_memory_map();

	while (!core_mmap_is_end_of_table(map)) {
		if (pa >= map->pa && pa <= (map->pa + map->size - 1))
			return map;
		map++;
	}
	return NULL;
}

#if defined(CFG_SECURE_DATA_PATH)
static bool dtb_get_sdp_region(void)
{
	void *fdt = NULL;
	int node = 0;
	int tmp_node = 0;
	paddr_t tmp_addr = 0;
	size_t tmp_size = 0;

	if (!IS_ENABLED(CFG_EMBED_DTB))
		return false;

	fdt = get_embedded_dt();
	if (!fdt)
		panic("No DTB found");

	node = fdt_node_offset_by_compatible(fdt, -1, tz_sdp_match);
	if (node < 0) {
		DMSG("No %s compatible node found", tz_sdp_match);
		return false;
	}
	tmp_node = node;
	while (tmp_node >= 0) {
		tmp_node = fdt_node_offset_by_compatible(fdt, tmp_node,
							 tz_sdp_match);
		if (tmp_node >= 0)
			DMSG("Ignore SDP pool node %s, supports only 1 node",
			     fdt_get_name(fdt, tmp_node, NULL));
	}

	tmp_addr = fdt_reg_base_address(fdt, node);
	if (tmp_addr == DT_INFO_INVALID_REG) {
		EMSG("%s: Unable to get base addr from DT", tz_sdp_match);
		return false;
	}

	tmp_size = fdt_reg_size(fdt, node);
	if (tmp_size == DT_INFO_INVALID_REG_SIZE) {
		EMSG("%s: Unable to get size of base addr from DT",
		     tz_sdp_match);
		return false;
	}

	sec_sdp.paddr = tmp_addr;
	sec_sdp.size = tmp_size;

	return true;
}
#endif

#if defined(CFG_CORE_DYN_SHM) || defined(CFG_SECURE_DATA_PATH)
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
#endif

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
		m = nex_realloc(m, sizeof(*m) * *nelems);
		if (!m)
			panic();
		*mem = m;
	} else if (pa == m[n].addr) {
		m[n].addr += size;
		m[n].size -= size;
	} else if ((pa + size) == (m[n].addr + m[n].size)) {
		m[n].size -= size;
	} else {
		/* Need to split the memory entry */
		m = nex_realloc(m, sizeof(*m) * (*nelems + 1));
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
	size_t n = 0;

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
	if (dtb_get_sdp_region())
		carve_out_phys_mem(&m, &num_elems, sec_sdp.paddr, sec_sdp.size);

	for (pmem = phys_sdp_mem_begin; pmem < phys_sdp_mem_end; pmem++)
		carve_out_phys_mem(&m, &num_elems, pmem->addr, pmem->size);
#endif

	for (n = 0; n < ARRAY_SIZE(secure_only); n++)
		carve_out_phys_mem(&m, &num_elems, secure_only[n].paddr,
				   secure_only[n].size);

	for (map = static_memory_map; !core_mmap_is_end_of_table(map); map++) {
		switch (map->type) {
		case MEM_AREA_NSEC_SHM:
			carve_out_phys_mem(&m, &num_elems, map->pa, map->size);
			break;
		case MEM_AREA_EXT_DT:
		case MEM_AREA_MANIFEST_DT:
		case MEM_AREA_RAM_NSEC:
		case MEM_AREA_RES_VASPACE:
		case MEM_AREA_SHM_VASPACE:
		case MEM_AREA_TS_VASPACE:
		case MEM_AREA_PAGER_VASPACE:
			break;
		default:
			check_phys_mem_is_outside(m, num_elems, map);
		}
	}

	discovered_nsec_ddr_start = m;
	discovered_nsec_ddr_nelems = num_elems;

	if (!core_mmu_check_end_pa(m[num_elems - 1].addr,
				   m[num_elems - 1].size))
		panic();
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

	if (!get_discovered_nsec_ddr(&start, &end))
		return false;

	return pbuf_is_special_mem(pbuf, len, start, end);
}

bool core_mmu_nsec_ddr_is_defined(void)
{
	const struct core_mmu_phys_mem *start;
	const struct core_mmu_phys_mem *end;

	if (!get_discovered_nsec_ddr(&start, &end))
		return false;

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
			pa1, (uint64_t)pa1 + (sz1), pa2, (uint64_t)pa2 + (sz2))

#ifdef CFG_SECURE_DATA_PATH
static bool pbuf_is_sdp_mem(paddr_t pbuf, size_t len)
{
	bool is_sdp_mem = false;

	if (sec_sdp.size)
		is_sdp_mem = core_is_buffer_inside(pbuf, len, sec_sdp.paddr,
						   sec_sdp.size);

	if (!is_sdp_mem)
		is_sdp_mem = pbuf_is_special_mem(pbuf, len, phys_sdp_mem_begin,
						 phys_sdp_mem_end);

	return is_sdp_mem;
}

static struct mobj *core_sdp_mem_alloc_mobj(paddr_t pa, size_t size)
{
	struct mobj *mobj = mobj_phys_alloc(pa, size, TEE_MATTR_MEM_TYPE_CACHED,
					    CORE_MEM_SDP_MEM);

	if (!mobj)
		panic("can't create SDP physical memory object");

	return mobj;
}

struct mobj **core_sdp_mem_create_mobjs(void)
{
	const struct core_mmu_phys_mem *mem = NULL;
	struct mobj **mobj_base = NULL;
	struct mobj **mobj = NULL;
	int cnt = phys_sdp_mem_end - phys_sdp_mem_begin;

	if (sec_sdp.size)
		cnt++;

	/* SDP mobjs table must end with a NULL entry */
	mobj_base = calloc(cnt + 1, sizeof(struct mobj *));
	if (!mobj_base)
		panic("Out of memory");

	mobj = mobj_base;

	for (mem = phys_sdp_mem_begin; mem < phys_sdp_mem_end; mem++, mobj++)
		*mobj = core_sdp_mem_alloc_mobj(mem->addr, mem->size);

	if (sec_sdp.size)
		*mobj = core_sdp_mem_alloc_mobj(sec_sdp.paddr, sec_sdp.size);

	return mobj_base;
}

#else /* CFG_SECURE_DATA_PATH */
static bool pbuf_is_sdp_mem(paddr_t pbuf __unused, size_t len __unused)
{
	return false;
}

#endif /* CFG_SECURE_DATA_PATH */

/* Check special memories comply with registered memories */
static void verify_special_mem_areas(struct tee_mmap_region *mem_map,
				     const struct core_mmu_phys_mem *start,
				     const struct core_mmu_phys_mem *end,
				     const char *area_name __maybe_unused)
{
	const struct core_mmu_phys_mem *mem;
	const struct core_mmu_phys_mem *mem2;
	struct tee_mmap_region *mmap;

	if (start == end) {
		DMSG("No %s memory area defined", area_name);
		return;
	}

	for (mem = start; mem < end; mem++)
		DMSG("%s memory [%" PRIxPA " %" PRIx64 "]",
		     area_name, mem->addr, (uint64_t)mem->addr + mem->size);

	/* Check memories do not intersect each other */
	for (mem = start; mem + 1 < end; mem++) {
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
	 */
	for (mem = start; mem < end; mem++) {
		for (mmap = mem_map; mmap->type != MEM_AREA_END; mmap++) {
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
			 const char *mem_name __maybe_unused,
			 enum teecore_memtypes mem_type,
			 paddr_t mem_addr, paddr_size_t mem_size, size_t *last)
{
	size_t n = 0;
	paddr_t pa;
	paddr_size_t size;

	if (!mem_size)	/* Discard null size entries */
		return;
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
	     mem_name, teecore_memtype_name(mem_type), mem_addr, mem_size);
	while (true) {
		if (n >= (num_elems - 1)) {
			EMSG("Out of entries (%zu) in memory_map", num_elems);
			panic();
		}
		if (n == *last)
			break;
		pa = memory_map[n].pa;
		size = memory_map[n].size;
		if (mem_type == memory_map[n].type &&
		    ((pa <= (mem_addr + (mem_size - 1))) &&
		    (mem_addr <= (pa + (size - 1))))) {
			DMSG("Physical mem map overlaps 0x%" PRIxPA, mem_addr);
			memory_map[n].pa = MIN(pa, mem_addr);
			memory_map[n].size = MAX(size, mem_size) +
					     (pa - memory_map[n].pa);
			return;
		}
		if (mem_type < memory_map[n].type ||
		    (mem_type == memory_map[n].type && mem_addr < pa))
			break; /* found the spot where to insert this memory */
		n++;
	}

	memmove(memory_map + n + 1, memory_map + n,
		sizeof(struct tee_mmap_region) * (*last - n));
	(*last)++;
	memset(memory_map + n, 0, sizeof(memory_map[0]));
	memory_map[n].type = mem_type;
	memory_map[n].pa = mem_addr;
	memory_map[n].size = mem_size;
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
	const uint32_t tagged = TEE_MATTR_MEM_TYPE_TAGGED <<
				TEE_MATTR_MEM_TYPE_SHIFT;
	const uint32_t cached = TEE_MATTR_MEM_TYPE_CACHED <<
				TEE_MATTR_MEM_TYPE_SHIFT;
	const uint32_t noncache = TEE_MATTR_MEM_TYPE_DEV <<
				  TEE_MATTR_MEM_TYPE_SHIFT;

	switch (t) {
	case MEM_AREA_TEE_RAM:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRWX | tagged;
	case MEM_AREA_TEE_RAM_RX:
	case MEM_AREA_INIT_RAM_RX:
	case MEM_AREA_IDENTITY_MAP_RX:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRX | tagged;
	case MEM_AREA_TEE_RAM_RO:
	case MEM_AREA_INIT_RAM_RO:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PR | tagged;
	case MEM_AREA_TEE_RAM_RW:
	case MEM_AREA_NEX_RAM_RO: /* This has to be r/w during init runtime */
	case MEM_AREA_NEX_RAM_RW:
	case MEM_AREA_TEE_ASAN:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | tagged;
	case MEM_AREA_TEE_COHERENT:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRWX | noncache;
	case MEM_AREA_TA_RAM:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | tagged;
	case MEM_AREA_NSEC_SHM:
	case MEM_AREA_NEX_NSEC_SHM:
		return attr | TEE_MATTR_PRW | cached;
	case MEM_AREA_MANIFEST_DT:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PR | cached;
	case MEM_AREA_TRANSFER_LIST:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | cached;
	case MEM_AREA_EXT_DT:
		/*
		 * If CFG_MAP_EXT_DT_SECURE is enabled map the external device
		 * tree as secure non-cached memory, otherwise, fall back to
		 * non-secure mapping.
		 */
		if (IS_ENABLED(CFG_MAP_EXT_DT_SECURE))
			return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW |
			       noncache;
		fallthrough;
	case MEM_AREA_IO_NSEC:
		return attr | TEE_MATTR_PRW | noncache;
	case MEM_AREA_IO_SEC:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | noncache;
	case MEM_AREA_RAM_NSEC:
		return attr | TEE_MATTR_PRW | cached;
	case MEM_AREA_RAM_SEC:
	case MEM_AREA_SEC_RAM_OVERALL:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | cached;
	case MEM_AREA_ROM_SEC:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PR | cached;
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
	case MEM_AREA_INIT_RAM_RX:
	case MEM_AREA_INIT_RAM_RO:
	case MEM_AREA_NEX_RAM_RW:
	case MEM_AREA_NEX_RAM_RO:
	case MEM_AREA_TEE_ASAN:
		return true;
	default:
		return false;
	}
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

static void dump_xlat_table(vaddr_t va, unsigned int level)
{
	struct core_mmu_table_info tbl_info;
	unsigned int idx = 0;
	paddr_t pa;
	uint32_t attr;

	core_mmu_find_table(NULL, va, level, &tbl_info);
	va = tbl_info.va_base;
	for (idx = 0; idx < tbl_info.num_entries; idx++) {
		core_mmu_get_entry(&tbl_info, idx, &pa, &attr);
		if (attr || level > CORE_MMU_BASE_TABLE_LEVEL) {
			const char *security_bit = "";

			if (core_mmu_entry_have_security_bit(attr)) {
				if (attr & TEE_MATTR_SECURE)
					security_bit = "S";
				else
					security_bit = "NS";
			}

			if (attr & TEE_MATTR_TABLE) {
				DMSG_RAW("%*s [LVL%d] VA:0x%010" PRIxVA
					" TBL:0x%010" PRIxPA " %s",
					level * 2, "", level, va, pa,
					security_bit);
				dump_xlat_table(va, level + 1);
			} else if (attr) {
				DMSG_RAW("%*s [LVL%d] VA:0x%010" PRIxVA
					" PA:0x%010" PRIxPA " %s-%s-%s-%s",
					level * 2, "", level, va, pa,
					mattr_is_cached(attr) ? "MEM" :
					"DEV",
					attr & TEE_MATTR_PW ? "RW" : "RO",
					attr & TEE_MATTR_PX ? "X " : "XN",
					security_bit);
			} else {
				DMSG_RAW("%*s [LVL%d] VA:0x%010" PRIxVA
					    " INVALID\n",
					    level * 2, "", level, va);
			}
		}
		va += BIT64(tbl_info.shift);
	}
}

#else

static void dump_xlat_table(vaddr_t va __unused, int level __unused)
{
}

#endif

/*
 * Reserves virtual memory space for pager usage.
 *
 * From the start of the first memory used by the link script +
 * TEE_RAM_VA_SIZE should be covered, either with a direct mapping or empty
 * mapping for pager usage. This adds translation tables as needed for the
 * pager to operate.
 */
static void add_pager_vaspace(struct tee_mmap_region *mmap, size_t num_elems,
			      size_t *last)
{
	paddr_t begin = 0;
	paddr_t end = 0;
	size_t size = 0;
	size_t pos = 0;
	size_t n = 0;

	if (*last >= (num_elems - 1)) {
		EMSG("Out of entries (%zu) in memory map", num_elems);
		panic();
	}

	for (n = 0; !core_mmap_is_end_of_table(mmap + n); n++) {
		if (map_is_tee_ram(mmap + n)) {
			if (!begin)
				begin = mmap[n].pa;
			pos = n + 1;
		}
	}

	end = mmap[pos - 1].pa + mmap[pos - 1].size;
	assert(end - begin < TEE_RAM_VA_SIZE);
	size = TEE_RAM_VA_SIZE - (end - begin);

	assert(pos <= *last);
	memmove(mmap + pos + 1, mmap + pos,
		sizeof(struct tee_mmap_region) * (*last - pos));
	(*last)++;
	memset(mmap + pos, 0, sizeof(mmap[0]));
	mmap[pos].type = MEM_AREA_PAGER_VASPACE;
	mmap[pos].va = 0;
	mmap[pos].size = size;
	mmap[pos].region_size = SMALL_PAGE_SIZE;
	mmap[pos].attr = core_mmu_type_to_attr(MEM_AREA_PAGER_VASPACE);
}

static void check_sec_nsec_mem_config(void)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(secure_only); n++) {
		if (pbuf_intersects(nsec_shared, secure_only[n].paddr,
				    secure_only[n].size))
			panic("Invalid memory access config: sec/nsec");
	}
}

static void collect_device_mem_ranges(struct tee_mmap_region *memory_map,
				      size_t num_elems, size_t *last)
{
	const char *compatible = "arm,ffa-manifest-device-regions";
	void *fdt = get_manifest_dt();
	const char *name = NULL;
	uint64_t page_count = 0;
	uint64_t base = 0;
	int subnode = 0;
	int node = 0;

	assert(fdt);

	node = fdt_node_offset_by_compatible(fdt, 0, compatible);
	if (node < 0)
		return;

	fdt_for_each_subnode(subnode, fdt, node) {
		name = fdt_get_name(fdt, subnode, NULL);
		if (!name)
			continue;

		if (dt_getprop_as_number(fdt, subnode, "base-address",
					 &base)) {
			EMSG("Mandatory field is missing: base-address");
			continue;
		}

		if (base & SMALL_PAGE_MASK) {
			EMSG("base-address is not page aligned");
			continue;
		}

		if (dt_getprop_as_number(fdt, subnode, "pages-count",
					 &page_count)) {
			EMSG("Mandatory field is missing: pages-count");
			continue;
		}

		add_phys_mem(memory_map, num_elems, name, MEM_AREA_IO_SEC,
			     base, page_count * SMALL_PAGE_SIZE, last);
	}
}

static size_t collect_mem_ranges(struct tee_mmap_region *memory_map,
				 size_t num_elems)
{
	const struct core_mmu_phys_mem *mem = NULL;
	vaddr_t ram_start = secure_only[0].paddr;
	size_t last = 0;


#define ADD_PHYS_MEM(_type, _addr, _size) \
		add_phys_mem(memory_map, num_elems, #_addr, (_type), \
			     (_addr), (_size),  &last)

	if (IS_ENABLED(CFG_CORE_RWDATA_NOEXEC)) {
		ADD_PHYS_MEM(MEM_AREA_TEE_RAM_RO, ram_start,
			     VCORE_UNPG_RX_PA - ram_start);
		ADD_PHYS_MEM(MEM_AREA_TEE_RAM_RX, VCORE_UNPG_RX_PA,
			     VCORE_UNPG_RX_SZ);
		ADD_PHYS_MEM(MEM_AREA_TEE_RAM_RO, VCORE_UNPG_RO_PA,
			     VCORE_UNPG_RO_SZ);

		if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
			ADD_PHYS_MEM(MEM_AREA_NEX_RAM_RO, VCORE_UNPG_RW_PA,
				     VCORE_UNPG_RW_SZ);
			ADD_PHYS_MEM(MEM_AREA_NEX_RAM_RW, VCORE_NEX_RW_PA,
				     VCORE_NEX_RW_SZ);
		} else {
			ADD_PHYS_MEM(MEM_AREA_TEE_RAM_RW, VCORE_UNPG_RW_PA,
				     VCORE_UNPG_RW_SZ);
		}

		if (IS_ENABLED(CFG_WITH_PAGER)) {
			ADD_PHYS_MEM(MEM_AREA_INIT_RAM_RX, VCORE_INIT_RX_PA,
				     VCORE_INIT_RX_SZ);
			ADD_PHYS_MEM(MEM_AREA_INIT_RAM_RO, VCORE_INIT_RO_PA,
				     VCORE_INIT_RO_SZ);
		}
	} else {
		ADD_PHYS_MEM(MEM_AREA_TEE_RAM, TEE_RAM_START, TEE_RAM_PH_SIZE);
	}

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		ADD_PHYS_MEM(MEM_AREA_SEC_RAM_OVERALL, TRUSTED_DRAM_BASE,
			     TRUSTED_DRAM_SIZE);
	} else {
		/*
		 * Every guest will have own TA RAM if virtualization
		 * support is enabled.
		 */
		paddr_t ta_base = 0;
		size_t ta_size = 0;

		core_mmu_get_ta_range(&ta_base, &ta_size);
		ADD_PHYS_MEM(MEM_AREA_TA_RAM, ta_base, ta_size);
	}

	if (IS_ENABLED(CFG_CORE_SANITIZE_KADDRESS) &&
	    IS_ENABLED(CFG_WITH_PAGER)) {
		/*
		 * Asan ram is part of MEM_AREA_TEE_RAM_RW when pager is
		 * disabled.
		 */
		ADD_PHYS_MEM(MEM_AREA_TEE_ASAN, ASAN_MAP_PA, ASAN_MAP_SZ);
	}

#undef ADD_PHYS_MEM

	/* Collect device memory info from SP manifest */
	if (IS_ENABLED(CFG_CORE_SEL2_SPMC))
		collect_device_mem_ranges(memory_map, num_elems, &last);

	for (mem = phys_mem_map_begin; mem < phys_mem_map_end; mem++) {
		/* Only unmapped virtual range may have a null phys addr */
		assert(mem->addr || !core_mmu_type_to_attr(mem->type));

		add_phys_mem(memory_map, num_elems, mem->name, mem->type,
			     mem->addr, mem->size, &last);
	}

	if (IS_ENABLED(CFG_SECURE_DATA_PATH))
		verify_special_mem_areas(memory_map, phys_sdp_mem_begin,
					 phys_sdp_mem_end, "SDP");

	add_va_space(memory_map, num_elems, MEM_AREA_RES_VASPACE,
		     CFG_RESERVED_VASPACE_SIZE, &last);

	add_va_space(memory_map, num_elems, MEM_AREA_SHM_VASPACE,
		     SHM_VASPACE_SIZE, &last);

	memory_map[last].type = MEM_AREA_END;

	return last;
}

static void assign_mem_granularity(struct tee_mmap_region *memory_map)
{
	struct tee_mmap_region *map = NULL;

	/*
	 * Assign region sizes, note that MEM_AREA_TEE_RAM always uses
	 * SMALL_PAGE_SIZE.
	 */
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
		paddr_t mask = map->pa | map->size;

		if (!(mask & CORE_MMU_PGDIR_MASK))
			map->region_size = CORE_MMU_PGDIR_SIZE;
		else if (!(mask & SMALL_PAGE_MASK))
			map->region_size = SMALL_PAGE_SIZE;
		else
			panic("Impossible memory alignment");

		if (map_is_tee_ram(map))
			map->region_size = SMALL_PAGE_SIZE;
	}
}

static bool place_tee_ram_at_top(paddr_t paddr)
{
	return paddr > BIT64(core_mmu_get_va_width()) / 2;
}

/*
 * MMU arch driver shall override this function if it helps
 * optimizing the memory footprint of the address translation tables.
 */
bool __weak core_mmu_prefer_tee_ram_at_top(paddr_t paddr)
{
	return place_tee_ram_at_top(paddr);
}

static bool assign_mem_va_dir(vaddr_t tee_ram_va,
			      struct tee_mmap_region *memory_map,
			      bool tee_ram_at_top)
{
	struct tee_mmap_region *map = NULL;
	vaddr_t va = 0;
	bool va_is_secure = true;

	/*
	 * tee_ram_va might equals 0 when CFG_CORE_ASLR=y.
	 * 0 is by design an invalid va, so return false directly.
	 */
	if (!tee_ram_va)
		return false;

	/* Clear eventual previous assignments */
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++)
		map->va = 0;

	/*
	 * TEE RAM regions are always aligned with region_size.
	 *
	 * Note that MEM_AREA_PAGER_VASPACE also counts as TEE RAM here
	 * since it handles virtual memory which covers the part of the ELF
	 * that cannot fit directly into memory.
	 */
	va = tee_ram_va;
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
		if (map_is_tee_ram(map) ||
		    map->type == MEM_AREA_PAGER_VASPACE) {
			assert(!(va & (map->region_size - 1)));
			assert(!(map->size & (map->region_size - 1)));
			map->va = va;
			if (ADD_OVERFLOW(va, map->size, &va))
				return false;
			if (va >= BIT64(core_mmu_get_va_width()))
				return false;
		}
	}

	if (tee_ram_at_top) {
		/*
		 * Map non-tee ram regions at addresses lower than the tee
		 * ram region.
		 */
		va = tee_ram_va;
		for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
			map->attr = core_mmu_type_to_attr(map->type);
			if (map->va)
				continue;

			if (!IS_ENABLED(CFG_WITH_LPAE) &&
			    va_is_secure != map_is_secure(map)) {
				va_is_secure = !va_is_secure;
				va = ROUNDDOWN(va, CORE_MMU_PGDIR_SIZE);
			}

			if (SUB_OVERFLOW(va, map->size, &va))
				return false;
			va = ROUNDDOWN(va, map->region_size);
			/*
			 * Make sure that va is aligned with pa for
			 * efficient pgdir mapping. Basically pa &
			 * pgdir_mask should be == va & pgdir_mask
			 */
			if (map->size > 2 * CORE_MMU_PGDIR_SIZE) {
				if (SUB_OVERFLOW(va, CORE_MMU_PGDIR_SIZE, &va))
					return false;
				va += (map->pa - va) & CORE_MMU_PGDIR_MASK;
			}
			map->va = va;
		}
	} else {
		/*
		 * Map non-tee ram regions at addresses higher than the tee
		 * ram region.
		 */
		for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
			map->attr = core_mmu_type_to_attr(map->type);
			if (map->va)
				continue;

			if (!IS_ENABLED(CFG_WITH_LPAE) &&
			    va_is_secure != map_is_secure(map)) {
				va_is_secure = !va_is_secure;
				if (ROUNDUP_OVERFLOW(va, CORE_MMU_PGDIR_SIZE,
						     &va))
					return false;
			}

			if (ROUNDUP_OVERFLOW(va, map->region_size, &va))
				return false;
			/*
			 * Make sure that va is aligned with pa for
			 * efficient pgdir mapping. Basically pa &
			 * pgdir_mask should be == va & pgdir_mask
			 */
			if (map->size > 2 * CORE_MMU_PGDIR_SIZE) {
				vaddr_t offs = (map->pa - va) &
					       CORE_MMU_PGDIR_MASK;

				if (ADD_OVERFLOW(va, offs, &va))
					return false;
			}

			map->va = va;
			if (ADD_OVERFLOW(va, map->size, &va))
				return false;
			if (va >= BIT64(core_mmu_get_va_width()))
				return false;
		}
	}

	return true;
}

static bool assign_mem_va(vaddr_t tee_ram_va,
			  struct tee_mmap_region *memory_map)
{
	bool tee_ram_at_top = place_tee_ram_at_top(tee_ram_va);

	/*
	 * Check that we're not overlapping with the user VA range.
	 */
	if (IS_ENABLED(CFG_WITH_LPAE)) {
		/*
		 * User VA range is supposed to be defined after these
		 * mappings have been established.
		 */
		assert(!core_mmu_user_va_range_is_defined());
	} else {
		vaddr_t user_va_base = 0;
		size_t user_va_size = 0;

		assert(core_mmu_user_va_range_is_defined());
		core_mmu_get_user_va_range(&user_va_base, &user_va_size);
		if (tee_ram_va < (user_va_base + user_va_size))
			return false;
	}

	if (IS_ENABLED(CFG_WITH_PAGER)) {
		bool prefered_dir = core_mmu_prefer_tee_ram_at_top(tee_ram_va);

		/* Try whole mapping covered by a single base xlat entry */
		if (prefered_dir != tee_ram_at_top &&
		    assign_mem_va_dir(tee_ram_va, memory_map, prefered_dir))
			return true;
	}

	return assign_mem_va_dir(tee_ram_va, memory_map, tee_ram_at_top);
}

static int cmp_init_mem_map(const void *a, const void *b)
{
	const struct tee_mmap_region *mm_a = a;
	const struct tee_mmap_region *mm_b = b;
	int rc = 0;

	rc = CMP_TRILEAN(mm_a->region_size, mm_b->region_size);
	if (!rc)
		rc = CMP_TRILEAN(mm_a->pa, mm_b->pa);
	/*
	 * 32bit MMU descriptors cannot mix secure and non-secure mapping in
	 * the same level2 table. Hence sort secure mapping from non-secure
	 * mapping.
	 */
	if (!rc && !IS_ENABLED(CFG_WITH_LPAE))
		rc = CMP_TRILEAN(map_is_secure(mm_a), map_is_secure(mm_b));

	return rc;
}

static bool mem_map_add_id_map(struct tee_mmap_region *memory_map,
			       size_t num_elems, size_t *last,
			       vaddr_t id_map_start, vaddr_t id_map_end)
{
	struct tee_mmap_region *map = NULL;
	vaddr_t start = ROUNDDOWN(id_map_start, SMALL_PAGE_SIZE);
	vaddr_t end = ROUNDUP(id_map_end, SMALL_PAGE_SIZE);
	size_t len = end - start;

	if (*last >= num_elems - 1) {
		EMSG("Out of entries (%zu) in memory map", num_elems);
		panic();
	}

	for (map = memory_map; !core_mmap_is_end_of_table(map); map++)
		if (core_is_buffer_intersect(map->va, map->size, start, len))
			return false;

	*map = (struct tee_mmap_region){
		.type = MEM_AREA_IDENTITY_MAP_RX,
		/*
		 * Could use CORE_MMU_PGDIR_SIZE to potentially save a
		 * translation table, at the increased risk of clashes with
		 * the rest of the memory map.
		 */
		.region_size = SMALL_PAGE_SIZE,
		.pa = start,
		.va = start,
		.size = len,
		.attr = core_mmu_type_to_attr(MEM_AREA_IDENTITY_MAP_RX),
	};

	(*last)++;

	return true;
}

static unsigned long init_mem_map(struct tee_mmap_region *memory_map,
				  size_t num_elems, unsigned long seed)
{
	/*
	 * @id_map_start and @id_map_end describes a physical memory range
	 * that must be mapped Read-Only eXecutable at identical virtual
	 * addresses.
	 */
	vaddr_t id_map_start = (vaddr_t)__identity_map_init_start;
	vaddr_t id_map_end = (vaddr_t)__identity_map_init_end;
	vaddr_t start_addr = secure_only[0].paddr;
	unsigned long offs = 0;
	size_t last = 0;

	last = collect_mem_ranges(memory_map, num_elems);
	assign_mem_granularity(memory_map);

	/*
	 * To ease mapping and lower use of xlat tables, sort mapping
	 * description moving small-page regions after the pgdir regions.
	 */
	qsort(memory_map, last, sizeof(struct tee_mmap_region),
	      cmp_init_mem_map);

	if (IS_ENABLED(CFG_WITH_PAGER))
		add_pager_vaspace(memory_map, num_elems, &last);

	if (IS_ENABLED(CFG_CORE_ASLR) && seed) {
		vaddr_t base_addr = start_addr + seed;
		const unsigned int va_width = core_mmu_get_va_width();
		const vaddr_t va_mask = GENMASK_64(va_width - 1,
						   SMALL_PAGE_SHIFT);
		vaddr_t ba = base_addr;
		size_t n = 0;

		for (n = 0; n < 3; n++) {
			if (n)
				ba = base_addr ^ BIT64(va_width - n);
			ba &= va_mask;
			if (assign_mem_va(ba, memory_map) &&
			    mem_map_add_id_map(memory_map, num_elems, &last,
					       id_map_start, id_map_end)) {
				offs = ba - start_addr;
				DMSG("Mapping core at %#"PRIxVA" offs %#lx",
				     ba, offs);
				goto out;
			} else {
				DMSG("Failed to map core at %#"PRIxVA, ba);
			}
		}
		EMSG("Failed to map core with seed %#lx", seed);
	}

	if (!assign_mem_va(start_addr, memory_map))
		panic();

out:
	qsort(memory_map, last, sizeof(struct tee_mmap_region),
	      cmp_mmap_by_lower_va);

	dump_mmap_table(memory_map);

	return offs;
}

static void check_mem_map(struct tee_mmap_region *map)
{
	struct tee_mmap_region *m = NULL;

	for (m = map; !core_mmap_is_end_of_table(m); m++) {
		switch (m->type) {
		case MEM_AREA_TEE_RAM:
		case MEM_AREA_TEE_RAM_RX:
		case MEM_AREA_TEE_RAM_RO:
		case MEM_AREA_TEE_RAM_RW:
		case MEM_AREA_INIT_RAM_RX:
		case MEM_AREA_INIT_RAM_RO:
		case MEM_AREA_NEX_RAM_RW:
		case MEM_AREA_NEX_RAM_RO:
		case MEM_AREA_IDENTITY_MAP_RX:
			if (!pbuf_is_inside(secure_only, m->pa, m->size))
				panic("TEE_RAM can't fit in secure_only");
			break;
		case MEM_AREA_TA_RAM:
			if (!pbuf_is_inside(secure_only, m->pa, m->size))
				panic("TA_RAM can't fit in secure_only");
			break;
		case MEM_AREA_NSEC_SHM:
			if (!pbuf_is_inside(nsec_shared, m->pa, m->size))
				panic("NS_SHM can't fit in nsec_shared");
			break;
		case MEM_AREA_SEC_RAM_OVERALL:
		case MEM_AREA_TEE_COHERENT:
		case MEM_AREA_TEE_ASAN:
		case MEM_AREA_IO_SEC:
		case MEM_AREA_IO_NSEC:
		case MEM_AREA_EXT_DT:
		case MEM_AREA_MANIFEST_DT:
		case MEM_AREA_TRANSFER_LIST:
		case MEM_AREA_RAM_SEC:
		case MEM_AREA_RAM_NSEC:
		case MEM_AREA_ROM_SEC:
		case MEM_AREA_RES_VASPACE:
		case MEM_AREA_SHM_VASPACE:
		case MEM_AREA_PAGER_VASPACE:
			break;
		default:
			EMSG("Uhandled memtype %d", m->type);
			panic();
		}
	}
}

static struct tee_mmap_region *get_tmp_mmap(void)
{
	struct tee_mmap_region *tmp_mmap = (void *)__heap1_start;

#ifdef CFG_WITH_PAGER
	if (__heap1_end - __heap1_start < (ptrdiff_t)sizeof(static_memory_map))
		tmp_mmap = (void *)__heap2_start;
#endif

	memset(tmp_mmap, 0, sizeof(static_memory_map));

	return tmp_mmap;
}

/*
 * core_init_mmu_map() - init tee core default memory mapping
 *
 * This routine sets the static default TEE core mapping. If @seed is > 0
 * and configured with CFG_CORE_ASLR it will map tee core at a location
 * based on the seed and return the offset from the link address.
 *
 * If an error happened: core_init_mmu_map is expected to panic.
 *
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak core_init_mmu_map(unsigned long seed, struct core_mmu_config *cfg)
{
#ifndef CFG_NS_VIRTUALIZATION
	vaddr_t start = ROUNDDOWN((vaddr_t)__nozi_start, SMALL_PAGE_SIZE);
#else
	vaddr_t start = ROUNDDOWN((vaddr_t)__vcore_nex_rw_start,
				  SMALL_PAGE_SIZE);
#endif
	vaddr_t len = ROUNDUP((vaddr_t)__nozi_end, SMALL_PAGE_SIZE) - start;
	struct tee_mmap_region *tmp_mmap = get_tmp_mmap();
	unsigned long offs = 0;

	if (IS_ENABLED(CFG_CORE_PHYS_RELOCATABLE) &&
	    (core_mmu_tee_load_pa & SMALL_PAGE_MASK))
		panic("OP-TEE load address is not page aligned");

	check_sec_nsec_mem_config();

	/*
	 * Add a entry covering the translation tables which will be
	 * involved in some virt_to_phys() and phys_to_virt() conversions.
	 */
	static_memory_map[0] = (struct tee_mmap_region){
		.type = MEM_AREA_TEE_RAM,
		.region_size = SMALL_PAGE_SIZE,
		.pa = start,
		.va = start,
		.size = len,
		.attr = core_mmu_type_to_attr(MEM_AREA_IDENTITY_MAP_RX),
	};

	COMPILE_TIME_ASSERT(CFG_MMAP_REGIONS >= 13);
	offs = init_mem_map(tmp_mmap, ARRAY_SIZE(static_memory_map), seed);

	check_mem_map(tmp_mmap);
	core_init_mmu(tmp_mmap);
	dump_xlat_table(0x0, CORE_MMU_BASE_TABLE_LEVEL);
	core_init_mmu_regs(cfg);
	cfg->map_offset = offs;
	memcpy(static_memory_map, tmp_mmap, sizeof(static_memory_map));
}

bool core_mmu_mattr_is_ok(uint32_t mattr)
{
	/*
	 * Keep in sync with core_mmu_lpae.c:mattr_to_desc and
	 * core_mmu_v7.c:mattr_to_texcb
	 */

	switch ((mattr >> TEE_MATTR_MEM_TYPE_SHIFT) & TEE_MATTR_MEM_TYPE_MASK) {
	case TEE_MATTR_MEM_TYPE_DEV:
	case TEE_MATTR_MEM_TYPE_STRONGLY_O:
	case TEE_MATTR_MEM_TYPE_CACHED:
	case TEE_MATTR_MEM_TYPE_TAGGED:
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
	paddr_t ta_base = 0;
	size_t ta_size = 0;
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
		core_mmu_get_ta_range(&ta_base, &ta_size);
		return core_is_buffer_inside(pbuf, len, ta_base, ta_size);
#ifdef CFG_CORE_RESERVED_SHM
	case CORE_MEM_NSEC_SHM:
		return core_is_buffer_inside(pbuf, len, TEE_SHMEM_START,
							TEE_SHMEM_SIZE);
#endif
	case CORE_MEM_SDP_MEM:
		return pbuf_is_sdp_mem(pbuf, len);
	case CORE_MEM_CACHED:
		map = find_map_by_pa(pbuf);
		if (!map || !pbuf_inside_map_area(pbuf, len, map))
			return false;
		return mattr_is_cached(map->attr);
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

static void *map_pa2va(struct tee_mmap_region *map, paddr_t pa, size_t len)
{
	if (!pa_is_in_map(map, pa, len))
		return NULL;

	return (void *)(vaddr_t)(map->va + pa - map->pa);
}

/*
 * teecore gets some memory area definitions
 */
void core_mmu_get_mem_by_type(enum teecore_memtypes type, vaddr_t *s,
			      vaddr_t *e)
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

void core_mmu_set_entry(struct core_mmu_table_info *tbl_info, unsigned int idx,
			paddr_t pa, uint32_t attr)
{
	assert(idx < tbl_info->num_entries);
	core_mmu_set_entry_primitive(tbl_info->table, tbl_info->level,
				     idx, pa, attr);
}

void core_mmu_get_entry(struct core_mmu_table_info *tbl_info, unsigned int idx,
			paddr_t *pa, uint32_t *attr)
{
	assert(idx < tbl_info->num_entries);
	core_mmu_get_entry_primitive(tbl_info->table, tbl_info->level,
				     idx, pa, attr);
}

static void clear_region(struct core_mmu_table_info *tbl_info,
			 struct tee_mmap_region *region)
{
	unsigned int end = 0;
	unsigned int idx = 0;

	/* va, len and pa should be block aligned */
	assert(!core_mmu_get_block_offset(tbl_info, region->va));
	assert(!core_mmu_get_block_offset(tbl_info, region->size));
	assert(!core_mmu_get_block_offset(tbl_info, region->pa));

	idx = core_mmu_va2idx(tbl_info, region->va);
	end = core_mmu_va2idx(tbl_info, region->va + region->size);

	while (idx < end) {
		core_mmu_set_entry(tbl_info, idx, 0, 0);
		idx++;
	}
}

static void set_region(struct core_mmu_table_info *tbl_info,
		       struct tee_mmap_region *region)
{
	unsigned int end;
	unsigned int idx;
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
		pa += BIT64(tbl_info->shift);
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

			/* Virtual addresses must grow */
			assert(r.va > pg_info->va_base);

			idx = core_mmu_va2idx(dir_info, r.va);
			pg_info->va_base = core_mmu_idx2va(dir_info, idx);

			/*
			 * Advance pgt to va_base, note that we may need to
			 * skip multiple page tables if there are large
			 * holes in the vm map.
			 */
			while ((*pgt)->vabase < pg_info->va_base) {
				*pgt = SLIST_NEXT(*pgt, link);
				/* We should have allocated enough */
				assert(*pgt);
			}
			assert((*pgt)->vabase == pg_info->va_base);
			pg_info->table = (*pgt)->tbl;

			core_mmu_set_entry(dir_info, idx,
					   virt_to_phys(pg_info->table),
					   pgt_attr);
		}

		r.size = MIN(CORE_MMU_PGDIR_SIZE - (r.va - pg_info->va_base),
			     end - r.va);

		if (!(*pgt)->populated  && !mobj_is_paged(region->mobj)) {
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
	unsigned int level;
	bool table_found;
	uint32_t old_attr;

	assert(!((vaddr | paddr) & SMALL_PAGE_MASK));

	while (size_left > 0) {
		level = CORE_MMU_BASE_TABLE_LEVEL;

		while (true) {
			paddr_t block_size = 0;

			assert(core_mmu_level_in_range(level));

			table_found = core_mmu_find_table(prtn, vaddr, level,
							  &tbl_info);
			if (!table_found)
				panic("can't find table for mapping");

			block_size = BIT64(tbl_info.shift);

			idx = core_mmu_va2idx(&tbl_info, vaddr);
			if (!can_map_at_level(paddr, vaddr, size_left,
					      block_size, mm)) {
				bool secure = mm->attr & TEE_MATTR_SECURE;

				/*
				 * This part of the region can't be mapped at
				 * this level. Need to go deeper.
				 */
				if (!core_mmu_entry_to_finer_grained(&tbl_info,
								     idx,
								     secure))
					panic("Can't divide MMU entry");
				level = tbl_info.next_level;
				continue;
			}

			/* We can map part of the region at current level */
			core_mmu_get_entry(&tbl_info, idx, NULL, &old_attr);
			if (old_attr)
				panic("Page is already mapped");

			core_mmu_set_entry(&tbl_info, idx, paddr, mm->attr);
			paddr += block_size;
			vaddr += block_size;
			size_left -= block_size;

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
	core_mmu_table_write_barrier();
	mmu_unlock(exceptions);

	return TEE_SUCCESS;
err:
	mmu_unlock(exceptions);

	if (i)
		core_mmu_unmap_pages(vstart, i);

	return ret;
}

TEE_Result core_mmu_map_contiguous_pages(vaddr_t vstart, paddr_t pstart,
					 size_t num_pages,
					 enum teecore_memtypes memtype)
{
	struct core_mmu_table_info tbl_info = { };
	struct tee_mmap_region *mm = NULL;
	unsigned int idx = 0;
	uint32_t old_attr = 0;
	uint32_t exceptions = 0;
	vaddr_t vaddr = vstart;
	paddr_t paddr = pstart;
	size_t i = 0;
	bool secure = false;

	assert(!(core_mmu_type_to_attr(memtype) & TEE_MATTR_PX));

	secure = core_mmu_type_to_attr(memtype) & TEE_MATTR_SECURE;

	if ((vaddr | paddr) & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = mmu_lock();

	mm = find_map_by_va((void *)vaddr);
	if (!mm || !va_is_in_map(mm, vaddr + num_pages * SMALL_PAGE_SIZE - 1))
		panic("VA does not belong to any known mm region");

	if (!core_mmu_is_dynamic_vaspace(mm))
		panic("Trying to map into static region");

	for (i = 0; i < num_pages; i++) {
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

		core_mmu_set_entry(&tbl_info, idx, paddr,
				   core_mmu_type_to_attr(memtype));
		paddr += SMALL_PAGE_SIZE;
		vaddr += SMALL_PAGE_SIZE;
	}

	/*
	 * Make sure all the changes to translation tables are visible
	 * before returning. TLB doesn't need to be invalidated as we are
	 * guaranteed that there's no valid mapping in this range.
	 */
	core_mmu_table_write_barrier();
	mmu_unlock(exceptions);

	return TEE_SUCCESS;
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
				struct user_mode_ctx *uctx)
{
	struct core_mmu_table_info pg_info = { };
	struct pgt_cache *pgt_cache = &uctx->pgt_cache;
	struct pgt *pgt = NULL;
	struct pgt *p = NULL;
	struct vm_region *r = NULL;

	if (TAILQ_EMPTY(&uctx->vm_info.regions))
		return; /* Nothing to map */

	/*
	 * Allocate all page tables in advance.
	 */
	pgt_get_all(uctx);
	pgt = SLIST_FIRST(pgt_cache);

	core_mmu_set_info_table(&pg_info, dir_info->next_level, 0, NULL);

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link)
		set_pg_region(dir_info, r, &pgt, &pg_info);
	/* Record that the translation tables now are populated. */
	SLIST_FOREACH(p, pgt_cache, link) {
		p->populated = true;
		if (p == pgt)
			break;
	}
	assert(p == pgt);
}

TEE_Result core_mmu_remove_mapping(enum teecore_memtypes type, void *addr,
				   size_t len)
{
	struct core_mmu_table_info tbl_info = { };
	struct tee_mmap_region *res_map = NULL;
	struct tee_mmap_region *map = NULL;
	paddr_t pa = virt_to_phys(addr);
	size_t granule = 0;
	ptrdiff_t i = 0;
	paddr_t p = 0;
	size_t l = 0;

	map = find_map_by_type_and_pa(type, pa, len);
	if (!map)
		return TEE_ERROR_GENERIC;

	res_map = find_map_by_type(MEM_AREA_RES_VASPACE);
	if (!res_map)
		return TEE_ERROR_GENERIC;
	if (!core_mmu_find_table(NULL, res_map->va, UINT_MAX, &tbl_info))
		return TEE_ERROR_GENERIC;
	granule = BIT(tbl_info.shift);

	if (map < static_memory_map ||
	    map >= static_memory_map + ARRAY_SIZE(static_memory_map))
		return TEE_ERROR_GENERIC;
	i = map - static_memory_map;

	/* Check that we have a full match */
	p = ROUNDDOWN(pa, granule);
	l = ROUNDUP(len + pa - p, granule);
	if (map->pa != p || map->size != l)
		return TEE_ERROR_GENERIC;

	clear_region(&tbl_info, map);
	tlbi_all();

	/* If possible remove the va range from res_map */
	if (res_map->va - map->size == map->va) {
		res_map->va -= map->size;
		res_map->size += map->size;
	}

	/* Remove the entry. */
	memmove(map, map + 1,
		(ARRAY_SIZE(static_memory_map) - i - 1) * sizeof(*map));

	/* Clear the last new entry in case it was used */
	memset(static_memory_map + ARRAY_SIZE(static_memory_map) - 1,
	       0, sizeof(*map));

	return TEE_SUCCESS;
}

struct tee_mmap_region *
core_mmu_find_mapping_exclusive(enum teecore_memtypes type, size_t len)
{
	struct tee_mmap_region *map = NULL;
	struct tee_mmap_region *map_found = NULL;

	if (!len)
		return NULL;

	for (map = get_memory_map(); !core_mmap_is_end_of_table(map); map++) {
		if (map->type != type)
			continue;

		if (map_found)
			return NULL;

		map_found = map;
	}

	if (!map_found || map_found->size < len)
		return NULL;

	return map_found;
}

void *core_mmu_add_mapping(enum teecore_memtypes type, paddr_t addr, size_t len)
{
	struct core_mmu_table_info tbl_info;
	struct tee_mmap_region *map;
	size_t n;
	size_t granule;
	paddr_t p;
	size_t l;

	if (!len)
		return NULL;

	if (!core_mmu_check_end_pa(addr, len))
		return NULL;

	/* Check if the memory is already mapped */
	map = find_map_by_type_and_pa(type, addr, len);
	if (map && pbuf_inside_map_area(addr, len, map))
		return (void *)(vaddr_t)(map->va + addr - map->pa);

	/* Find the reserved va space used for late mappings */
	map = find_map_by_type(MEM_AREA_RES_VASPACE);
	if (!map)
		return NULL;

	if (!core_mmu_find_table(NULL, map->va, UINT_MAX, &tbl_info))
		return NULL;

	granule = BIT64(tbl_info.shift);
	p = ROUNDDOWN(addr, granule);
	l = ROUNDUP(len + addr - p, granule);

	/* Ban overflowing virtual addresses */
	if (map->size < l)
		return NULL;

	/*
	 * Something is wrong, we can't fit the va range into the selected
	 * table. The reserved va range is possibly missaligned with
	 * granule.
	 */
	if (core_mmu_va2idx(&tbl_info, map->va + len) >= tbl_info.num_entries)
		return NULL;

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
	core_mmu_table_write_barrier();

	return (void *)(vaddr_t)(map->va + addr - map->pa);
}

#ifdef CFG_WITH_PAGER
static vaddr_t get_linear_map_end_va(void)
{
	/* this is synced with the generic linker file kern.ld.S */
	return (vaddr_t)__heap2_end;
}

static paddr_t get_linear_map_end_pa(void)
{
	return get_linear_map_end_va() - boot_mmu_config.map_offset;
}
#endif

#if defined(CFG_TEE_CORE_DEBUG)
static void check_pa_matches_va(void *va, paddr_t pa)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t v = (vaddr_t)va;
	paddr_t p = 0;
	struct core_mmu_table_info ti __maybe_unused = { };

	if (core_mmu_user_va_range_is_defined()) {
		vaddr_t user_va_base = 0;
		size_t user_va_size = 0;

		core_mmu_get_user_va_range(&user_va_base, &user_va_size);
		if (v >= user_va_base &&
		    v <= (user_va_base - 1 + user_va_size)) {
			if (!core_mmu_user_mapping_is_active()) {
				if (pa)
					panic("issue in linear address space");
				return;
			}

			res = vm_va2pa(to_user_mode_ctx(thread_get_tsd()->ctx),
				       va, &p);
			if (res == TEE_ERROR_NOT_SUPPORTED)
				return;
			if (res == TEE_SUCCESS && pa != p)
				panic("bad pa");
			if (res != TEE_SUCCESS && pa)
				panic("false pa");
			return;
		}
	}
#ifdef CFG_WITH_PAGER
	if (is_unpaged(va)) {
		if (v - boot_mmu_config.map_offset != pa)
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
			paddr_t mask = BIT64(ti.shift) - 1;

			p |= v & mask;
			if (pa != p)
				panic();
		} else {
			if (pa)
				panic();
		}
		return;
	}
#endif

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
}
#else
static void check_pa_matches_va(void *va __unused, paddr_t pa __unused)
{
}
#endif

paddr_t virt_to_phys(void *va)
{
	paddr_t pa = 0;

	if (!arch_va2pa_helper(va, &pa))
		pa = 0;
	check_pa_matches_va(va, pa);
	return pa;
}

#if defined(CFG_TEE_CORE_DEBUG)
static void check_va_matches_pa(paddr_t pa, void *va)
{
	paddr_t p = 0;

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

static void *phys_to_virt_ts_vaspace(paddr_t pa, size_t len)
{
	if (!core_mmu_user_mapping_is_active())
		return NULL;

	return vm_pa2va(to_user_mode_ctx(thread_get_tsd()->ctx), pa, len);
}

#ifdef CFG_WITH_PAGER
static void *phys_to_virt_tee_ram(paddr_t pa, size_t len)
{
	paddr_t end_pa = 0;

	if (SUB_OVERFLOW(len, 1, &end_pa) || ADD_OVERFLOW(pa, end_pa, &end_pa))
		return NULL;

	if (pa >= TEE_LOAD_ADDR && pa < get_linear_map_end_pa()) {
		if (end_pa > get_linear_map_end_pa())
			return NULL;
		return (void *)(vaddr_t)(pa + boot_mmu_config.map_offset);
	}

	return tee_pager_phys_to_virt(pa, len);
}
#else
static void *phys_to_virt_tee_ram(paddr_t pa, size_t len)
{
	struct tee_mmap_region *mmap = NULL;

	mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM, pa, len);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_NEX_RAM_RW, pa, len);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_NEX_RAM_RO, pa, len);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RW, pa, len);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RO, pa, len);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RX, pa, len);
	/*
	 * Note that MEM_AREA_INIT_RAM_RO and MEM_AREA_INIT_RAM_RX are only
	 * used with pager and not needed here.
	 */
	return map_pa2va(mmap, pa, len);
}
#endif

void *phys_to_virt(paddr_t pa, enum teecore_memtypes m, size_t len)
{
	void *va = NULL;

	switch (m) {
	case MEM_AREA_TS_VASPACE:
		va = phys_to_virt_ts_vaspace(pa, len);
		break;
	case MEM_AREA_TEE_RAM:
	case MEM_AREA_TEE_RAM_RX:
	case MEM_AREA_TEE_RAM_RO:
	case MEM_AREA_TEE_RAM_RW:
	case MEM_AREA_NEX_RAM_RO:
	case MEM_AREA_NEX_RAM_RW:
		va = phys_to_virt_tee_ram(pa, len);
		break;
	case MEM_AREA_SHM_VASPACE:
		/* Find VA from PA in dynamic SHM is not yet supported */
		va = NULL;
		break;
	default:
		va = map_pa2va(find_map_by_type_and_pa(m, pa, len), pa, len);
	}
	if (m != MEM_AREA_SEC_RAM_OVERALL)
		check_va_matches_pa(pa, va);
	return va;
}

void *phys_to_virt_io(paddr_t pa, size_t len)
{
	struct tee_mmap_region *map = NULL;
	void *va = NULL;

	map = find_map_by_type_and_pa(MEM_AREA_IO_SEC, pa, len);
	if (!map)
		map = find_map_by_type_and_pa(MEM_AREA_IO_NSEC, pa, len);
	if (!map)
		return NULL;
	va = map_pa2va(map, pa, len);
	check_va_matches_pa(pa, va);
	return va;
}

vaddr_t core_mmu_get_va(paddr_t pa, enum teecore_memtypes type, size_t len)
{
	if (cpu_mmu_enabled())
		return (vaddr_t)phys_to_virt(pa, type, len);

	return (vaddr_t)pa;
}

#ifdef CFG_WITH_PAGER
bool is_unpaged(const void *va)
{
	vaddr_t v = (vaddr_t)va;

	return v >= VCORE_START_VA && v < get_linear_map_end_va();
}
#endif

#ifdef CFG_NS_VIRTUALIZATION
bool is_nexus(const void *va)
{
	vaddr_t v = (vaddr_t)va;

	return v >= VCORE_START_VA && v < VCORE_NEX_RW_PA + VCORE_NEX_RW_SZ;
}
#endif

void core_mmu_init_virtualization(void)
{
	paddr_t b1 = 0;
	paddr_size_t s1 = 0;

	static_assert(ARRAY_SIZE(secure_only) <= 2);
	if (ARRAY_SIZE(secure_only) == 2) {
		b1 = secure_only[1].paddr;
		s1 = secure_only[1].size;
	}
	virt_init_memory(static_memory_map, secure_only[0].paddr,
			 secure_only[0].size, b1, s1);
}

vaddr_t io_pa_or_va(struct io_pa_va *p, size_t len)
{
	assert(p->pa);
	if (cpu_mmu_enabled()) {
		if (!p->va)
			p->va = (vaddr_t)phys_to_virt_io(p->pa, len);
		assert(p->va);
		return p->va;
	}
	return p->pa;
}

vaddr_t io_pa_or_va_secure(struct io_pa_va *p, size_t len)
{
	assert(p->pa);
	if (cpu_mmu_enabled()) {
		if (!p->va)
			p->va = (vaddr_t)phys_to_virt(p->pa, MEM_AREA_IO_SEC,
						      len);
		assert(p->va);
		return p->va;
	}
	return p->pa;
}

vaddr_t io_pa_or_va_nsec(struct io_pa_va *p, size_t len)
{
	assert(p->pa);
	if (cpu_mmu_enabled()) {
		if (!p->va)
			p->va = (vaddr_t)phys_to_virt(p->pa, MEM_AREA_IO_NSEC,
						      len);
		assert(p->va);
		return p->va;
	}
	return p->pa;
}

#ifdef CFG_CORE_RESERVED_SHM
static TEE_Result teecore_init_pub_ram(void)
{
	vaddr_t s = 0;
	vaddr_t e = 0;

	/* get virtual addr/size of NSec shared mem allocated from teecore */
	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &s, &e);

	if (s >= e || s & SMALL_PAGE_MASK || e & SMALL_PAGE_MASK)
		panic("invalid PUB RAM");

	/* extra check: we could rely on core_mmu_get_mem_by_type() */
	if (!tee_vbuf_is_non_sec(s, e - s))
		panic("PUB RAM is not non-secure");

#ifdef CFG_PL310
	/* Allocate statically the l2cc mutex */
	tee_l2cc_store_mutex_boot_pa(virt_to_phys((void *)s));
	s += sizeof(uint32_t);			/* size of a pl310 mutex */
	s = ROUNDUP(s, SMALL_PAGE_SIZE);	/* keep required alignment */
#endif

	default_nsec_shm_paddr = virt_to_phys((void *)s);
	default_nsec_shm_size = e - s;

	return TEE_SUCCESS;
}
early_init(teecore_init_pub_ram);
#endif /*CFG_CORE_RESERVED_SHM*/

void core_mmu_init_ta_ram(void)
{
	vaddr_t s = 0;
	vaddr_t e = 0;
	paddr_t ps = 0;
	size_t size = 0;

	/*
	 * Get virtual addr/size of RAM where TA are loaded/executedNSec
	 * shared mem allocated from teecore.
	 */
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION))
		virt_get_ta_ram(&s, &e);
	else
		core_mmu_get_mem_by_type(MEM_AREA_TA_RAM, &s, &e);

	ps = virt_to_phys((void *)s);
	size = e - s;

	if (!ps || (ps & CORE_MMU_USER_CODE_MASK) ||
	    !size || (size & CORE_MMU_USER_CODE_MASK))
		panic("invalid TA RAM");

	/* extra check: we could rely on core_mmu_get_mem_by_type() */
	if (!tee_pbuf_is_sec(ps, size))
		panic("TA RAM is not secure");

	if (!tee_mm_is_empty(&tee_mm_sec_ddr))
		panic("TA RAM pool is not empty");

	/* remove previous config and init TA ddr memory pool */
	tee_mm_final(&tee_mm_sec_ddr);
	tee_mm_init(&tee_mm_sec_ddr, ps, size, CORE_MMU_USER_CODE_SHIFT,
		    TEE_MM_POOL_NO_FLAGS);
}
