// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Linaro Limited
 */

#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <mm/core_mmu.h>
#include <mm/phys_mem.h>
#include <mm/tee_mm.h>
#include <string.h>
#include <types_ext.h>

static tee_mm_pool_t *nex_core_pool __nex_bss;
static tee_mm_pool_t *nex_ta_pool __nex_bss;

static tee_mm_pool_t *init_pool(paddr_t b, paddr_size_t sz, uint32_t flags)
{
	tee_mm_pool_t *pool = NULL;

	if (!b && !sz)
		return NULL;

	if (!b || (b & CORE_MMU_USER_CODE_MASK) ||
	    !sz || (sz & CORE_MMU_USER_CODE_MASK))
		panic("invalid phys mem");

	if (flags & TEE_MM_POOL_NEX_MALLOC)
		pool = nex_malloc(sizeof(*pool));
	else
		pool = malloc(sizeof(*pool));
	if (!pool)
		panic();

	if (!tee_mm_init(pool, b, sz, CORE_MMU_USER_CODE_SHIFT, flags))
		panic();

	return pool;
}

void nex_phys_mem_init(paddr_t core_base, paddr_size_t core_size,
		       paddr_t ta_base, paddr_size_t ta_size)
{
	uint32_t flags = TEE_MM_POOL_NEX_MALLOC;

	assert(!nex_core_pool && !nex_ta_pool);

	nex_core_pool = init_pool(core_base, core_size, flags);
	nex_ta_pool = init_pool(ta_base, ta_size, flags);
}

paddr_size_t nex_phys_mem_get_ta_size(void)
{
	if (nex_ta_pool)
		return nex_ta_pool->size;
	assert(nex_core_pool);
	return nex_core_pool->size - TEE_RAM_VA_SIZE;
}

paddr_t nex_phys_mem_get_ta_base(void)
{
	if (nex_ta_pool)
		return nex_ta_pool->lo;
	assert(nex_core_pool);
	return nex_core_pool->lo;
}

static bool is_in_pool_range(tee_mm_pool_t *pool, paddr_t addr)
{
	return pool && core_is_buffer_inside(addr, 1, pool->lo, pool->size);
}

static tee_mm_entry_t *mm_find(tee_mm_pool_t *p0, tee_mm_pool_t *p1,
			       paddr_t addr)
{
	if (is_in_pool_range(p0, addr))
		return tee_mm_find(p0, addr);
	if (is_in_pool_range(p1, addr))
		return tee_mm_find(p1, addr);
	return NULL;
}

tee_mm_entry_t *nex_phys_mem_mm_find(paddr_t addr)
{
	return mm_find(nex_core_pool, nex_ta_pool, addr);
}

static tee_mm_entry_t *mm_alloc(tee_mm_pool_t *p0, tee_mm_pool_t *p1,
				size_t size)
{
	tee_mm_entry_t *mm = NULL;

	if (p0)
		mm = tee_mm_alloc(p0, size);
	if (!mm && p1)
		mm = tee_mm_alloc(p1, size);

	return mm;
}

tee_mm_entry_t *nex_phys_mem_core_alloc(size_t size)
{
	return mm_alloc(nex_core_pool, NULL, size);
}

tee_mm_entry_t *nex_phys_mem_ta_alloc(size_t size)
{
	return mm_alloc(nex_ta_pool, nex_core_pool, size);
}

static tee_mm_entry_t *mm_alloc2(tee_mm_pool_t *p0, tee_mm_pool_t *p1,
				 paddr_t base, size_t size)
{
	if (is_in_pool_range(p0, base))
		return tee_mm_alloc2(p0, base, size);
	if (is_in_pool_range(p1, base))
		return tee_mm_alloc2(p1, base, size);
	return NULL;
}

tee_mm_entry_t *nex_phys_mem_alloc2(paddr_t base, size_t size)
{
	return mm_alloc2(nex_core_pool, nex_ta_pool, base, size);
}

static void partial_carve_out(tee_mm_pool_t *pool, paddr_t base, size_t size)
{
	if (pool &&
	    core_is_buffer_intersect(base, size, pool->lo, pool->size)) {
		tee_mm_entry_t *mm __maybe_unused = NULL;
		paddr_t end_pa = 0;
		paddr_t pa = 0;
		size_t sz = 0;

		pa = MAX(base, pool->lo);
		end_pa = MIN(base + size - 1, pool->lo + pool->size - 1);
		sz = end_pa - pa + 1;

		mm = tee_mm_alloc2(pool, pa, sz);
		assert(mm);
	}
}

void nex_phys_mem_partial_carve_out(paddr_t base, size_t size)
{
	partial_carve_out(nex_core_pool, base, size);
	partial_carve_out(nex_ta_pool, base, size);
}

#ifdef CFG_WITH_STATS
static void add_pool_stats(tee_mm_pool_t *pool, struct pta_stats_alloc *stats,
			   bool reset)
{
	if (pool) {
		struct pta_stats_alloc s = { };

		tee_mm_get_pool_stats(pool, &s, reset);
		stats->size += s.size;
		if (s.max_allocated > stats->max_allocated)
			stats->max_allocated = s.max_allocated;
		stats->allocated += s.allocated;
	}
}

void nex_phys_mem_stats(struct pta_stats_alloc *stats, bool reset)
{
	memset(stats, 0, sizeof(*stats));

	add_pool_stats(nex_core_pool, stats, reset);
	add_pool_stats(nex_ta_pool, stats, reset);
}
#endif /*CFG_WITH_STATS*/

#if defined(CFG_NS_VIRTUALIZATION)

static tee_mm_pool_t *core_pool;
static tee_mm_pool_t *ta_pool;

void phys_mem_init(paddr_t core_base, paddr_size_t core_size,
		   paddr_t ta_base, paddr_size_t ta_size)
{
	uint32_t flags = TEE_MM_POOL_NO_FLAGS;

	assert(!core_pool && !ta_pool);

	core_pool = init_pool(core_base, core_size, flags);
	ta_pool = init_pool(ta_base, ta_size, flags);
}

tee_mm_entry_t *phys_mem_mm_find(paddr_t addr)
{
	return mm_find(core_pool, ta_pool, addr);
}

tee_mm_entry_t *phys_mem_core_alloc(size_t size)
{
	/*
	 * With CFG_NS_VIRTUALIZATION all memory is equally secure so we
	 * should normally be able to use one pool only, but if we have two
	 * make sure to use both even for core allocations.
	 */
	return mm_alloc(core_pool, ta_pool, size);
}

tee_mm_entry_t *phys_mem_ta_alloc(size_t size)
{
	return mm_alloc(ta_pool, core_pool, size);
}

tee_mm_entry_t *phys_mem_alloc2(paddr_t base, size_t size)
{
	return mm_alloc2(core_pool, ta_pool, base, size);
}

#ifdef CFG_WITH_STATS
void phys_mem_stats(struct pta_stats_alloc *stats, bool reset)
{
	memset(stats, 0, sizeof(*stats));

	add_pool_stats(core_pool, stats, reset);
	add_pool_stats(ta_pool, stats, reset);
}
#endif /*CFG_WITH_STATS*/
#endif /*CFG_NS_VIRTUALIZATION*/
