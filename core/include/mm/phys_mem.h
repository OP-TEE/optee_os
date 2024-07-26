/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 */

#ifndef __MM_PHYS_MEM_H
#define __MM_PHYS_MEM_H

#include <mm/tee_mm.h>
#include <types_ext.h>

void nex_phys_mem_init(paddr_t core_base, paddr_size_t core_size,
		       paddr_t ta_base, paddr_size_t ta_size);
paddr_size_t nex_phys_mem_get_ta_size(void);
paddr_t nex_phys_mem_get_ta_base(void);
tee_mm_entry_t *nex_phys_mem_mm_find(paddr_t addr);
tee_mm_entry_t *nex_phys_mem_core_alloc(size_t size);
tee_mm_entry_t *nex_phys_mem_ta_alloc(size_t size);
tee_mm_entry_t *nex_phys_mem_alloc2(paddr_t base, size_t size);
void nex_phys_mem_partial_carve_out(paddr_t base, size_t size);
#ifdef CFG_WITH_STATS
void nex_phys_mem_stats(struct pta_stats_alloc *stats, bool reset);
#endif

#ifdef CFG_NS_VIRTUALIZATION
void phys_mem_init(paddr_t core_base, paddr_size_t core_size,
		   paddr_t ta_base, paddr_size_t ta_size);
tee_mm_entry_t *phys_mem_mm_find(paddr_t addr);
tee_mm_entry_t *phys_mem_core_alloc(size_t size);
tee_mm_entry_t *phys_mem_ta_alloc(size_t size);
tee_mm_entry_t *phys_mem_alloc2(paddr_t base, size_t size);
#ifdef CFG_WITH_STATS
void phys_mem_stats(struct pta_stats_alloc *stats, bool reset);
#endif
#else
static inline void phys_mem_init(paddr_t core_base, paddr_size_t core_size,
				 paddr_t ta_base, paddr_size_t ta_size)
{
	nex_phys_mem_init(core_base, core_size, ta_base, ta_size);
}

static inline tee_mm_entry_t *phys_mem_mm_find(paddr_t addr)
{
	return nex_phys_mem_mm_find(addr);
}

static inline tee_mm_entry_t *phys_mem_core_alloc(size_t size)
{
	return nex_phys_mem_core_alloc(size);
}

static inline tee_mm_entry_t *phys_mem_ta_alloc(size_t size)
{
	return nex_phys_mem_ta_alloc(size);
}

static inline tee_mm_entry_t *phys_mem_alloc2(paddr_t base, size_t size)
{
	return nex_phys_mem_alloc2(base, size);
}

#ifdef CFG_WITH_STATS
static inline void phys_mem_stats(struct pta_stats_alloc *stats, bool reset)
{
	return nex_phys_mem_stats(stats, reset);
}
#endif
#endif

#endif /*__MM_PHYS_MEM_H*/
