// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022, NXP
 */

#include <assert.h>
#include <keep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tlb_helpers.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>
#include <platform_config.h>
#include <riscv.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#ifndef RV64
#error implement
#endif

#ifndef DEBUG_XLAT_TABLE
#define DEBUG_XLAT_TABLE 0
#endif

#if DEBUG_XLAT_TABLE
#define debug_print(...) DMSG_RAW(__VA_ARGS__)
#else
#define debug_print(...) ((void)0)
#endif

#define RISCV_MAX_PGTS  6

typedef struct _pte_t {
	unsigned long entry;
} pte_t;

typedef struct _pgt_t {
	pte_t entries[RISCV_PTES_PER_PT];
} pgt_t;

static pgt_t base_xlation_table
	__aligned(RISCV_PGSIZE)
	__section(".nozi.mmu.base_table");

static pgt_t xlat_tables[RISCV_MAX_PGTS]
	__aligned(RISCV_PGSIZE) __section(".nozi.mmu.l2");

struct mmu_partition {
	pgt_t *base_table;
	pgt_t *xlat_tables;
	unsigned int pgts_used;
	unsigned int asid;
};

static struct mmu_partition default_partition __nex_data  = {
	.base_table = &base_xlation_table,
	.xlat_tables = (pgt_t *)xlat_tables,
	.pgts_used = 0,
	.asid = 0
};

static void core_mmu_entry_set(pte_t *pte, uint64_t val)
{
	pte->entry = val; 
}

static inline bool core_mmu_entry_is_valid(pte_t *pte)
{
	return (pte->entry & PTE_V);
}

static inline bool core_mmu_entry_is_invalid(pte_t *pte)
{
	return !core_mmu_entry_is_valid(pte); 
}

static inline bool core_mmu_entry_is_leaf(pte_t *pte)
{
	// A leaf has one or more RWX bits set
	return (pte->entry & (PTE_R | PTE_W | PTE_X)) != 0;
}

static inline bool core_mmu_entry_is_branch(pte_t *pte)
{
	return !(core_mmu_entry_is_leaf(pte));
}

static inline unsigned long core_mmu_pte_create(unsigned long ppn, int type)
{
	return (ppn << PTE_PPN_SHIFT) | PTE_V | type;
}

static inline unsigned long core_mmu_ptd_create(unsigned long ppn)
{
  return core_mmu_pte_create(ppn, PTE_V);
}

static unsigned long core_mmu_pte_ppn(pte_t *pte)
{
  return pte->entry >> PTE_PPN_SHIFT;
}

static unsigned long core_mmu_ppn(unsigned long addr)
{
  return addr >> RISCV_PGSHIFT;
}

static size_t core_mmu_pgt_idx(unsigned long addr, int level)
{
	size_t idx = addr >> (RISCV_PGLEVEL_BITS * level + RISCV_PGSHIFT);
	return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
}

static inline unsigned core_mmu_pgt_shift(unsigned level)
{
	return RISCV_PGLEVEL_BITS * level + RISCV_PGSHIFT;
}

static inline unsigned core_mmu_pgt_block_szie(unsigned level)
{
	return BIT64(core_mmu_pgt_shift(level));
}

static struct mmu_partition *core_mmu_get_prtn(void)
{
	return &default_partition;
}

static pgt_t* core_mmu_get_base_pgt_va(struct mmu_partition *prtn)
{
	return prtn->base_table;
}

void core_mmu_get_user_va_range(vaddr_t *base, size_t *size)
{
	if (base) {
		*base = 1 << RISCV_PGSHIFT;
	}

	if (size)
		*size = (RISCV_PTES_PER_PT - 1) << RISCV_PGSHIFT;
}

void core_init_mmu_prtn(struct mmu_partition *prtn, struct tee_mmap_region *mm)
{
	size_t n;
	void *ttb1 = (void *)core_mmu_get_base_pgt_va(prtn);
	memset(ttb1 , 0, RISCV_PTES_PER_PT * sizeof(pte_t));
	
	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++)
		if (!core_mmu_is_dynamic_vaspace(mm + n))
			core_mmu_map_region(prtn, mm + n);
}

void core_init_mmu(struct tee_mmap_region *mm)
{
	core_init_mmu_prtn(&default_partition, mm);	
}

static unsigned long pte_to_mattr(unsigned level __maybe_unused, unsigned long pte)
{
    unsigned long mattr = TEE_MATTR_SECURE;

	mattr |= (pte & PTE_R) ? TEE_MATTR_UR : 0;
	mattr |= (pte & PTE_W) ? TEE_MATTR_UW : 0;
    mattr |= (pte & PTE_X) ? TEE_MATTR_UX : 0;

	return mattr;
}

static unsigned long mattr_to_pte(unsigned level __maybe_unused, uint32_t attr)
{
    unsigned long pte = 0;

	pte |= ((attr & TEE_MATTR_UR) || (attr & TEE_MATTR_PR)) ? PTE_R : 0;
    pte |= ((attr & TEE_MATTR_UW) || (attr & TEE_MATTR_PW)) ? PTE_W : 0;
    pte |= ((attr & TEE_MATTR_UX) || (attr & TEE_MATTR_PX)) ? PTE_X : 0;

	return pte;
}

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
		unsigned level, vaddr_t va_base, void *table)
{

	tbl_info->level = level;
	tbl_info->table = table;
	tbl_info->va_base = va_base;
	tbl_info->shift = core_mmu_pgt_shift(level);
	assert(level < RISCV_PGLEVELS);
	tbl_info->num_entries = RISCV_PTES_PER_PT;
}

static pgt_t *core_mmu_pgt_alloc(struct mmu_partition *prtn)
{
	pgt_t *new_table = NULL;

	if (prtn->pgts_used >= RISCV_MAX_PGTS) {
		debug_print("%u pgts exhausted", RISCV_MAX_PGTS);
		panic();
		return NULL;
	}

	new_table = &prtn->xlat_tables[prtn->pgts_used++];

	memset(new_table, 0, RISCV_PTES_PER_PT * sizeof(pte_t));

	debug_print("pgts used %u / %u", prtn->pgts_used, RISCV_MAX_PGTS);

	return new_table;
}


bool core_mmu_entry_to_finer_grained(struct core_mmu_table_info *tbl_info,
				     unsigned int idx, bool secure __maybe_unused)
{
	pte_t *pte;

	if (idx >= RISCV_PTES_PER_PT)
		return false;
	
	pte = (pte_t *)tbl_info->table + idx;

	if(core_mmu_entry_is_valid(pte)){
		// TODO: check the secure attribute
	}

	if (core_mmu_entry_is_invalid(pte)) {
		struct mmu_partition *prtn = core_mmu_get_prtn();
		pgt_t *new_table = core_mmu_pgt_alloc(prtn);
		if (!new_table)
			return false;
		core_mmu_entry_set(pte, core_mmu_ptd_create(core_mmu_ppn((unsigned long)new_table)));
	}

	return true;
}

bool core_mmu_user_mapping_is_active(void)
{
	return false;
}

bool core_mmu_place_tee_ram_at_top(paddr_t paddr)
{
	return paddr > 0x80000000;
}

static unsigned long core_mmu_pgt_to_satp(unsigned long asid, pgt_t* pgt)
{
    unsigned long satp = 0;
	unsigned long pgt_ppn = ((unsigned long)pgt) >> RISCV_PGSHIFT;

	assert(asid & RISCV_SATP_ASID_MASK == asid);
	satp |= asid << RISCV_SATP_ASID_SHIFT;
	satp |= (((unsigned long)RISCV_SATP_MODE) << RISCV_SATP_MODE_SHIFT);
	satp |= pgt_ppn;

    return satp;
}

void core_init_mmu_regs(struct core_mmu_config *cfg)
{
	struct mmu_partition *prtn = core_mmu_get_prtn();	
	cfg->satp = core_mmu_pgt_to_satp(0, core_mmu_get_base_pgt_va(prtn));
}

void core_mmu_set_entry_primitive(void *table, size_t level, size_t idx,
				  paddr_t pa, uint32_t attr)
{

	pgt_t *pgt = (pgt_t *)table;
	unsigned long bits = mattr_to_pte(level, attr) | PTE_V |  PTE_D | PTE_A;

	pte_t *pte = &(pgt->entries[idx]);
	unsigned long e = core_mmu_pte_create(core_mmu_ppn(pa), bits);
	core_mmu_entry_set(pte, e);
}


void core_mmu_get_entry_primitive(const void *table, size_t level,
				  size_t idx, paddr_t *pa, uint32_t *attr)
{

	pgt_t *pgt = (pgt_t *)table;
	pte_t *pte = &(pgt->entries[idx]);

    if(core_mmu_entry_is_leaf(pte))
    {
		if (pa)
			*pa = core_mmu_pte_ppn(pte) << RISCV_PGSHIFT;
		if (attr)
			*attr = pte_to_mattr(level, pte->entry);
    }

}

bool core_mmu_find_table(struct mmu_partition *prtn, vaddr_t va,
			 unsigned max_level,
			 struct core_mmu_table_info *tbl_info)
{
	pgt_t *pgt;
	pte_t *pte;
	int level;
	size_t idx;

	if(max_level > RISCV_PGLEVELS)
		return false;

	if (!prtn)
		prtn = core_mmu_get_prtn();

	pgt = core_mmu_get_base_pgt_va(prtn);

	for (level = RISCV_PGLEVELS - 1; level >= 0 ; level--) {
		if(level == (int)max_level)
			break;
		idx = core_mmu_pgt_idx(va, level);
		pte = &(pgt->entries[idx]);
		if(core_mmu_entry_is_branch(pte))
		{
			pgt = (pgt_t*)(core_mmu_pte_ppn(pte) << RISCV_PGSHIFT);
		}
	}

	core_mmu_set_info_table(tbl_info, level, 0, 
	phys_to_virt((paddr_t)pgt, MEM_AREA_TEE_RAM_RW_DATA, 1));

  return true;
}

bool arch_va2pa_helper(void *va, paddr_t *pa)
{
	struct mmu_partition *prtn = core_mmu_get_prtn();
	vaddr_t vaddr = (vaddr_t) va;
	pgt_t* pgt = (pgt_t *)core_mmu_get_base_pgt_va(prtn);
	int level;

    for(level = RISCV_PGLEVELS - 1; level >= 0; level--)
    {
        size_t idx = core_mmu_pgt_idx(vaddr, level);
		pte_t* pte = &(pgt->entries[idx]);

		if(core_mmu_entry_is_invalid(pte))
		{
			return false;
		}
        else if(core_mmu_entry_is_leaf(pte))
        {
            *pa = core_mmu_pte_ppn(pte) << RISCV_PGSHIFT;
            return true;
        }
        pgt = (pgt_t*) phys_to_virt((core_mmu_pte_ppn(pte) << RISCV_PGSHIFT), MEM_AREA_TEE_RAM_RW_DATA, 1);
    }

    return false;
}

bool cpu_mmu_enabled(void)
{
	return read_satp() != 0;
}

void tlbi_mva_range_asid(vaddr_t va __unused, size_t len __unused,
	size_t granule __unused, uint32_t asid __unused)
{
}

void asid_free(unsigned int asid __unused)
{
}

void core_mmu_get_user_map(struct core_mmu_user_map *map __unused)
{
}

void core_mmu_set_user_map(struct core_mmu_user_map *map __unused)
{
}

void core_mmu_create_user_map(struct user_mode_ctx *uctx __unused,
			      struct core_mmu_user_map *map __unused)
{
}
