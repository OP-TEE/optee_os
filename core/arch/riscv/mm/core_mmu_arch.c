// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <assert.h>
#include <bitstring.h>
#include <config.h>
#include <kernel/boot.h>
#include <kernel/cache_helpers.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/tee_misc.h>
#include <kernel/tlb_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/phys_mem.h>
#include <platform_config.h>
#include <riscv.h>
#include <stdalign.h>
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

#define IS_PAGE_ALIGNED(addr)	IS_ALIGNED(addr, SMALL_PAGE_SIZE)

static bitstr_t bit_decl(g_asid, RISCV_SATP_ASID_WIDTH) __nex_bss;
static unsigned int g_asid_spinlock __nex_bss = SPINLOCK_UNLOCK;

struct mmu_pte {
	unsigned long entry;
};

struct mmu_pgt {
	struct mmu_pte entries[RISCV_PTES_PER_PT];
};

#define RISCV_MMU_PGT_SIZE	(sizeof(struct mmu_pgt))

#ifndef CFG_DYN_CONFIG
static struct mmu_pgt root_pgt[CFG_TEE_CORE_NB_CORE]
	__aligned(RISCV_PGSIZE)
	__section(".nozi.mmu.root_pgt");

static struct mmu_pgt pool_pgts[RISCV_MMU_MAX_PGTS]
	__aligned(RISCV_PGSIZE) __section(".nozi.mmu.pool_pgts");

static struct mmu_pgt user_pgts[CFG_NUM_THREADS]
	__aligned(RISCV_PGSIZE) __section(".nozi.mmu.usr_pgts");
#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
static struct mmu_pgt *user_vpn2_table_va[CFG_TEE_CORE_NB_CORE];
#endif
#endif

static int user_va_idx __nex_data = -1;

struct mmu_partition {
	struct mmu_pgt *root_pgt;
	struct mmu_pgt *pool_pgts;
	struct mmu_pgt *user_pgts;
	unsigned int pgts_used;
	unsigned int asid;
#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
	struct mmu_pgt **user_vpn2_table_va;
#endif
};

#ifdef CFG_DYN_CONFIG
static struct mmu_partition default_partition __nex_bss;
#else
static struct mmu_partition default_partition __nex_data  = {
	.root_pgt = root_pgt,
	.pool_pgts = pool_pgts,
	.user_pgts = user_pgts,
	.pgts_used = 0,
	.asid = 0,
#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
	.user_vpn2_table_va = user_vpn2_table_va,
#endif
};
#endif

static struct mmu_pte *core_mmu_table_get_entry(struct mmu_pgt *pgt,
						unsigned int idx)
{
	return &pgt->entries[idx & RISCV_MMU_VPN_MASK];
}

static void core_mmu_entry_set(struct mmu_pte *pte, uint64_t val)
{
	pte->entry = val;
}

static uint64_t core_mmu_entry_get(struct mmu_pte *pte)
{
	return pte->entry;
}

static bool core_mmu_entry_is_valid(struct mmu_pte *pte)
{
	return pte->entry & PTE_V;
}

static bool core_mmu_entry_is_invalid(struct mmu_pte *pte)
{
	return !core_mmu_entry_is_valid(pte);
}

static bool core_mmu_entry_is_leaf(struct mmu_pte *pte)
{
	/* A leaf has one or more RWX bits set */
	return pte->entry & (PTE_R | PTE_W | PTE_X);
}

static bool __maybe_unused core_mmu_entry_is_branch(struct mmu_pte *pte)
{
	return core_mmu_entry_is_valid(pte) && !core_mmu_entry_is_leaf(pte);
}

static unsigned long core_mmu_pte_create(unsigned long ppn, uint8_t pte_bits)
{
	/*
	 * This function may be called from core_mmu_set_entry(). There is a
	 * case that MM core wants to clear PTE by calling core_mmu_set_entry()
	 * with zero physical address and zero memory attributes, which turns
	 * @ppn and @pte_bits in this function to be both zero. In this case, we
	 * should create zero PTE without setting its V bit.
	 */

	return SHIFT_U64(ppn, PTE_PPN_SHIFT) | pte_bits;
}

static unsigned long core_mmu_ptp_create(unsigned long ppn)
{
	/* Set V bit to create PTE points to next level of the page table. */
	return core_mmu_pte_create(ppn, PTE_V);
}

static unsigned long core_mmu_pte_ppn(struct mmu_pte *pte)
{
	return (pte->entry & PTE_PPN) >> PTE_PPN_SHIFT;
}

static unsigned long pa_to_ppn(paddr_t pa)
{
	return pa >> RISCV_PGSHIFT;
}

static paddr_t pte_to_pa(struct mmu_pte *pte)
{
	return SHIFT_U64(core_mmu_pte_ppn(pte), RISCV_PGSHIFT);
}

static unsigned long core_mmu_pgt_to_satp(unsigned long asid,
					  struct mmu_pgt *pgt)
{
	unsigned long satp = 0;
	unsigned long pgt_ppn = (paddr_t)pgt >> RISCV_PGSHIFT;

	assert(!cpu_mmu_enabled());

	satp |= SHIFT_U64(asid, RISCV_SATP_ASID_SHIFT);
	satp |= SHIFT_U64(RISCV_SATP_MODE, RISCV_SATP_MODE_SHIFT);
	satp |= pgt_ppn;

	return satp;
}

static unsigned long pte_to_mattr(unsigned level __maybe_unused,
				  struct mmu_pte *pte)
{
	unsigned long mattr = TEE_MATTR_SECURE;
	unsigned long entry = core_mmu_entry_get(pte);

	if (entry & PTE_V) {
		if (!(entry & (PTE_R | PTE_W | PTE_X)))
			return TEE_MATTR_TABLE;

		mattr |=  TEE_MATTR_VALID_BLOCK;
	}

	if (entry & PTE_U) {
		if (entry & PTE_R)
			mattr |= TEE_MATTR_UR | TEE_MATTR_PR;
		if (entry & PTE_W)
			mattr |= TEE_MATTR_UW | TEE_MATTR_PW;
		if (entry & PTE_X)
			mattr |= TEE_MATTR_UX | TEE_MATTR_PX;
	} else {
		if (entry & PTE_R)
			mattr |= TEE_MATTR_PR;
		if (entry & PTE_W)
			mattr |= TEE_MATTR_PW;
		if (entry & PTE_X)
			mattr |= TEE_MATTR_PX;
	}

	if (entry & PTE_G)
		mattr |= TEE_MATTR_GLOBAL;

	return mattr;
}

static uint8_t mattr_to_pte_bits(unsigned level __maybe_unused, uint32_t attr)
{
	unsigned long pte_bits = 0;

	if (attr & TEE_MATTR_TABLE)
		return PTE_V;

	if (attr & TEE_MATTR_VALID_BLOCK)
		pte_bits |= PTE_V;

	if (attr & TEE_MATTR_UR)
		pte_bits |= PTE_R | PTE_U;
	if (attr & TEE_MATTR_UW)
		pte_bits |= PTE_W | PTE_U;
	if (attr & TEE_MATTR_UX)
		pte_bits |= PTE_X | PTE_U;

	if (attr & TEE_MATTR_PR)
		pte_bits |= PTE_R;
	if (attr & TEE_MATTR_PW)
		pte_bits |= PTE_W | PTE_R;
	if (attr & TEE_MATTR_PX)
		pte_bits |= PTE_X | PTE_R;

	if (attr & (TEE_MATTR_UR | TEE_MATTR_PR))
		pte_bits |= PTE_A;

	if (attr & (TEE_MATTR_UW | TEE_MATTR_PW))
		pte_bits |= PTE_D;

	if (attr & TEE_MATTR_GLOBAL)
		pte_bits |= PTE_G;

	return pte_bits;
}

static unsigned int core_mmu_pgt_idx(vaddr_t va, unsigned int level)
{
	unsigned int idx = va >> CORE_MMU_SHIFT_OF_LEVEL(level);

	return idx & RISCV_MMU_VPN_MASK;
}

/* Get the pointed VA base of specific PTE in page table */
static inline vaddr_t core_mmu_pgt_get_va_base(unsigned int level,
					       unsigned int idx)
{
#ifdef RV32
	return SHIFT_U32(idx, CORE_MMU_SHIFT_OF_LEVEL(level));
#else
	vaddr_t va_base = SHIFT_U64(idx, CORE_MMU_SHIFT_OF_LEVEL(level));
	vaddr_t va_width_msb = BIT64(RISCV_MMU_VA_WIDTH - 1);
	vaddr_t va_extended_mask = GENMASK_64(63, RISCV_MMU_VA_WIDTH);

	if (va_base & va_width_msb)
		return va_extended_mask | va_base;

	return va_base;
#endif
}

static struct mmu_partition *core_mmu_get_prtn(void)
{
	return &default_partition;
}

static struct mmu_pgt *core_mmu_get_root_pgt_va(struct mmu_partition *prtn,
						size_t core_pos)
{
	assert(core_pos < CFG_TEE_CORE_NB_CORE);

	return prtn->root_pgt + core_pos;
}

static struct mmu_pgt *core_mmu_get_ta_pgt_va(struct mmu_partition *prtn)
{
	return &prtn->user_pgts[thread_get_id()];
}

static struct mmu_pgt *core_mmu_pgt_alloc(struct mmu_partition *prtn)
{
	struct mmu_pgt *pgt = NULL;

	if (IS_ENABLED(CFG_DYN_CONFIG)) {
		if (cpu_mmu_enabled()) {
			tee_mm_entry_t *mm = NULL;
			paddr_t pa = 0;
			size_t size = RISCV_MMU_PGT_SIZE;

			if (prtn == core_mmu_get_prtn()) {
				mm = phys_mem_core_alloc(size);
				if (!mm)
					EMSG("Phys mem exhausted");
			} else {
				mm = nex_phys_mem_core_alloc(size);
				if (!mm)
					EMSG("Phys nex mem exhausted");
			}
			if (!mm)
				return NULL;
			pa = tee_mm_get_smem(mm);

			pgt = phys_to_virt(pa, MEM_AREA_SEC_RAM_OVERALL,
					   RISCV_MMU_PGT_SIZE);
			assert(pgt);
		} else {
			pgt = boot_mem_alloc(RISCV_MMU_PGT_SIZE,
					     RISCV_MMU_PGT_SIZE);
			if (prtn->pool_pgts) {
				assert((vaddr_t)prtn->pool_pgts +
				       prtn->pgts_used *
				       RISCV_MMU_PGT_SIZE == (vaddr_t)pgt);
			} else {
				boot_mem_add_reloc(&prtn->pool_pgts);
				prtn->pool_pgts = pgt;
			}
		}
		prtn->pgts_used++;
		DMSG("pgts used %u", prtn->pgts_used);
	} else {
		if (prtn->pgts_used >= RISCV_MMU_MAX_PGTS) {
			debug_print("%u pgts exhausted", RISCV_MMU_MAX_PGTS);
			return NULL;
		}

		pgt = &prtn->pool_pgts[prtn->pgts_used++];

		memset(pgt, 0, RISCV_MMU_PGT_SIZE);

		DMSG("pgts used %u / %u", prtn->pgts_used,
		     RISCV_MMU_MAX_PGTS);
	}

	return pgt;
}

/*
 * Given an entry that points to a table.
 * If mmu is disabled, returns the pa of pointed table.
 * If mmu is enabled, returns the va of pointed table.
 * returns NULL otherwise.
 */
static struct mmu_pgt *core_mmu_xlat_table_entry_pa2va(struct mmu_pte *pte,
						       struct mmu_pgt *pgt)
{
	struct mmu_pgt *va = NULL;

	if (core_mmu_entry_is_invalid(pte) ||
	    core_mmu_entry_is_leaf(pte))
		return NULL;

	if (!cpu_mmu_enabled())
		return (struct mmu_pgt *)pte_to_pa(pte);

	va = phys_to_virt(pte_to_pa(pte), MEM_AREA_TEE_RAM_RW_DATA,
			  sizeof(*pgt));
	if (!va)
		va = phys_to_virt(pte_to_pa(pte), MEM_AREA_SEC_RAM_OVERALL,
				  sizeof(*pgt));

	return va;
}

#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
static struct mmu_pgt *core_mmu_get_vpn2_ta_table(struct mmu_partition *prtn,
						  size_t core_pos)
{
	assert(core_pos < CFG_TEE_CORE_NB_CORE);
	return prtn->user_vpn2_table_va[core_pos];
}

static void core_mmu_set_vpn2_ta_table(struct mmu_partition *prtn,
				       size_t core_pos, struct mmu_pgt *pgt)
{
	assert(core_pos < CFG_TEE_CORE_NB_CORE);
	prtn->user_vpn2_table_va[core_pos] = pgt;
}

/*
 * Giving a page table, return the base address of next level page table from
 * given index of entry in it.
 */
static struct mmu_pgt *core_mmu_get_next_level_pgt(struct mmu_pgt *pgt,
						   unsigned int idx)
{
	struct mmu_pte *pte = NULL;

	pte = core_mmu_table_get_entry(pgt, idx);
	assert(core_mmu_entry_is_branch(pte));

	return core_mmu_xlat_table_entry_pa2va(pte, pgt);
}
#endif

/*
 * For a table entry that points to a table - allocate and copy to
 * a new pointed table. This is done for the requested entry,
 * without going deeper into the pointed table entries.
 *
 * A success is returned for non-table entries, as nothing to do there.
 */
__maybe_unused
static bool core_mmu_entry_copy(struct core_mmu_table_info *tbl_info,
				unsigned int idx)
{
	struct mmu_pgt *orig_pgt = NULL;
	struct mmu_pgt *new_pgt = NULL;
	struct mmu_pte *pte = NULL;
	struct mmu_partition *prtn = NULL;
	unsigned long ptp = 0;

	prtn = &default_partition;
	assert(prtn);

	if (idx >= tbl_info->num_entries)
		return false;

	orig_pgt = tbl_info->table;
	pte = core_mmu_table_get_entry(orig_pgt, idx);

	/* Nothing to do for non-table entries */
	if (core_mmu_entry_is_leaf(pte) || tbl_info->level >= RISCV_PGLEVELS)
		return true;

	new_pgt = core_mmu_pgt_alloc(prtn);
	if (!new_pgt)
		return false;

	orig_pgt = core_mmu_xlat_table_entry_pa2va(pte, orig_pgt);
	if (!orig_pgt)
		return false;

	/* Copy original table content to new table */
	memcpy(new_pgt, orig_pgt, sizeof(struct mmu_pgt));

	/* Point to the new table */
	ptp = core_mmu_ptp_create(pa_to_ppn((paddr_t)new_pgt));
	core_mmu_entry_set(pte, ptp);

	return true;
}

/*
 * Setup entries inside level 4, 3, and 2 page tables for TAs memory mapping
 *
 * Sv39 - user_va_idx is already in level 2 page table, so nothing to do.
 * Sv48 - we need to allocate entry 0 of level 3 page table, and let it point to
 *        level 2 page table.
 * Sv57 - we need to allocate entry 0 of level 4 page table, and let it point to
 *        level 3 page table. We need to further allocate entry 0 of the level 3
 *        page table, and let it point to level 2 page table.
 */
static void core_init_mmu_prtn_ta_core(struct mmu_partition *prtn
				       __maybe_unused,
				       unsigned int core __maybe_unused)
{
#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
	unsigned int level = CORE_MMU_BASE_TABLE_LEVEL;
	struct core_mmu_table_info tbl_info = { };
	struct mmu_pgt *pgt = NULL;
	struct mmu_pte *pte = NULL;

	assert(user_va_idx != -1);

	while (level > CORE_MMU_VPN2_LEVEL) {
		if (level == CORE_MMU_BASE_TABLE_LEVEL) {
			/* First level: get root page table */
			pgt = core_mmu_get_root_pgt_va(prtn, core);
		} else {
			/* Other levels: get table from PTE of previous level */
			pgt = core_mmu_get_next_level_pgt(pgt, 0);
		}

		core_mmu_set_info_table(&tbl_info, level, 0, pgt);

		/*
		 * If this isn't the core that created the initial tables
		 * mappings, then the table must be copied,
		 * as it will hold pointer to the next mapping table
		 * that changes per core.
		 */
		if (core != get_core_pos()) {
			if (!core_mmu_entry_copy(&tbl_info, 0))
				panic();
		}

		if (!core_mmu_entry_to_finer_grained(&tbl_info, 0, true))
			panic();

		/* Now index 0 of the table should be pointer to next level. */
		pte = core_mmu_table_get_entry(pgt, 0);
		assert(core_mmu_entry_is_branch(pte));

		level--;
	}

	pgt = core_mmu_xlat_table_entry_pa2va(pte, pgt);
	assert(pgt);
	core_mmu_set_vpn2_ta_table(prtn, core, pgt);
#endif
}

static void core_init_mmu_prtn_ta(struct mmu_partition *prtn)
{
	unsigned int core = 0;

	assert(core_mmu_user_va_range_is_defined());

	memset(prtn->user_pgts, 0, CFG_NUM_THREADS * RISCV_MMU_PGT_SIZE);
	for (core = 0; core < CFG_TEE_CORE_NB_CORE; core++)
		core_init_mmu_prtn_ta_core(prtn, core);
}

static void core_init_mmu_prtn_tee(struct mmu_partition *prtn,
				   struct memory_map *mem_map)
{
	size_t n = 0;

	assert(prtn && mem_map);

	for (n = 0; n < mem_map->count; n++) {
		struct tee_mmap_region *mm = mem_map->map + n;

		debug_print(" %010" PRIxVA " %010" PRIxPA " %10zx %x",
			    mm->va, mm->pa, mm->size, mm->attr);

		if (!IS_PAGE_ALIGNED(mm->pa) || !IS_PAGE_ALIGNED(mm->size))
			panic("unaligned region");
	}

	/* Clear table before using it. */
	memset(prtn->root_pgt, 0, RISCV_MMU_PGT_SIZE * CFG_TEE_CORE_NB_CORE);

	for (n = 0; n < mem_map->count; n++)
		core_mmu_map_region(prtn, mem_map->map + n);

	/*
	 * Primary mapping table is ready at index `get_core_pos()`
	 * whose value may not be ZERO. Take this index as copy source.
	 */
	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		if (n == get_core_pos())
			continue;

		memcpy(core_mmu_get_root_pgt_va(prtn, n),
		       core_mmu_get_root_pgt_va(prtn, get_core_pos()),
		       RISCV_MMU_PGT_SIZE);
	}
}

void tlbi_va_range(vaddr_t va, size_t len,
		   size_t granule)
{
	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);
	assert(!(va & (granule - 1)) && !(len & (granule - 1)));

	/*
	 * Ensure operations are completed or observed before proceeding
	 * with TLB invalidation.
	 */
	mb();
	while (len) {
		tlbi_va_allasid(va);
		len -= granule;
		va += granule;
	}
	/*
	 * After invalidating TLB entries, a memory barrier is required
	 * to ensure that the page table entries become visible to other harts
	 * before subsequent memory accesses are performed.
	 */
	mb();
}

void tlbi_va_range_asid(vaddr_t va, size_t len,
			size_t granule, uint32_t asid)
{
	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);
	assert(!(va & (granule - 1)) && !(len & (granule - 1)));

	/*
	 * A memory barrier is necessary here to ensure the consistency
	 * and correctness of memory accesses.
	 */
	mb();
	while (len) {
		tlbi_va_asid(va, asid);
		len -= granule;
		va += granule;
	}
	/* Enforce ordering of memory operations and ensure that all
	 * preceding memory operations are completed after TLB
	 * invalidation.
	 */
	mb();
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

unsigned int asid_alloc(void)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);
	unsigned int r = 0;
	int i = 0;

	bit_ffc(g_asid, (int)RISCV_SATP_ASID_WIDTH, &i);
	if (i == -1) {
		r = 0;
	} else {
		bit_set(g_asid, i);
		r = i + 1;
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);

	return r;
}

void asid_free(unsigned int asid)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);

	if (asid) {
		unsigned int i = asid - 1;

		assert(i < RISCV_SATP_ASID_WIDTH && bit_test(g_asid, i));
		bit_clear(g_asid, i);
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
}

bool arch_va2pa_helper(void *va, paddr_t *pa)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	vaddr_t vaddr = (vaddr_t)va;
	struct mmu_pgt *pgt = NULL;
	struct mmu_pte *pte = NULL;
	int level = 0;
	unsigned int idx = 0;
	struct mmu_partition *prtn = core_mmu_get_prtn();
	vaddr_t offset_mask = 0;

	assert(pa);

	pgt = core_mmu_get_root_pgt_va(prtn, get_core_pos());

	for (level = CORE_MMU_BASE_TABLE_LEVEL; level >= 0; level--) {
		idx = core_mmu_pgt_idx(vaddr, level);
		pte = core_mmu_table_get_entry(pgt, idx);

		if (core_mmu_entry_is_invalid(pte)) {
			thread_unmask_exceptions(exceptions);
			return false;
		} else if (core_mmu_entry_is_leaf(pte)) {
			offset_mask = CORE_MMU_PAGE_OFFSET_MASK(level);
			*pa = pte_to_pa(pte) | (vaddr & offset_mask);
			thread_unmask_exceptions(exceptions);
			return true;
		}

		pgt = core_mmu_xlat_table_entry_pa2va(pte, pgt);
	}

	thread_unmask_exceptions(exceptions);
	return false;
}

vaddr_t arch_aslr_base_addr(vaddr_t start_addr, uint64_t seed,
			    unsigned int iteration_count)
{
	const unsigned int va_width = core_mmu_get_va_width();
	const vaddr_t va_mask = GENMASK_64(63, SMALL_PAGE_SHIFT);
	const vaddr_t va_width_msb = BIT64(va_width - 1);
	const vaddr_t va_extended_mask = GENMASK_64(63, va_width);
	vaddr_t base_addr = start_addr + seed;

	if (iteration_count) {
		base_addr &= ~GENMASK_64(va_width - 2,
					 va_width - 1 - iteration_count);
	}

	/*
	 * If the MSB is set, map the base address to the top
	 * half of the virtual address space by extending 1s
	 * to 64-bit; otherwise, map it to the bottom half.
	 */
	if (base_addr & va_width_msb)
		base_addr |= va_extended_mask;
	else
		base_addr &= ~va_extended_mask;

	return base_addr & va_mask;
}

bool cpu_mmu_enabled(void)
{
	return read_satp();
}

bool core_mmu_find_table(struct mmu_partition *prtn, vaddr_t va,
			 unsigned int max_level,
			 struct core_mmu_table_info *tbl_info)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	struct mmu_pgt *pgt = NULL;
	struct mmu_pte *pte = NULL;
	unsigned int level = CORE_MMU_BASE_TABLE_LEVEL;
	unsigned int idx = 0;
	unsigned int deepest_level = max_level;
	vaddr_t va_base = 0;
	bool ret = false;

	if (max_level == UINT_MAX)
		deepest_level = 0;

	if (!prtn)
		prtn = core_mmu_get_prtn();

	pgt = core_mmu_get_root_pgt_va(prtn, get_core_pos());

	while (true) {
		idx = core_mmu_pgt_idx(va - va_base, level);
		pte = core_mmu_table_get_entry(pgt, idx);
		if (level == deepest_level || level == 0 ||
		    core_mmu_entry_is_invalid(pte) ||
		    core_mmu_entry_is_leaf(pte)) {
			core_mmu_set_info_table(tbl_info, level, va_base, pgt);
			ret = true;
			goto out;
		}
		pgt = core_mmu_xlat_table_entry_pa2va(pte, pgt);
		if (!pgt)
			goto out;
		va_base += core_mmu_pgt_get_va_base(level, idx);
		level--;
	}
out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

bool core_mmu_entry_to_finer_grained(struct core_mmu_table_info *tbl_info,
				     unsigned int idx, bool secure __unused)
{
	struct mmu_pgt *pgt = NULL;
	struct mmu_pte *pte = NULL;
	struct mmu_partition *prtn = core_mmu_get_prtn();
	unsigned long ptp = 0;
	paddr_t pgt_pa = 0;

	if (!core_mmu_level_in_range(tbl_info->level))
		return false;

	pgt = tbl_info->table;
	pte = core_mmu_table_get_entry(pgt, idx);

	if (core_mmu_entry_is_invalid(pte)) {
		pgt = core_mmu_pgt_alloc(prtn);
		if (!pgt)
			return false;

		if (cpu_mmu_enabled())
			pgt_pa = virt_to_phys(pgt);
		else
			pgt_pa = (paddr_t)pgt;

		ptp = core_mmu_ptp_create(pa_to_ppn(pgt_pa));
		core_mmu_entry_set(pte, ptp);
	}

	return true;
}

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
			     unsigned int level, vaddr_t va_base, void *table)
{
	tbl_info->level = level;
	tbl_info->next_level = level - 1;
	tbl_info->table = table;
	tbl_info->va_base = va_base;
	tbl_info->shift = CORE_MMU_SHIFT_OF_LEVEL(level);
	assert(level < RISCV_PGLEVELS);
	tbl_info->num_entries = RISCV_PTES_PER_PT;
}

void core_mmu_get_entry_primitive(const void *table, size_t level,
				  size_t idx, paddr_t *pa, uint32_t *attr)
{
	struct mmu_pgt *pgt = (struct mmu_pgt *)table;
	struct mmu_pte *pte = core_mmu_table_get_entry(pgt, idx);

	if (core_mmu_entry_is_valid(pte)) {
		if (pa)
			*pa = pte_to_pa(pte);
		if (attr)
			*attr = pte_to_mattr(level, pte);
	} else {
		if (pa)
			*pa = 0;
		if (attr)
			*attr = 0;
	}
}

void core_mmu_set_entry_primitive(void *table, size_t level, size_t idx,
				  paddr_t pa, uint32_t attr)
{
	struct mmu_pgt *pgt = (struct mmu_pgt *)table;
	struct mmu_pte *pte = core_mmu_table_get_entry(pgt, idx);
	uint8_t pte_bits = mattr_to_pte_bits(level, attr);

	core_mmu_entry_set(pte, core_mmu_pte_create(pa_to_ppn(pa), pte_bits));
}

/*
 * Due to OP-TEE design limitation, TAs page table should be an entry
 * inside a level 2 (VPN[2]) page table.
 *
 * Available options are only these:
 * For Sv57:
 * - base level 4 entry 0 - [0GB, 256TB[
 *   - level 3 entry 0 - [0GB, 512GB[
 *     - level 2 entry 0 - [0GB, 1GB[
 *     - level 2 entry 1 - [1GB, 2GB[           <----
 *     - level 2 entry 2 - [2GB, 3GB[           <----
 *     - level 2 entry 3 - [3GB, 4GB[           <----
 *     - level 2 entry 4 - [4GB, 5GB[
 *     - ...
 *   - ...
 * - ...
 *
 * For Sv48:
 * - base level 3 entry 0 - [0GB, 512GB[
 *   - level 2 entry 0 - [0GB, 1GB[
 *   - level 2 entry 1 - [1GB, 2GB[           <----
 *   - level 2 entry 2 - [2GB, 3GB[           <----
 *   - level 2 entry 3 - [3GB, 4GB[           <----
 *   - level 2 entry 4 - [4GB, 5GB[
 *   - ...
 * - ...
 *
 * For Sv39:
 * - base level 2 entry 0 - [0GB, 1GB[
 * - base level 2 entry 1 - [1GB, 2GB[        <----
 * - base level 2 entry 2 - [2GB, 3GB[        <----
 * - base level 2 entry 3 - [3GB, 4GB[        <----
 * - base level 2 entry 4 - [4GB, 5GB[
 * - ...
 */
static void set_user_va_idx(struct mmu_partition *prtn)
{
	struct mmu_pgt *pgt = NULL;
	__maybe_unused struct mmu_pte *pte = NULL;
	__maybe_unused unsigned int level = CORE_MMU_BASE_TABLE_LEVEL;
	unsigned int idx = 0;

	pgt = core_mmu_get_root_pgt_va(prtn, get_core_pos());

#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
	/* Traverse from root page table to level 2 page table. */
	while (level > CORE_MMU_VPN2_LEVEL) {
		pgt = core_mmu_get_next_level_pgt(pgt, 0);
		assert(pgt);
		level--;
	}
#endif

	for (idx = 1 ; idx < RISCV_PTES_PER_PT; idx++) {
		pte = core_mmu_table_get_entry(pgt, idx);
		if (core_mmu_entry_is_invalid(pte)) {
			user_va_idx = idx;
			return;
		}
	}
	if (user_va_idx < 0)
		panic();
}

static struct mmu_pte *
core_mmu_get_user_mapping_entry(struct mmu_partition *prtn)
{
	struct mmu_pgt *pgt = NULL;

	assert(core_mmu_user_va_range_is_defined());

#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
	pgt = core_mmu_get_vpn2_ta_table(prtn, get_core_pos());
#else
	pgt = core_mmu_get_root_pgt_va(prtn, get_core_pos());
#endif
	return core_mmu_table_get_entry(pgt, user_va_idx);
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	unsigned long satp = 0;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	struct mmu_partition *prtn = core_mmu_get_prtn();
	struct mmu_pte *pte = NULL;
	unsigned long ptp = 0;

	satp = read_satp();
	/* Clear ASID */
	satp &= ~SHIFT_U64(RISCV_SATP_ASID_MASK, RISCV_SATP_ASID_SHIFT);
	pte = core_mmu_get_user_mapping_entry(prtn);
	if (map && map->user_map) {
		ptp = core_mmu_ptp_create(pa_to_ppn((paddr_t)map->user_map));
		core_mmu_entry_set(pte, ptp);
		core_mmu_table_write_barrier();
		satp |= SHIFT_U64(map->asid, RISCV_SATP_ASID_SHIFT);
		write_satp(satp);
	} else {
		core_mmu_entry_set(pte, 0);
		core_mmu_table_write_barrier();
	}

	tlbi_all();
	thread_unmask_exceptions(exceptions);
}

bool core_mmu_user_va_range_is_defined(void)
{
	return user_va_idx != -1;
}

void core_mmu_get_user_va_range(vaddr_t *base, size_t *size)
{
	assert(core_mmu_user_va_range_is_defined());

#ifdef RV64
	if (base)
		*base = SHIFT_U64(user_va_idx, CORE_MMU_VPN2_SHIFT);
	if (size)
		*size =  BIT64(CORE_MMU_VPN2_SHIFT);
#else
	if (base)
		*base = SHIFT_U64(user_va_idx, CORE_MMU_VPN1_SHIFT);
	if (size)
		*size =  BIT64(CORE_MMU_VPN1_SHIFT);
#endif
}

void core_mmu_get_user_pgdir(struct core_mmu_table_info *pgd_info)
{
	vaddr_t va_range_base = 0;
	struct mmu_partition *prtn = core_mmu_get_prtn();
	struct mmu_pgt *pgt = core_mmu_get_ta_pgt_va(prtn);

	core_mmu_get_user_va_range(&va_range_base, NULL);
	core_mmu_set_info_table(pgd_info, CORE_MMU_PGDIR_LEVEL + 1,
				va_range_base, pgt);
}

void core_mmu_create_user_map(struct user_mode_ctx *uctx,
			      struct core_mmu_user_map *map)
{
	struct core_mmu_table_info tbl_info = { };

	core_mmu_get_user_pgdir(&tbl_info);
	memset(tbl_info.table, 0, RISCV_MMU_PGT_SIZE);
	core_mmu_populate_user_map(&tbl_info, uctx);
	map->user_map = virt_to_phys(tbl_info.table);
	map->asid = uctx->vm_info.asid;
}

void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	struct mmu_partition *prtn = core_mmu_get_prtn();
	struct mmu_pte *pte = core_mmu_get_user_mapping_entry(prtn);

	map->user_map = pte_to_pa(pte);

	if (map->user_map)
		map->asid = (read_satp() >> RISCV_SATP_ASID_SHIFT) &
			    RISCV_SATP_ASID_MASK;
	else
		map->asid = 0;
}

bool core_mmu_user_mapping_is_active(void)
{
	struct mmu_partition *prtn = core_mmu_get_prtn();
	bool ret = false;
	struct mmu_pte *pte = NULL;
	uint32_t exceptions = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	pte = core_mmu_get_user_mapping_entry(prtn);
	ret = core_mmu_entry_is_valid(pte);
	thread_unmask_exceptions(exceptions);

	return ret;
}

void core_init_mmu_prtn(struct mmu_partition *prtn, struct memory_map *mem_map)
{
	core_init_mmu_prtn_tee(prtn, mem_map);
	core_init_mmu_prtn_ta(prtn);
}

void core_init_mmu(struct memory_map *mem_map)
{
	struct mmu_partition *prtn = &default_partition;
	size_t n = 0;

	if (IS_ENABLED(CFG_DYN_CONFIG)) {
		prtn->root_pgt = boot_mem_alloc(RISCV_MMU_PGT_SIZE *
						CFG_TEE_CORE_NB_CORE,
						RISCV_MMU_PGT_SIZE);
		boot_mem_add_reloc(&prtn->root_pgt);

		prtn->user_pgts = boot_mem_alloc(RISCV_MMU_PGT_SIZE *
						 CFG_NUM_THREADS,
						 RISCV_MMU_PGT_SIZE);
		boot_mem_add_reloc(&prtn->user_pgts);
#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
		prtn->user_vpn2_table_va =
			boot_mem_alloc(CFG_TEE_CORE_NB_CORE *
				       sizeof(struct mmu_pgt *),
				       alignof(sizeof(struct mmu_pgt *)));
		boot_mem_add_reloc(&prtn->user_vpn2_table_va);
#endif
	}

#if (RISCV_SATP_MODE >= SATP_MODE_SV48)
	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
		boot_mem_add_reloc(&prtn->user_vpn2_table_va[n]);
#endif

	/* Initialize default pagetables */
	core_init_mmu_prtn_tee(prtn, mem_map);

	for (n = 0; n < mem_map->count; n++) {
		if (!core_mmu_va_is_valid(mem_map->map[n].va) ||
		    !core_mmu_va_is_valid(mem_map->map[n].va +
					  mem_map->map[n].size - 1))
			panic("Invalid VA range in memory map");
	}

	set_user_va_idx(prtn);

	core_init_mmu_prtn_ta(prtn);
}

void core_init_mmu_regs(struct core_mmu_config *cfg)
{
	struct mmu_partition *p = core_mmu_get_prtn();
	unsigned int n = 0;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
		cfg->satp[n] = core_mmu_pgt_to_satp(p->asid, p->root_pgt + n);
}

enum core_mmu_fault core_mmu_get_fault_type(uint32_t fault_descr)
{
	switch (fault_descr) {
	case CAUSE_MISALIGNED_FETCH:
	case CAUSE_MISALIGNED_LOAD:
	case CAUSE_MISALIGNED_STORE:
		return CORE_MMU_FAULT_ALIGNMENT;
	case CAUSE_STORE_ACCESS:
	case CAUSE_LOAD_ACCESS:
		return CORE_MMU_FAULT_ACCESS_BIT;
	case CAUSE_FETCH_PAGE_FAULT:
	case CAUSE_LOAD_PAGE_FAULT:
	case CAUSE_STORE_PAGE_FAULT:
	case CAUSE_FETCH_GUEST_PAGE_FAULT:
	case CAUSE_LOAD_GUEST_PAGE_FAULT:
	case CAUSE_STORE_GUEST_PAGE_FAULT:
		return CORE_MMU_FAULT_TRANSLATION;
	case CAUSE_BREAKPOINT:
		return CORE_MMU_FAULT_DEBUG_EVENT;
	default:
		return CORE_MMU_FAULT_OTHER;
	}
}
