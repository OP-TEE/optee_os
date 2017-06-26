/*
 * Copyright (c) 2015-2016, Linaro Limited
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
 * Copyright (c) 2014, ARM Limited and Contributors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
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
#include <platform_config.h>

#include <arm.h>
#include <assert.h>
#include <compiler.h>
#include <inttypes.h>
#include <keep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tlb_helpers.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_memprot.h>
#include <mm/pgt_cache.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "core_mmu_private.h"

#ifndef DEBUG_XLAT_TABLE
#define DEBUG_XLAT_TABLE 0
#endif

#if DEBUG_XLAT_TABLE
#define debug_print(...) DMSG_RAW(__VA_ARGS__)
#else
#define debug_print(...) ((void)0)
#endif


/*
 * Miscellaneous MMU related constants
 */

#define INVALID_DESC		0x0
#define BLOCK_DESC		0x1
#define L3_BLOCK_DESC		0x3
#define TABLE_DESC		0x3
#define DESC_ENTRY_TYPE_MASK	0x3

#define HIDDEN_DESC		0x4
#define HIDDEN_DIRTY_DESC	0x8

#define XN			(1ull << 2)
#define PXN			(1ull << 1)
#define CONT_HINT		(1ull << 0)

#define UPPER_ATTRS(x)		(((x) & 0x7) << 52)
#define NON_GLOBAL		(1ull << 9)
#define ACCESS_FLAG		(1ull << 8)
#define NSH			(0x0 << 6)
#define OSH			(0x2 << 6)
#define ISH			(0x3 << 6)

#define AP_RO			(0x1 << 5)
#define AP_RW			(0x0 << 5)
#define AP_UNPRIV		(0x1 << 4)

#define NS				(0x1 << 3)
#define LOWER_ATTRS_SHIFT		2
#define LOWER_ATTRS(x)			(((x) & 0xfff) << LOWER_ATTRS_SHIFT)

#define ATTR_DEVICE_INDEX		0x0
#define ATTR_IWBWA_OWBWA_NTR_INDEX	0x1
#define ATTR_INDEX_MASK			0x7

#define ATTR_DEVICE			(0x4)
#define ATTR_IWBWA_OWBWA_NTR		(0xff)

#define MAIR_ATTR_SET(attr, index)	(((uint64_t)attr) << ((index) << 3))

#define OUTPUT_ADDRESS_MASK	(0x0000FFFFFFFFF000ULL)

/* (internal) physical address size bits in EL3/EL1 */
#define TCR_PS_BITS_4GB		(0x0)
#define TCR_PS_BITS_64GB	(0x1)
#define TCR_PS_BITS_1TB		(0x2)
#define TCR_PS_BITS_4TB		(0x3)
#define TCR_PS_BITS_16TB	(0x4)
#define TCR_PS_BITS_256TB	(0x5)

#define ADDR_MASK_48_TO_63	0xFFFF000000000000ULL
#define ADDR_MASK_44_TO_47	0x0000F00000000000ULL
#define ADDR_MASK_42_TO_43	0x00000C0000000000ULL
#define ADDR_MASK_40_TO_41	0x0000030000000000ULL
#define ADDR_MASK_36_TO_39	0x000000F000000000ULL
#define ADDR_MASK_32_TO_35	0x0000000F00000000ULL

#define UNSET_DESC		((uint64_t)-1)

#define FOUR_KB_SHIFT		12
#define PAGE_SIZE_SHIFT		FOUR_KB_SHIFT
#define PAGE_SIZE		(1 << PAGE_SIZE_SHIFT)
#define PAGE_SIZE_MASK		(PAGE_SIZE - 1)
#define IS_PAGE_ALIGNED(addr)	(((addr) & PAGE_SIZE_MASK) == 0)

#define XLAT_ENTRY_SIZE_SHIFT	3 /* Each MMU table entry is 8 bytes (1 << 3) */
#define XLAT_ENTRY_SIZE		(1 << XLAT_ENTRY_SIZE_SHIFT)

#define XLAT_TABLE_SIZE_SHIFT	PAGE_SIZE_SHIFT
#define XLAT_TABLE_SIZE		(1 << XLAT_TABLE_SIZE_SHIFT)

/* Values for number of entries in each MMU translation table */
#define XLAT_TABLE_ENTRIES_SHIFT (XLAT_TABLE_SIZE_SHIFT - XLAT_ENTRY_SIZE_SHIFT)
#define XLAT_TABLE_ENTRIES	(1 << XLAT_TABLE_ENTRIES_SHIFT)
#define XLAT_TABLE_ENTRIES_MASK	(XLAT_TABLE_ENTRIES - 1)

/* Values to convert a memory address to an index into a translation table */
#define L3_XLAT_ADDRESS_SHIFT	PAGE_SIZE_SHIFT
#define L2_XLAT_ADDRESS_SHIFT	(L3_XLAT_ADDRESS_SHIFT + \
				 XLAT_TABLE_ENTRIES_SHIFT)
#define L1_XLAT_ADDRESS_SHIFT	(L2_XLAT_ADDRESS_SHIFT + \
				 XLAT_TABLE_ENTRIES_SHIFT)

#define NUM_L1_ENTRIES		\
		(CFG_LPAE_ADDR_SPACE_SIZE >> L1_XLAT_ADDRESS_SHIFT)

#ifndef MAX_XLAT_TABLES
#define MAX_XLAT_TABLES		5
#endif

/* MMU L1 table, one for each core */
static uint64_t l1_xlation_table[CFG_TEE_CORE_NB_CORE][NUM_L1_ENTRIES]
	__aligned(NUM_L1_ENTRIES * XLAT_ENTRY_SIZE) __section(".nozi.mmu.l1");

static uint64_t xlat_tables[MAX_XLAT_TABLES][XLAT_TABLE_ENTRIES]
	__aligned(XLAT_TABLE_SIZE) __section(".nozi.mmu.l2");

/* MMU L2 table for TAs, one for each thread */
static uint64_t xlat_tables_ul1[CFG_NUM_THREADS][XLAT_TABLE_ENTRIES]
	__aligned(XLAT_TABLE_SIZE) __section(".nozi.mmu.l2");


static unsigned int next_xlat;
static uint64_t tcr_ps_bits;
static int user_va_idx = -1;

static uint32_t desc_to_mattr(unsigned level, uint64_t desc)
{
	uint32_t a;

	if (!(desc & 1)) {
		if (desc & HIDDEN_DESC)
			return TEE_MATTR_HIDDEN_BLOCK;
		if (desc & HIDDEN_DIRTY_DESC)
			return TEE_MATTR_HIDDEN_DIRTY_BLOCK;
		return 0;
	}

	if (level == 3) {
		if ((desc & DESC_ENTRY_TYPE_MASK) != L3_BLOCK_DESC)
			return 0;
	} else {
		if ((desc & DESC_ENTRY_TYPE_MASK) == TABLE_DESC)
			return TEE_MATTR_TABLE;
	}

	a = TEE_MATTR_VALID_BLOCK;

	if (desc & LOWER_ATTRS(ACCESS_FLAG))
		a |= TEE_MATTR_PRX | TEE_MATTR_URX;

	if (!(desc & LOWER_ATTRS(AP_RO)))
		a |= TEE_MATTR_PW | TEE_MATTR_UW;

	if (!(desc & LOWER_ATTRS(AP_UNPRIV)))
		a &= ~TEE_MATTR_URWX;

	if (desc & UPPER_ATTRS(XN))
		a &= ~(TEE_MATTR_PX | TEE_MATTR_UX);

	if (desc & UPPER_ATTRS(PXN))
		a &= ~TEE_MATTR_PX;

	COMPILE_TIME_ASSERT(ATTR_DEVICE_INDEX == TEE_MATTR_CACHE_NONCACHE);
	COMPILE_TIME_ASSERT(ATTR_IWBWA_OWBWA_NTR_INDEX ==
			    TEE_MATTR_CACHE_CACHED);

	a |= ((desc & LOWER_ATTRS(ATTR_INDEX_MASK)) >> LOWER_ATTRS_SHIFT) <<
	     TEE_MATTR_CACHE_SHIFT;

	if (!(desc & LOWER_ATTRS(NON_GLOBAL)))
		a |= TEE_MATTR_GLOBAL;

	if (!(desc & LOWER_ATTRS(NS)))
		a |= TEE_MATTR_SECURE;

	return a;
}

static uint64_t mattr_to_desc(unsigned level, uint32_t attr)
{
	uint64_t desc;
	uint32_t a = attr;

	if (a & TEE_MATTR_HIDDEN_BLOCK)
		return INVALID_DESC | HIDDEN_DESC;

	if (a & TEE_MATTR_HIDDEN_DIRTY_BLOCK)
		return INVALID_DESC | HIDDEN_DIRTY_DESC;

	if (a & TEE_MATTR_TABLE)
		return TABLE_DESC;

	if (!(a & TEE_MATTR_VALID_BLOCK))
		return 0;

	if (a & (TEE_MATTR_PX | TEE_MATTR_PW))
		a |= TEE_MATTR_PR;
	if (a & (TEE_MATTR_UX | TEE_MATTR_UW))
		a |= TEE_MATTR_UR;
	if (a & TEE_MATTR_UR)
		a |= TEE_MATTR_PR;
	if (a & TEE_MATTR_UW)
		a |= TEE_MATTR_PW;

	if (level == 3)
		desc = L3_BLOCK_DESC;
	else
		desc = BLOCK_DESC;

	if (!(a & (TEE_MATTR_PX | TEE_MATTR_UX)))
		desc |= UPPER_ATTRS(XN);
	if (!(a & TEE_MATTR_PX))
		desc |= UPPER_ATTRS(PXN);

	if (a & TEE_MATTR_UR)
		desc |= LOWER_ATTRS(AP_UNPRIV);

	if (!(a & TEE_MATTR_PW))
		desc |= LOWER_ATTRS(AP_RO);

	/* Keep in sync with core_mmu.c:core_mmu_mattr_is_ok */
	switch ((a >> TEE_MATTR_CACHE_SHIFT) & TEE_MATTR_CACHE_MASK) {
	case TEE_MATTR_CACHE_NONCACHE:
		desc |= LOWER_ATTRS(ATTR_DEVICE_INDEX | OSH);
		break;
	case TEE_MATTR_CACHE_CACHED:
		desc |= LOWER_ATTRS(ATTR_IWBWA_OWBWA_NTR_INDEX | ISH);
		break;
	default:
		/*
		 * "Can't happen" the attribute is supposed to be checked
		 * with core_mmu_mattr_is_ok() before.
		 */
		panic();
	}

	if (a & (TEE_MATTR_UR | TEE_MATTR_PR))
		desc |= LOWER_ATTRS(ACCESS_FLAG);

	if (!(a & TEE_MATTR_GLOBAL))
		desc |= LOWER_ATTRS(NON_GLOBAL);

	desc |= a & TEE_MATTR_SECURE ? 0 : LOWER_ATTRS(NS);

	return desc;
}

static uint64_t mmap_desc(uint32_t attr, uint64_t addr_pa,
					unsigned level)
{
	return mattr_to_desc(level, attr) | addr_pa;
}

static int mmap_region_attr(struct tee_mmap_region *mm, uint64_t base_va,
					uint64_t size)
{
	uint32_t attr = mm->attr;

	for (;;) {
		mm++;

		if (core_mmap_is_end_of_table(mm))
			return attr; /* Reached end of list */

		if (mm->va >= base_va + size)
			return attr; /* Next region is after area so end */

		if (mm->va + mm->size <= base_va)
			continue; /* Next region has already been overtaken */

		if (mm->attr == attr)
			continue; /* Region doesn't override attribs so skip */

		if (mm->va > base_va ||
			mm->va + mm->size < base_va + size)
			return -1; /* Region doesn't fully cover our area */
	}
}

static struct tee_mmap_region *init_xlation_table(struct tee_mmap_region *mm,
			uint64_t base_va, uint64_t *table, unsigned level)
{
	unsigned int level_size_shift = L1_XLAT_ADDRESS_SHIFT - (level - 1) *
						XLAT_TABLE_ENTRIES_SHIFT;
	unsigned int level_size = BIT32(level_size_shift);
	uint64_t level_index_msk = SHIFT_U64(XLAT_TABLE_ENTRIES_MASK,
					     level_size_shift);

	assert(level <= 3);

	debug_print("New xlat table (level %u):", level);

	do  {
		uint64_t desc = UNSET_DESC;

		/* Skip unmapped entries */
		while (!core_mmap_is_end_of_table(mm) &&
		       core_mmu_is_dynamic_vaspace(mm))
			mm++;
		if (core_mmap_is_end_of_table(mm))
			break;

		if (mm->va + mm->size <= base_va) {
			/* Area now after the region so skip it */
			mm++;
			continue;
		}

		if (mm->va >= base_va + level_size) {
			/* Next region is after area so nothing to map yet */
			desc = INVALID_DESC;
			debug_print("%*s%010" PRIx64 " %8x",
					level * 2, "", base_va, level_size);
		} else if (mm->va <= base_va &&
			   mm->va + mm->size >= base_va + level_size &&
			   !(mm->pa & (level_size - 1))) {
			/* Next region covers all of area */
			int attr = mmap_region_attr(mm, base_va, level_size);

			if (attr >= 0) {
				desc = mmap_desc(attr,
						 base_va - mm->va + mm->pa,
						 level);
				debug_print("%*s%010" PRIx64 " %8x %s-%s-%s-%s",
					level * 2, "", base_va, level_size,
					attr & (TEE_MATTR_CACHE_CACHED <<
						TEE_MATTR_CACHE_SHIFT) ?
						"MEM" : "DEV",
					attr & TEE_MATTR_PW ? "RW" : "RO",
					attr & TEE_MATTR_PX ? "X" : "XN",
					attr & TEE_MATTR_SECURE ? "S" : "NS");
			} else {
				debug_print("%*s%010" PRIx64 " %8x",
					level * 2, "", base_va, level_size);
			}
		}
		/* else Next region only partially covers area, so need */

		if (desc == UNSET_DESC) {
			/* Area not covered by a region so need finer table */
			uint64_t *new_table = xlat_tables[next_xlat++];

			/* Clear table before use */
			DMSG("xlat used: %d/%d", next_xlat, MAX_XLAT_TABLES);
			if (next_xlat > MAX_XLAT_TABLES)
				panic("running out of xlat tables");
			memset(new_table, 0, XLAT_TABLE_SIZE);

			desc = TABLE_DESC | virt_to_phys(new_table);

			/* Recurse to fill in new table */
			mm = init_xlation_table(mm, base_va, new_table,
					   level + 1);
		}

		*table++ = desc;
		base_va += level_size;
	} while (!core_mmap_is_end_of_table(mm) && (base_va & level_index_msk));

	return mm;
}

static unsigned int calc_physical_addr_size_bits(uint64_t max_addr)
{
	/* Physical address can't exceed 48 bits */
	assert(!(max_addr & ADDR_MASK_48_TO_63));

	/* 48 bits address */
	if (max_addr & ADDR_MASK_44_TO_47)
		return TCR_PS_BITS_256TB;

	/* 44 bits address */
	if (max_addr & ADDR_MASK_42_TO_43)
		return TCR_PS_BITS_16TB;

	/* 42 bits address */
	if (max_addr & ADDR_MASK_40_TO_41)
		return TCR_PS_BITS_4TB;

	/* 40 bits address */
	if (max_addr & ADDR_MASK_36_TO_39)
		return TCR_PS_BITS_1TB;

	/* 36 bits address */
	if (max_addr & ADDR_MASK_32_TO_35)
		return TCR_PS_BITS_64GB;

	return TCR_PS_BITS_4GB;
}

void core_init_mmu_tables(struct tee_mmap_region *mm)
{
	paddr_t max_pa = 0;
	uint64_t max_va = 0;
	size_t n;

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++) {
		paddr_t pa_end;
		vaddr_t va_end;

		debug_print(" %010" PRIxVA " %010" PRIxPA " %10zx %x",
			    mm[n].va, mm[n].pa, mm[n].size, mm[n].attr);

		if (!IS_PAGE_ALIGNED(mm[n].pa) || !IS_PAGE_ALIGNED(mm[n].size))
			panic("unaligned region");

		pa_end = mm[n].pa + mm[n].size - 1;
		va_end = mm[n].va + mm[n].size - 1;
		if (pa_end > max_pa)
			max_pa = pa_end;
		if (va_end > max_va)
			max_va = va_end;
	}

	/* Clear table before use */
	memset(l1_xlation_table[0], 0, NUM_L1_ENTRIES * XLAT_ENTRY_SIZE);
	init_xlation_table(mm, 0, l1_xlation_table[0], 1);
	for (n = 1; n < CFG_TEE_CORE_NB_CORE; n++)
		memcpy(l1_xlation_table[n], l1_xlation_table[0],
			XLAT_ENTRY_SIZE * NUM_L1_ENTRIES);

	for (n = 1; n < NUM_L1_ENTRIES; n++) {
		if (!l1_xlation_table[0][n]) {
			user_va_idx = n;
			break;
		}
	}
	assert(user_va_idx != -1);

	tcr_ps_bits = calc_physical_addr_size_bits(max_pa);
	COMPILE_TIME_ASSERT(CFG_LPAE_ADDR_SPACE_SIZE > 0);
	assert(max_va < CFG_LPAE_ADDR_SPACE_SIZE);
}

bool core_mmu_place_tee_ram_at_top(paddr_t paddr)
{
	size_t l1size = (1 << L1_XLAT_ADDRESS_SHIFT);
	paddr_t l1mask = l1size - 1;

	return (paddr & l1mask) > (l1size / 2);
}

#ifdef ARM32
void core_init_mmu_regs(void)
{
	uint32_t ttbcr = TTBCR_EAE;
	uint32_t mair;
	paddr_t ttbr0;

	ttbr0 = virt_to_phys(l1_xlation_table[get_core_pos()]);

	mair  = MAIR_ATTR_SET(ATTR_DEVICE, ATTR_DEVICE_INDEX);
	mair |= MAIR_ATTR_SET(ATTR_IWBWA_OWBWA_NTR, ATTR_IWBWA_OWBWA_NTR_INDEX);
	write_mair0(mair);

	ttbcr |= TTBCR_XRGNX_WBWA << TTBCR_IRGN0_SHIFT;
	ttbcr |= TTBCR_XRGNX_WBWA << TTBCR_ORGN0_SHIFT;
	ttbcr |= TTBCR_SHX_ISH << TTBCR_SH0_SHIFT;

	/* Disable the use of TTBR1 */
	ttbcr |= TTBCR_EPD1;

	/* TTBCR.A1 = 0 => ASID is stored in TTBR0 */

	write_ttbcr(ttbcr);
	write_ttbr0_64bit(ttbr0);
	write_ttbr1_64bit(0);
}
#endif /*ARM32*/

#ifdef ARM64
void core_init_mmu_regs(void)
{
	uint64_t mair;
	uint64_t tcr;
	paddr_t ttbr0;

	ttbr0 = virt_to_phys(l1_xlation_table[get_core_pos()]);

	mair  = MAIR_ATTR_SET(ATTR_DEVICE, ATTR_DEVICE_INDEX);
	mair |= MAIR_ATTR_SET(ATTR_IWBWA_OWBWA_NTR, ATTR_IWBWA_OWBWA_NTR_INDEX);
	write_mair_el1(mair);

	tcr = TCR_RES1;
	tcr |= TCR_XRGNX_WBWA << TCR_IRGN0_SHIFT;
	tcr |= TCR_XRGNX_WBWA << TCR_ORGN0_SHIFT;
	tcr |= TCR_SHX_ISH << TCR_SH0_SHIFT;
	tcr |= tcr_ps_bits << TCR_EL1_IPS_SHIFT;
	tcr |= 64 - __builtin_ctzl(CFG_LPAE_ADDR_SPACE_SIZE);

	/* Disable the use of TTBR1 */
	tcr |= TCR_EPD1;

	/*
	 * TCR.A1 = 0 => ASID is stored in TTBR0
	 * TCR.AS = 0 => Same ASID size as in Aarch32/ARMv7
	 */

	write_tcr_el1(tcr);
	write_ttbr0_el1(ttbr0);
	write_ttbr1_el1(0);
}
#endif /*ARM64*/

KEEP_PAGER(core_init_mmu_regs);

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
		unsigned level, vaddr_t va_base, void *table)
{
	tbl_info->level = level;
	tbl_info->table = table;
	tbl_info->va_base = va_base;
	tbl_info->shift = L1_XLAT_ADDRESS_SHIFT -
			  (level - 1) * XLAT_TABLE_ENTRIES_SHIFT;
	assert(level <= 3);
	if (level == 1)
		tbl_info->num_entries = NUM_L1_ENTRIES;
	else
		tbl_info->num_entries = XLAT_TABLE_ENTRIES;
}

void core_mmu_get_user_pgdir(struct core_mmu_table_info *pgd_info)
{
	vaddr_t va_range_base;
	void *tbl = xlat_tables_ul1[thread_get_id()];

	core_mmu_get_user_va_range(&va_range_base, NULL);
	core_mmu_set_info_table(pgd_info, 2, va_range_base, tbl);
}

void core_mmu_create_user_map(struct user_ta_ctx *utc,
			      struct core_mmu_user_map *map)
{
	struct core_mmu_table_info dir_info;

	COMPILE_TIME_ASSERT(sizeof(uint64_t) * XLAT_TABLE_ENTRIES == PGT_SIZE);

	core_mmu_get_user_pgdir(&dir_info);
	memset(dir_info.table, 0, PGT_SIZE);
	core_mmu_populate_user_map(&dir_info, utc);
	map->user_map = virt_to_phys(dir_info.table) | TABLE_DESC;
	map->asid = utc->context & TTBR_ASID_MASK;
}

bool core_mmu_find_table(vaddr_t va, unsigned max_level,
		struct core_mmu_table_info *tbl_info)
{
	uint64_t *tbl = l1_xlation_table[get_core_pos()];
	uintptr_t ntbl;
	unsigned level = 1;
	vaddr_t va_base = 0;
	unsigned num_entries = NUM_L1_ENTRIES;

	while (true) {
		unsigned level_size_shift =
			L1_XLAT_ADDRESS_SHIFT - (level - 1) *
						XLAT_TABLE_ENTRIES_SHIFT;
		unsigned n = (va - va_base) >> level_size_shift;

		if (n >= num_entries)
			return false;

		if (level == max_level || level == 3 ||
			(tbl[n] & TABLE_DESC) != TABLE_DESC) {
			/*
			 * We've either reached max_level, level 3, a block
			 * mapping entry or an "invalid" mapping entry.
			 */
			tbl_info->table = tbl;
			tbl_info->va_base = va_base;
			tbl_info->level = level;
			tbl_info->shift = level_size_shift;
			tbl_info->num_entries = num_entries;
			return true;
		}

		/* Copy bits 39:12 from tbl[n] to ntbl */
		ntbl = (tbl[n] & ((1ULL << 40) - 1)) & ~((1 << 12) - 1);

		tbl = phys_to_virt(ntbl, MEM_AREA_TEE_RAM_RW_DATA);
		if (!tbl)
			return false;

		va_base += (vaddr_t)n << level_size_shift;
		level++;
		num_entries = XLAT_TABLE_ENTRIES;
	}
}

bool core_mmu_divide_block(struct core_mmu_table_info *tbl_info,
			   unsigned int idx)
{
	uint64_t *new_table;
	uint64_t *entry;
	uint64_t new_table_desc;
	size_t new_entry_size;
	paddr_t paddr;
	uint32_t attr;
	int i;
	bool flush_tlb;

	if (tbl_info->level >= 3)
		return false;

	if (next_xlat >= MAX_XLAT_TABLES)
		return false;

	if (tbl_info->level == 1 && idx >= NUM_L1_ENTRIES)
		return false;

	if (tbl_info->level > 1 && idx >= XLAT_TABLE_ENTRIES)
		return false;

	entry = (uint64_t *)tbl_info->table + idx;
	assert(!*entry || (*entry & DESC_ENTRY_TYPE_MASK) == BLOCK_DESC);

	/* We need to flush TLBs only if there already was some mapping */
	flush_tlb = *entry;

	new_table = xlat_tables[next_xlat++];
	new_table_desc = TABLE_DESC | (uint64_t)(uintptr_t)new_table;

	/* store attributes of original block */
	attr = desc_to_mattr(tbl_info->level, *entry);
	paddr = *entry & OUTPUT_ADDRESS_MASK;
	new_entry_size = 1 << (tbl_info->shift - XLAT_TABLE_ENTRIES_SHIFT);

	/* Fill new xlat table with entries pointing to the same memory */
	for (i = 0; i < XLAT_TABLE_ENTRIES; i++) {
		*new_table = paddr | mattr_to_desc(tbl_info->level + 1, attr);
		paddr += new_entry_size;
		new_table++;
	}

	/* Update descriptor at current level */
	*entry = new_table_desc;

	if (flush_tlb)
		tlbi_all();
	return true;
}

void core_mmu_set_entry_primitive(void *table, size_t level, size_t idx,
				  paddr_t pa, uint32_t attr)
{
	uint64_t *tbl = table;
	uint64_t desc = mattr_to_desc(level, attr);

	tbl[idx] = desc | pa;
}

void core_mmu_get_entry_primitive(const void *table, size_t level,
				  size_t idx, paddr_t *pa, uint32_t *attr)
{
	const uint64_t *tbl = table;

	if (pa)
		*pa = (tbl[idx] & ((1ull << 40) - 1)) & ~((1 << 12) - 1);

	if (attr)
		*attr = desc_to_mattr(level, tbl[idx]);
}

bool core_mmu_user_va_range_is_defined(void)
{
	return user_va_idx != -1;
}

void core_mmu_get_user_va_range(vaddr_t *base, size_t *size)
{
	assert(user_va_idx != -1);

	if (base)
		*base = (vaddr_t)user_va_idx << L1_XLAT_ADDRESS_SHIFT;
	if (size)
		*size = 1 << L1_XLAT_ADDRESS_SHIFT;
}

bool core_mmu_user_mapping_is_active(void)
{
	assert(user_va_idx != -1);
	return !!l1_xlation_table[get_core_pos()][user_va_idx];
}

#ifdef ARM32
void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	assert(user_va_idx != -1);

	map->user_map = l1_xlation_table[get_core_pos()][user_va_idx];
	if (map->user_map) {
		map->asid = (read_ttbr0_64bit() >> TTBR_ASID_SHIFT) &
			    TTBR_ASID_MASK;
	} else {
		map->asid = 0;
	}
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	uint64_t ttbr;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	assert(user_va_idx != -1);

	ttbr = read_ttbr0_64bit();
	/* Clear ASID */
	ttbr &= ~((uint64_t)TTBR_ASID_MASK << TTBR_ASID_SHIFT);
	write_ttbr0_64bit(ttbr);
	isb();

	/* Set the new map */
	if (map && map->user_map) {
		l1_xlation_table[get_core_pos()][user_va_idx] = map->user_map;
		dsb();	/* Make sure the write above is visible */
		ttbr |= ((uint64_t)map->asid << TTBR_ASID_SHIFT);
		write_ttbr0_64bit(ttbr);
		isb();
	} else {
		l1_xlation_table[get_core_pos()][user_va_idx] = 0;
		dsb();	/* Make sure the write above is visible */
	}

	tlbi_all();

	thread_unmask_exceptions(exceptions);
}

enum core_mmu_fault core_mmu_get_fault_type(uint32_t fault_descr)
{
	assert(fault_descr & FSR_LPAE);

	switch (fault_descr & FSR_STATUS_MASK) {
	case 0x21: /* b100001 Alignment fault */
		return CORE_MMU_FAULT_ALIGNMENT;
	case 0x11: /* b010001 Asynchronous extern abort (DFSR only) */
		return CORE_MMU_FAULT_ASYNC_EXTERNAL;
	case 0x12: /* b100010 Debug event */
		return CORE_MMU_FAULT_DEBUG_EVENT;
	default:
		break;
	}

	switch ((fault_descr & FSR_STATUS_MASK) >> 2) {
	case 0x1: /* b0001LL Translation fault */
		return CORE_MMU_FAULT_TRANSLATION;
	case 0x2: /* b0010LL Access flag fault */
	case 0x3: /* b0011LL Permission fault */
		if (fault_descr & FSR_WNR)
			return CORE_MMU_FAULT_WRITE_PERMISSION;
		else
			return CORE_MMU_FAULT_READ_PERMISSION;
	default:
		return CORE_MMU_FAULT_OTHER;
	}
}
#endif /*ARM32*/

#ifdef ARM64
void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	assert(user_va_idx != -1);

	map->user_map = l1_xlation_table[get_core_pos()][user_va_idx];
	if (map->user_map) {
		map->asid = (read_ttbr0_el1() >> TTBR_ASID_SHIFT) &
			    TTBR_ASID_MASK;
	} else {
		map->asid = 0;
	}
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	uint64_t ttbr;
	uint32_t daif = read_daif();

	write_daif(daif | DAIF_AIF);

	ttbr = read_ttbr0_el1();
	/* Clear ASID */
	ttbr &= ~((uint64_t)TTBR_ASID_MASK << TTBR_ASID_SHIFT);
	write_ttbr0_el1(ttbr);
	isb();

	/* Set the new map */
	if (map && map->user_map) {
		l1_xlation_table[get_core_pos()][user_va_idx] = map->user_map;
		dsb();	/* Make sure the write above is visible */
		ttbr |= ((uint64_t)map->asid << TTBR_ASID_SHIFT);
		write_ttbr0_el1(ttbr);
		isb();
	} else {
		l1_xlation_table[get_core_pos()][user_va_idx] = 0;
		dsb();	/* Make sure the write above is visible */
	}

	tlbi_all();

	write_daif(daif);
}

enum core_mmu_fault core_mmu_get_fault_type(uint32_t fault_descr)
{
	switch ((fault_descr >> ESR_EC_SHIFT) & ESR_EC_MASK) {
	case ESR_EC_SP_ALIGN:
	case ESR_EC_PC_ALIGN:
		return CORE_MMU_FAULT_ALIGNMENT;
	case ESR_EC_IABT_EL0:
	case ESR_EC_DABT_EL0:
	case ESR_EC_IABT_EL1:
	case ESR_EC_DABT_EL1:
		switch (fault_descr & ESR_FSC_MASK) {
		case ESR_FSC_TRANS_L0:
		case ESR_FSC_TRANS_L1:
		case ESR_FSC_TRANS_L2:
		case ESR_FSC_TRANS_L3:
			return CORE_MMU_FAULT_TRANSLATION;
		case ESR_FSC_ACCF_L1:
		case ESR_FSC_ACCF_L2:
		case ESR_FSC_ACCF_L3:
		case ESR_FSC_PERMF_L1:
		case ESR_FSC_PERMF_L2:
		case ESR_FSC_PERMF_L3:
			if (fault_descr & ESR_ABT_WNR)
				return CORE_MMU_FAULT_WRITE_PERMISSION;
			else
				return CORE_MMU_FAULT_READ_PERMISSION;
		case ESR_FSC_ALIGN:
			return CORE_MMU_FAULT_ALIGNMENT;
		default:
			return CORE_MMU_FAULT_OTHER;
		}
	default:
		return CORE_MMU_FAULT_OTHER;
	}
}
#endif /*ARM64*/
