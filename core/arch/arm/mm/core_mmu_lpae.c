// SPDX-License-Identifier: (BSD-2-Clause AND BSD-3-Clause)
/*
 * Copyright (c) 2015-2016, 2022 Linaro Limited
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
 * Copyright (c) 2014, 2022, ARM Limited and Contributors. All rights reserved.
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
#include <config.h>
#include <inttypes.h>
#include <keep.h>
#include <kernel/cache_helpers.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/tlb_helpers.h>
#include <memtag.h>
#include <mm/core_memprot.h>
#include <mm/pgt_cache.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

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

#define XN			(1ull << 2)
#define PXN			(1ull << 1)
#define CONT_HINT		(1ull << 0)

#define UPPER_ATTRS(x)		(((x) & 0x7) << 52)
#define GP                      BIT64(50)   /* Guarded Page, Aarch64 FEAT_BTI */
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

#define ATTR_DEVICE_nGnRE_INDEX		0x0
#define ATTR_IWBWA_OWBWA_NTR_INDEX	0x1
#define ATTR_DEVICE_nGnRnE_INDEX	0x2
#define ATTR_TAGGED_NORMAL_MEM_INDEX	0x3
#define ATTR_INDEX_MASK			0x7

#define ATTR_DEVICE_nGnRnE		(0x0)
#define ATTR_DEVICE_nGnRE		(0x4)
#define ATTR_IWBWA_OWBWA_NTR		(0xff)
/* Same as ATTR_IWBWA_OWBWA_NTR but with memory tagging.  */
#define ATTR_TAGGED_NORMAL_MEM		(0xf0)

#define MAIR_ATTR_SET(attr, index)	(((uint64_t)attr) << ((index) << 3))

#define OUTPUT_ADDRESS_MASK	(0x0000FFFFFFFFF000ULL)

/* (internal) physical address size bits in EL3/EL1 */
#define TCR_PS_BITS_4GB		(0x0)
#define TCR_PS_BITS_64GB	(0x1)
#define TCR_PS_BITS_1TB		(0x2)
#define TCR_PS_BITS_4TB		(0x3)
#define TCR_PS_BITS_16TB	(0x4)
#define TCR_PS_BITS_256TB	(0x5)
#define TCR_PS_BITS_4PB		(0x6)

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

#define XLAT_TABLE_LEVEL_MAX	U(3)

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
#define L0_XLAT_ADDRESS_SHIFT	(L1_XLAT_ADDRESS_SHIFT + \
				 XLAT_TABLE_ENTRIES_SHIFT)
#define XLAT_ADDR_SHIFT(level)	(PAGE_SIZE_SHIFT + \
				 ((XLAT_TABLE_LEVEL_MAX - (level)) * \
				 XLAT_TABLE_ENTRIES_SHIFT))

#define XLAT_BLOCK_SIZE(level)	(UL(1) << XLAT_ADDR_SHIFT(level))

/* Base table */
#define BASE_XLAT_ADDRESS_SHIFT	XLAT_ADDR_SHIFT(CORE_MMU_BASE_TABLE_LEVEL)
#define BASE_XLAT_BLOCK_SIZE	XLAT_BLOCK_SIZE(CORE_MMU_BASE_TABLE_LEVEL)

#define NUM_BASE_LEVEL_ENTRIES	\
	BIT(CFG_LPAE_ADDR_SPACE_BITS - BASE_XLAT_ADDRESS_SHIFT)

/*
 * MMU L1 table, one for each core
 *
 * With CFG_CORE_UNMAP_CORE_AT_EL0, each core has one table to be used
 * while in kernel mode and one to be used while in user mode.
 */
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
#define NUM_BASE_TABLES	2
#else
#define NUM_BASE_TABLES	1
#endif

#ifndef MAX_XLAT_TABLES
#ifdef CFG_NS_VIRTUALIZATION
#	define XLAT_TABLE_VIRTUALIZATION_EXTRA 3
#else
#	define XLAT_TABLE_VIRTUALIZATION_EXTRA 0
#endif
#ifdef CFG_CORE_ASLR
#	define XLAT_TABLE_ASLR_EXTRA 3
#else
#	define XLAT_TABLE_ASLR_EXTRA 0
#endif
#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
#	define XLAT_TABLE_TEE_EXTRA 8
#	define XLAT_TABLE_USER_EXTRA (NUM_BASE_TABLES * CFG_TEE_CORE_NB_CORE)
#else
#	define XLAT_TABLE_TEE_EXTRA 5
#	define XLAT_TABLE_USER_EXTRA 0
#endif
#define MAX_XLAT_TABLES		(XLAT_TABLE_TEE_EXTRA + \
				 XLAT_TABLE_VIRTUALIZATION_EXTRA + \
				 XLAT_TABLE_ASLR_EXTRA + \
				 XLAT_TABLE_USER_EXTRA)
#endif /*!MAX_XLAT_TABLES*/

#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
#if (MAX_XLAT_TABLES <= UINT8_MAX)
typedef uint8_t l1_idx_t;
#elif (MAX_XLAT_TABLES <= UINT16_MAX)
typedef uint16_t l1_idx_t;
#else
#error MAX_XLAT_TABLES is suspiciously large, please check
#endif
#endif

typedef uint64_t base_xlat_tbls_t[CFG_TEE_CORE_NB_CORE][NUM_BASE_LEVEL_ENTRIES];
typedef uint64_t xlat_tbl_t[XLAT_TABLE_ENTRIES];

static base_xlat_tbls_t base_xlation_table[NUM_BASE_TABLES]
	__aligned(NUM_BASE_LEVEL_ENTRIES * XLAT_ENTRY_SIZE)
	__section(".nozi.mmu.base_table");

static xlat_tbl_t xlat_tables[MAX_XLAT_TABLES]
	__aligned(XLAT_TABLE_SIZE) __section(".nozi.mmu.l2");

#define XLAT_TABLES_SIZE	(sizeof(xlat_tbl_t) * MAX_XLAT_TABLES)

/* MMU L2 table for TAs, one for each thread */
static xlat_tbl_t xlat_tables_ul1[CFG_NUM_THREADS]
	__aligned(XLAT_TABLE_SIZE) __section(".nozi.mmu.l2");

/*
 * TAs page table entry inside a level 1 page table.
 *
 * TAs mapping is expected to start from level 2.
 *
 * If base level is 1 then this is the index of a level 1 entry,
 * that will point directly into TA mapping table.
 *
 * If base level is 0 then entry 0 in base table is always used, and then
 * we fallback to "base level == 1" like scenario.
 */
static int user_va_idx __nex_data = -1;

struct mmu_partition {
	base_xlat_tbls_t *base_tables;
	xlat_tbl_t *xlat_tables;
	xlat_tbl_t *l2_ta_tables;
	unsigned int xlat_tables_used;
	unsigned int asid;

#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
	/*
	 * Indexes of the L1 table from 'xlat_tables'
	 * that points to the user mappings.
	 */
	l1_idx_t user_l1_table_idx[NUM_BASE_TABLES][CFG_TEE_CORE_NB_CORE];
#endif
};

static struct mmu_partition default_partition __nex_data = {
	.base_tables = base_xlation_table,
	.xlat_tables = xlat_tables,
	.l2_ta_tables = xlat_tables_ul1,
	.xlat_tables_used = 0,
	.asid = 0
};

#ifdef CFG_NS_VIRTUALIZATION
static struct mmu_partition *current_prtn[CFG_TEE_CORE_NB_CORE] __nex_bss;
#endif

static struct mmu_partition *get_prtn(void)
{
#ifdef CFG_NS_VIRTUALIZATION
	struct mmu_partition *ret;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	ret = current_prtn[get_core_pos()];

	thread_unmask_exceptions(exceptions);
	return ret;
#else
	return &default_partition;
#endif
}

static uint32_t desc_to_mattr(unsigned level, uint64_t desc)
{
	uint32_t a;

	if (!(desc & 1))
		return 0;

	if (level == XLAT_TABLE_LEVEL_MAX) {
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

	COMPILE_TIME_ASSERT(ATTR_DEVICE_nGnRnE_INDEX ==
			    TEE_MATTR_MEM_TYPE_STRONGLY_O);
	COMPILE_TIME_ASSERT(ATTR_DEVICE_nGnRE_INDEX == TEE_MATTR_MEM_TYPE_DEV);
	COMPILE_TIME_ASSERT(ATTR_IWBWA_OWBWA_NTR_INDEX ==
			    TEE_MATTR_MEM_TYPE_CACHED);
	COMPILE_TIME_ASSERT(ATTR_TAGGED_NORMAL_MEM_INDEX ==
			    TEE_MATTR_MEM_TYPE_TAGGED);

	a |= ((desc & LOWER_ATTRS(ATTR_INDEX_MASK)) >> LOWER_ATTRS_SHIFT) <<
	     TEE_MATTR_MEM_TYPE_SHIFT;

	if (!(desc & LOWER_ATTRS(NON_GLOBAL)))
		a |= TEE_MATTR_GLOBAL;

	if (!(desc & LOWER_ATTRS(NS)))
		a |= TEE_MATTR_SECURE;

	if (desc & GP)
		a |= TEE_MATTR_GUARDED;

	return a;
}

static uint64_t mattr_to_desc(unsigned level, uint32_t attr)
{
	uint64_t desc;
	uint32_t a = attr;

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

	if (IS_ENABLED(CFG_CORE_BTI) && (a & TEE_MATTR_PX))
		a |= TEE_MATTR_GUARDED;

	if (level == XLAT_TABLE_LEVEL_MAX)
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

	if (feat_bti_is_implemented() && (a & TEE_MATTR_GUARDED))
		desc |= GP;

	/* Keep in sync with core_mmu.c:core_mmu_mattr_is_ok */
	switch ((a >> TEE_MATTR_MEM_TYPE_SHIFT) & TEE_MATTR_MEM_TYPE_MASK) {
	case TEE_MATTR_MEM_TYPE_STRONGLY_O:
		desc |= LOWER_ATTRS(ATTR_DEVICE_nGnRnE_INDEX | OSH);
		break;
	case TEE_MATTR_MEM_TYPE_DEV:
		desc |= LOWER_ATTRS(ATTR_DEVICE_nGnRE_INDEX | OSH);
		break;
	case TEE_MATTR_MEM_TYPE_CACHED:
		desc |= LOWER_ATTRS(ATTR_IWBWA_OWBWA_NTR_INDEX | ISH);
		break;
	case TEE_MATTR_MEM_TYPE_TAGGED:
		desc |= LOWER_ATTRS(ATTR_TAGGED_NORMAL_MEM_INDEX | ISH);
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

#ifdef CFG_NS_VIRTUALIZATION
size_t core_mmu_get_total_pages_size(void)
{
	return ROUNDUP(sizeof(base_xlation_table), SMALL_PAGE_SIZE) +
		sizeof(xlat_tables) + sizeof(xlat_tables_ul1);
}

struct mmu_partition *core_alloc_mmu_prtn(void *tables)
{
	struct mmu_partition *prtn;
	uint8_t *tbl = tables;
	unsigned int asid = asid_alloc();

	assert(((vaddr_t)tbl) % SMALL_PAGE_SIZE == 0);

	if (!asid)
		return NULL;

	prtn = nex_malloc(sizeof(*prtn));
	if (!prtn) {
		asid_free(asid);
		return NULL;
	}

	prtn->base_tables = (void *)tbl;
	COMPILE_TIME_ASSERT(sizeof(base_xlation_table) <= SMALL_PAGE_SIZE);
	memset(prtn->base_tables, 0, SMALL_PAGE_SIZE);
	tbl += ROUNDUP(sizeof(base_xlation_table), SMALL_PAGE_SIZE);

	prtn->xlat_tables = (void *)tbl;
	memset(prtn->xlat_tables, 0, XLAT_TABLES_SIZE);
	tbl += XLAT_TABLES_SIZE;
	assert(((vaddr_t)tbl) % SMALL_PAGE_SIZE == 0);

	prtn->l2_ta_tables = (void *)tbl;
	prtn->xlat_tables_used = 0;
	prtn->asid = asid;

	return prtn;
}

void core_free_mmu_prtn(struct mmu_partition *prtn)
{
	asid_free(prtn->asid);
	nex_free(prtn);
}

void core_mmu_set_prtn(struct mmu_partition *prtn)
{
	uint64_t ttbr;
	/*
	 * We are changing mappings for current CPU,
	 * so make sure that we will not be rescheduled
	 */
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	current_prtn[get_core_pos()] = prtn;

	ttbr = virt_to_phys(prtn->base_tables[0][get_core_pos()]);

	write_ttbr0_el1(ttbr | ((paddr_t)prtn->asid << TTBR_ASID_SHIFT));
	isb();
	tlbi_all();
}

void core_mmu_set_default_prtn(void)
{
	core_mmu_set_prtn(&default_partition);
}

void core_mmu_set_default_prtn_tbl(void)
{
	size_t n = 0;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
		current_prtn[n] = &default_partition;
}
#endif

static uint64_t *core_mmu_xlat_table_alloc(struct mmu_partition *prtn)
{
	uint64_t *new_table = NULL;

	if (prtn->xlat_tables_used >= MAX_XLAT_TABLES) {
		EMSG("%u xlat tables exhausted", MAX_XLAT_TABLES);

		return NULL;
	}

	new_table = prtn->xlat_tables[prtn->xlat_tables_used++];

	DMSG("xlat tables used %u / %u",
	     prtn->xlat_tables_used, MAX_XLAT_TABLES);

	return new_table;
}

/*
 * Given an entry that points to a table returns the virtual address
 * of the pointed table. NULL otherwise.
 */
static void *core_mmu_xlat_table_entry_pa2va(struct mmu_partition *prtn,
					     unsigned int level,
					     uint64_t entry)
{
	paddr_t pa = 0;
	void *va = NULL;

	if ((entry & DESC_ENTRY_TYPE_MASK) != TABLE_DESC ||
	    level >= XLAT_TABLE_LEVEL_MAX)
		return NULL;

	pa = entry & OUTPUT_ADDRESS_MASK;

	if (!IS_ENABLED(CFG_NS_VIRTUALIZATION) || prtn == &default_partition)
		va = phys_to_virt(pa, MEM_AREA_TEE_RAM_RW_DATA,
				  XLAT_TABLE_SIZE);
	else
		va = phys_to_virt(pa, MEM_AREA_SEC_RAM_OVERALL,
				  XLAT_TABLE_SIZE);

	return va;
}

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
	uint64_t *orig_table = NULL;
	uint64_t *new_table = NULL;
	uint64_t *entry = NULL;
	struct mmu_partition *prtn = NULL;

#ifdef CFG_NS_VIRTUALIZATION
	prtn = tbl_info->prtn;
#else
	prtn = &default_partition;
#endif
	assert(prtn);

	if (idx >= tbl_info->num_entries)
		return false;

	entry = (uint64_t *)tbl_info->table + idx;

	/* Nothing to do for non-table entries */
	if ((*entry & DESC_ENTRY_TYPE_MASK) != TABLE_DESC ||
	    tbl_info->level >= XLAT_TABLE_LEVEL_MAX)
		return true;

	new_table = core_mmu_xlat_table_alloc(prtn);
	if (!new_table)
		return false;

	orig_table = core_mmu_xlat_table_entry_pa2va(prtn, tbl_info->level,
						     *entry);
	if (!orig_table)
		return false;

	/* Copy original table content to new table */
	memcpy(new_table, orig_table, XLAT_TABLE_ENTRIES * XLAT_ENTRY_SIZE);

	/* Point to the new table */
	*entry = virt_to_phys(new_table) | (*entry & ~OUTPUT_ADDRESS_MASK);

	return true;
}

static void core_init_mmu_prtn_tee(struct mmu_partition *prtn,
				   struct tee_mmap_region *mm)
{
	size_t n;

	assert(prtn && mm);

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++) {
		debug_print(" %010" PRIxVA " %010" PRIxPA " %10zx %x",
			    mm[n].va, mm[n].pa, mm[n].size, mm[n].attr);

		if (!IS_PAGE_ALIGNED(mm[n].pa) || !IS_PAGE_ALIGNED(mm[n].size))
			panic("unaligned region");
	}

	/* Clear table before use */
	memset(prtn->base_tables, 0, sizeof(base_xlation_table));

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++)
		if (!core_mmu_is_dynamic_vaspace(mm + n))
			core_mmu_map_region(prtn, mm + n);

	/*
	 * Primary mapping table is ready at index `get_core_pos()`
	 * whose value may not be ZERO. Take this index as copy source.
	 */
	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		if (n == get_core_pos())
			continue;

		memcpy(prtn->base_tables[0][n],
		       prtn->base_tables[0][get_core_pos()],
		       XLAT_ENTRY_SIZE * NUM_BASE_LEVEL_ENTRIES);
	}
}

/*
 * In order to support 32-bit TAs we will have to find
 * a user VA base in the region [1GB, 4GB[.
 * Due to OP-TEE design limitation, TAs page table should be an entry
 * inside a level 1 page table.
 *
 * Available options are only these:
 * - base level 0 entry 0 - [0GB, 512GB[
 *   - level 1 entry 0 - [0GB, 1GB[
 *   - level 1 entry 1 - [1GB, 2GB[           <----
 *   - level 1 entry 2 - [2GB, 3GB[           <----
 *   - level 1 entry 3 - [3GB, 4GB[           <----
 *   - level 1 entry 4 - [4GB, 5GB[
 *   - ...
 * - ...
 *
 * - base level 1 entry 0 - [0GB, 1GB[
 * - base level 1 entry 1 - [1GB, 2GB[        <----
 * - base level 1 entry 2 - [2GB, 3GB[        <----
 * - base level 1 entry 3 - [3GB, 4GB[        <----
 * - base level 1 entry 4 - [4GB, 5GB[
 * - ...
 */
static void set_user_va_idx(struct mmu_partition *prtn)
{
	uint64_t *tbl = NULL;
	unsigned int n = 0;

	assert(prtn);

	tbl = prtn->base_tables[0][get_core_pos()];

	/*
	 * If base level is 0, then we must use its entry 0.
	 */
	if (CORE_MMU_BASE_TABLE_LEVEL == 0) {
		/*
		 * If base level 0 entry 0 is not used then
		 * it's clear that we can use level 1 entry 1 inside it.
		 * (will be allocated later).
		 */
		if ((tbl[0] & DESC_ENTRY_TYPE_MASK) == INVALID_DESC) {
			user_va_idx = 1;

			return;
		}

		assert((tbl[0] & DESC_ENTRY_TYPE_MASK) == TABLE_DESC);

		tbl = core_mmu_xlat_table_entry_pa2va(prtn, 0, tbl[0]);
		assert(tbl);
	}

	/*
	 * Search level 1 table (i.e. 1GB mapping per entry) for
	 * an empty entry in the range [1GB, 4GB[.
	 */
	for (n = 1; n < 4; n++) {
		if ((tbl[n] & DESC_ENTRY_TYPE_MASK) == INVALID_DESC) {
			user_va_idx = n;
			break;
		}
	}

	assert(user_va_idx != -1);
}

/*
 * Setup an entry inside a core level 1 page table for TAs memory mapping
 *
 * If base table level is 1 - user_va_idx is already the index,
 *                            so nothing to do.
 * If base table level is 0 - we might need to allocate entry 0 of base table,
 *                            as TAs page table is an entry inside a level 1
 *                            page table.
 */
static void core_init_mmu_prtn_ta_core(struct mmu_partition *prtn
				       __maybe_unused,
				       unsigned int base_idx __maybe_unused,
				       unsigned int core __maybe_unused)
{
#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
	struct core_mmu_table_info tbl_info = { };
	uint64_t *tbl = NULL;
	uintptr_t idx = 0;

	assert(user_va_idx != -1);
	COMPILE_TIME_ASSERT(MAX_XLAT_TABLES <
			    (1 << (8 * sizeof(prtn->user_l1_table_idx[0][0]))));

	tbl = prtn->base_tables[base_idx][core];

	/*
	 * If base level is 0, then user_va_idx refers to
	 * level 1 page table that's in base level 0 entry 0.
	 */
	core_mmu_set_info_table(&tbl_info, 0, 0, tbl);
#ifdef CFG_NS_VIRTUALIZATION
	tbl_info.prtn = prtn;
#endif

	/*
	 * If this isn't the core that created the initial tables
	 * mappings, then the level 1 table must be copied,
	 * as it will hold pointer to the user mapping table
	 * that changes per core.
	 */
	if (core != get_core_pos()) {
		if (!core_mmu_entry_copy(&tbl_info, 0))
			panic();
	}

	if (!core_mmu_entry_to_finer_grained(&tbl_info, 0, true))
		panic();

	/*
	 * Now base level table should be ready with a table descriptor
	 */
	assert((tbl[0] & DESC_ENTRY_TYPE_MASK) == TABLE_DESC);

	tbl = core_mmu_xlat_table_entry_pa2va(prtn, 0, tbl[0]);
	assert(tbl);

	idx = ((uintptr_t)&tbl[user_va_idx] - (uintptr_t)prtn->xlat_tables) /
	      sizeof(xlat_tbl_t);
	assert(idx < prtn->xlat_tables_used);

	prtn->user_l1_table_idx[base_idx][core] = idx;
#endif
}

static void core_init_mmu_prtn_ta(struct mmu_partition *prtn)
{
	unsigned int base_idx = 0;
	unsigned int core = 0;

	assert(user_va_idx != -1);

	for (base_idx = 0; base_idx < NUM_BASE_TABLES; base_idx++)
		for (core = 0; core < CFG_TEE_CORE_NB_CORE; core++)
			core_init_mmu_prtn_ta_core(prtn, base_idx, core);
}

void core_init_mmu_prtn(struct mmu_partition *prtn, struct tee_mmap_region *mm)
{
	core_init_mmu_prtn_tee(prtn, mm);
	core_init_mmu_prtn_ta(prtn);
}

void core_init_mmu(struct tee_mmap_region *mm)
{
	uint64_t max_va = 0;
	size_t n;

	COMPILE_TIME_ASSERT(CORE_MMU_BASE_TABLE_SHIFT ==
			    XLAT_ADDR_SHIFT(CORE_MMU_BASE_TABLE_LEVEL));
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	COMPILE_TIME_ASSERT(CORE_MMU_BASE_TABLE_OFFSET ==
			   sizeof(base_xlation_table) / 2);
#endif
	COMPILE_TIME_ASSERT(XLAT_TABLES_SIZE == sizeof(xlat_tables));

	/* Initialize default pagetables */
	core_init_mmu_prtn_tee(&default_partition, mm);

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++) {
		vaddr_t va_end = mm[n].va + mm[n].size - 1;

		if (va_end > max_va)
			max_va = va_end;
	}

	set_user_va_idx(&default_partition);

	core_init_mmu_prtn_ta(&default_partition);

	COMPILE_TIME_ASSERT(CFG_LPAE_ADDR_SPACE_BITS > L1_XLAT_ADDRESS_SHIFT);
	assert(max_va < BIT64(CFG_LPAE_ADDR_SPACE_BITS));
}

#ifdef CFG_WITH_PAGER
/* Prefer to consume only 1 base xlat table for the whole mapping */
bool core_mmu_prefer_tee_ram_at_top(paddr_t paddr)
{
	size_t base_level_size = BASE_XLAT_BLOCK_SIZE;
	paddr_t base_level_mask = base_level_size - 1;

	return (paddr & base_level_mask) > (base_level_size / 2);
}
#endif

#ifdef ARM32
void core_init_mmu_regs(struct core_mmu_config *cfg)
{
	uint32_t ttbcr = 0;
	uint32_t mair = 0;

	cfg->ttbr0_base = virt_to_phys(base_xlation_table[0][0]);
	cfg->ttbr0_core_offset = sizeof(base_xlation_table[0][0]);

	mair  = MAIR_ATTR_SET(ATTR_DEVICE_nGnRE, ATTR_DEVICE_nGnRE_INDEX);
	mair |= MAIR_ATTR_SET(ATTR_IWBWA_OWBWA_NTR, ATTR_IWBWA_OWBWA_NTR_INDEX);
	mair |= MAIR_ATTR_SET(ATTR_DEVICE_nGnRnE, ATTR_DEVICE_nGnRnE_INDEX);
	/*
	 * Tagged memory isn't supported in 32-bit mode, map tagged memory
	 * as normal memory instead.
	 */
	mair |= MAIR_ATTR_SET(ATTR_IWBWA_OWBWA_NTR,
			      ATTR_TAGGED_NORMAL_MEM_INDEX);
	cfg->mair0 = mair;

	ttbcr = TTBCR_EAE;
	ttbcr |= TTBCR_XRGNX_WBWA << TTBCR_IRGN0_SHIFT;
	ttbcr |= TTBCR_XRGNX_WBWA << TTBCR_ORGN0_SHIFT;
	ttbcr |= TTBCR_SHX_ISH << TTBCR_SH0_SHIFT;
	ttbcr |= TTBCR_EPD1;	/* Disable the use of TTBR1 */

	/* TTBCR.A1 = 0 => ASID is stored in TTBR0 */
	cfg->ttbcr = ttbcr;
}
#endif /*ARM32*/

#ifdef ARM64
static unsigned int get_hard_coded_pa_size_bits(void)
{
	/*
	 * Intermediate Physical Address Size.
	 * 0b000      32 bits, 4GB.
	 * 0b001      36 bits, 64GB.
	 * 0b010      40 bits, 1TB.
	 * 0b011      42 bits, 4TB.
	 * 0b100      44 bits, 16TB.
	 * 0b101      48 bits, 256TB.
	 * 0b110      52 bits, 4PB
	 */
	static_assert(CFG_CORE_ARM64_PA_BITS >= 32);
	static_assert(CFG_CORE_ARM64_PA_BITS <= 52);

	if (CFG_CORE_ARM64_PA_BITS <= 32)
		return TCR_PS_BITS_4GB;

	if (CFG_CORE_ARM64_PA_BITS <= 36)
		return TCR_PS_BITS_64GB;

	if (CFG_CORE_ARM64_PA_BITS <= 40)
		return TCR_PS_BITS_1TB;

	if (CFG_CORE_ARM64_PA_BITS <= 42)
		return TCR_PS_BITS_4TB;

	if (CFG_CORE_ARM64_PA_BITS <= 44)
		return TCR_PS_BITS_16TB;

	if (CFG_CORE_ARM64_PA_BITS <= 48)
		return TCR_PS_BITS_256TB;

	/* CFG_CORE_ARM64_PA_BITS <= 48 */
	return TCR_PS_BITS_4PB;
}

static unsigned int get_physical_addr_size_bits(void)
{
	const unsigned int size_bits = read_id_aa64mmfr0_el1() &
				       ID_AA64MMFR0_EL1_PARANGE_MASK;
	unsigned int b = 0;

	if (IS_ENABLED(CFG_AUTO_MAX_PA_BITS))
		return size_bits;

	b = get_hard_coded_pa_size_bits();
	assert(b <= size_bits);
	return b;
}

unsigned int core_mmu_arm64_get_pa_width(void)
{
	const uint8_t map[] = { 32, 36, 40, 42, 44, 48, 52, };
	unsigned int size_bits = get_physical_addr_size_bits();

	size_bits = MIN(size_bits, ARRAY_SIZE(map) - 1);
	return map[size_bits];
}

void core_init_mmu_regs(struct core_mmu_config *cfg)
{
	uint64_t ips = get_physical_addr_size_bits();
	uint64_t mair = 0;
	uint64_t tcr = 0;

	cfg->ttbr0_el1_base = virt_to_phys(base_xlation_table[0][0]);
	cfg->ttbr0_core_offset = sizeof(base_xlation_table[0][0]);

	mair  = MAIR_ATTR_SET(ATTR_DEVICE_nGnRE, ATTR_DEVICE_nGnRE_INDEX);
	mair |= MAIR_ATTR_SET(ATTR_IWBWA_OWBWA_NTR, ATTR_IWBWA_OWBWA_NTR_INDEX);
	mair |= MAIR_ATTR_SET(ATTR_DEVICE_nGnRnE, ATTR_DEVICE_nGnRnE_INDEX);
	/*
	 * If MEMTAG isn't enabled, map tagged memory as normal memory
	 * instead.
	 */
	if (memtag_is_enabled())
		mair |= MAIR_ATTR_SET(ATTR_TAGGED_NORMAL_MEM,
				      ATTR_TAGGED_NORMAL_MEM_INDEX);
	else
		mair |= MAIR_ATTR_SET(ATTR_IWBWA_OWBWA_NTR,
				      ATTR_TAGGED_NORMAL_MEM_INDEX);
	cfg->mair_el1 = mair;

	tcr = TCR_RES1;
	tcr |= TCR_XRGNX_WBWA << TCR_IRGN0_SHIFT;
	tcr |= TCR_XRGNX_WBWA << TCR_ORGN0_SHIFT;
	tcr |= TCR_SHX_ISH << TCR_SH0_SHIFT;
	tcr |= ips << TCR_EL1_IPS_SHIFT;
	tcr |= 64 - CFG_LPAE_ADDR_SPACE_BITS;

	/* Disable the use of TTBR1 */
	tcr |= TCR_EPD1;

	/*
	 * TCR.A1 = 0 => ASID is stored in TTBR0
	 * TCR.AS = 0 => Same ASID size as in Aarch32/ARMv7
	 */
	cfg->tcr_el1 = tcr;
}
#endif /*ARM64*/

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
		unsigned level, vaddr_t va_base, void *table)
{
	tbl_info->level = level;
	tbl_info->next_level = level + 1;
	tbl_info->table = table;
	tbl_info->va_base = va_base;
	tbl_info->shift = XLAT_ADDR_SHIFT(level);

#if (CORE_MMU_BASE_TABLE_LEVEL > 0)
	assert(level >= CORE_MMU_BASE_TABLE_LEVEL);
#endif
	assert(level <= XLAT_TABLE_LEVEL_MAX);

	if (level == CORE_MMU_BASE_TABLE_LEVEL)
		tbl_info->num_entries = NUM_BASE_LEVEL_ENTRIES;
	else
		tbl_info->num_entries = XLAT_TABLE_ENTRIES;
}

void core_mmu_get_user_pgdir(struct core_mmu_table_info *pgd_info)
{
	vaddr_t va_range_base;
	void *tbl = get_prtn()->l2_ta_tables[thread_get_id()];

	core_mmu_get_user_va_range(&va_range_base, NULL);
	core_mmu_set_info_table(pgd_info, 2, va_range_base, tbl);
}

void core_mmu_create_user_map(struct user_mode_ctx *uctx,
			      struct core_mmu_user_map *map)
{
	struct core_mmu_table_info dir_info;

	COMPILE_TIME_ASSERT(sizeof(uint64_t) * XLAT_TABLE_ENTRIES == PGT_SIZE);

	core_mmu_get_user_pgdir(&dir_info);
	memset(dir_info.table, 0, PGT_SIZE);
	core_mmu_populate_user_map(&dir_info, uctx);
	map->user_map = virt_to_phys(dir_info.table) | TABLE_DESC;
	map->asid = uctx->vm_info.asid;
}

bool core_mmu_find_table(struct mmu_partition *prtn, vaddr_t va,
			 unsigned max_level,
			 struct core_mmu_table_info *tbl_info)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	unsigned int num_entries = NUM_BASE_LEVEL_ENTRIES;
	unsigned int level = CORE_MMU_BASE_TABLE_LEVEL;
	vaddr_t va_base = 0;
	bool ret = false;
	uint64_t *tbl;

	if (!prtn)
		prtn = get_prtn();
	tbl = prtn->base_tables[0][get_core_pos()];

	while (true) {
		unsigned int level_size_shift = XLAT_ADDR_SHIFT(level);
		unsigned int n = (va - va_base) >> level_size_shift;

		if (n >= num_entries)
			goto out;

		if (level == max_level || level == XLAT_TABLE_LEVEL_MAX ||
		    (tbl[n] & TABLE_DESC) != TABLE_DESC) {
			/*
			 * We've either reached max_level, a block
			 * mapping entry or an "invalid" mapping entry.
			 */

			/*
			 * Base level is the CPU specific translation table.
			 * It doesn't make sense to return anything based
			 * on that unless foreign interrupts already are
			 * masked.
			 */
			if (level == CORE_MMU_BASE_TABLE_LEVEL &&
			    !(exceptions & THREAD_EXCP_FOREIGN_INTR))
				goto out;

			tbl_info->table = tbl;
			tbl_info->va_base = va_base;
			tbl_info->level = level;
			tbl_info->next_level = level + 1;
			tbl_info->shift = level_size_shift;
			tbl_info->num_entries = num_entries;
#ifdef CFG_NS_VIRTUALIZATION
			tbl_info->prtn = prtn;
#endif
			ret = true;
			goto out;
		}

		tbl = core_mmu_xlat_table_entry_pa2va(prtn, level, tbl[n]);

		if (!tbl)
			goto out;

		va_base += (vaddr_t)n << level_size_shift;
		level++;
		num_entries = XLAT_TABLE_ENTRIES;
	}
out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

bool core_mmu_entry_to_finer_grained(struct core_mmu_table_info *tbl_info,
				     unsigned int idx, bool secure __unused)
{
	uint64_t *new_table;
	uint64_t *entry;
	int i;
	paddr_t pa;
	uint64_t attr;
	paddr_t block_size_on_next_lvl = XLAT_BLOCK_SIZE(tbl_info->level + 1);
	struct mmu_partition *prtn;

#ifdef CFG_NS_VIRTUALIZATION
	prtn = tbl_info->prtn;
#else
	prtn = &default_partition;
#endif
	assert(prtn);

	if (tbl_info->level >= XLAT_TABLE_LEVEL_MAX ||
	    idx >= tbl_info->num_entries)
		return false;

	entry = (uint64_t *)tbl_info->table + idx;

	if ((*entry & DESC_ENTRY_TYPE_MASK) == TABLE_DESC)
		return true;

	new_table = core_mmu_xlat_table_alloc(prtn);
	if (!new_table)
		return false;

	if (*entry) {
		pa = *entry & OUTPUT_ADDRESS_MASK;
		attr = *entry & ~(OUTPUT_ADDRESS_MASK | DESC_ENTRY_TYPE_MASK);
		for (i = 0; i < XLAT_TABLE_ENTRIES; i++) {
			new_table[i] = pa | attr | BLOCK_DESC;
			pa += block_size_on_next_lvl;
		}
	} else {
		memset(new_table, 0, XLAT_TABLE_ENTRIES * XLAT_ENTRY_SIZE);
	}

	*entry = virt_to_phys(new_table) | TABLE_DESC;

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
		*pa = tbl[idx] & GENMASK_64(47, 12);

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
		*size = BIT64(L1_XLAT_ADDRESS_SHIFT);
}

static uint64_t *core_mmu_get_user_mapping_entry(struct mmu_partition *prtn,
						 unsigned int base_idx)
{
#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
	l1_idx_t idx = 0;
	uint64_t *tbl = NULL;
#endif

	assert(user_va_idx != -1);

#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
	idx = prtn->user_l1_table_idx[base_idx][get_core_pos()];
	tbl = prtn->xlat_tables[idx];

	return &tbl[user_va_idx];
#else
	return &prtn->base_tables[base_idx][get_core_pos()][user_va_idx];
#endif
}

bool core_mmu_user_mapping_is_active(void)
{
	bool ret = false;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	uint64_t *entry = NULL;

	entry = core_mmu_get_user_mapping_entry(get_prtn(), 0);
	ret = (*entry != 0);

	thread_unmask_exceptions(exceptions);

	return ret;
}

#ifdef ARM32
void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	struct mmu_partition *prtn = get_prtn();
	uint64_t *entry = NULL;

	entry = core_mmu_get_user_mapping_entry(prtn, 0);

	map->user_map = *entry;
	if (map->user_map) {
		map->asid = (read_ttbr0_64bit() >> TTBR_ASID_SHIFT) &
			    TTBR_ASID_MASK;
	} else {
		map->asid = 0;
	}
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	uint64_t ttbr = 0;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	struct mmu_partition *prtn = get_prtn();
	uint64_t *entries[NUM_BASE_TABLES] = { };
	unsigned int i = 0;

	ttbr = read_ttbr0_64bit();
	/* Clear ASID */
	ttbr &= ~((uint64_t)TTBR_ASID_MASK << TTBR_ASID_SHIFT);
	write_ttbr0_64bit(ttbr);
	isb();

	for (i = 0; i < NUM_BASE_TABLES; i++)
		entries[i] = core_mmu_get_user_mapping_entry(prtn, i);

	/* Set the new map */
	if (map && map->user_map) {
		for (i = 0; i < NUM_BASE_TABLES; i++)
			*entries[i] = map->user_map;

		dsb();	/* Make sure the write above is visible */
		ttbr |= ((uint64_t)map->asid << TTBR_ASID_SHIFT);
		write_ttbr0_64bit(ttbr);
		isb();
	} else {
		for (i = 0; i < NUM_BASE_TABLES; i++)
			*entries[i] = INVALID_DESC;

		dsb();	/* Make sure the write above is visible */
	}

	tlbi_all();
	icache_inv_all();

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
	struct mmu_partition *prtn = get_prtn();
	uint64_t *entry = NULL;

	entry = core_mmu_get_user_mapping_entry(prtn, 0);

	map->user_map = *entry;
	if (map->user_map) {
		map->asid = (read_ttbr0_el1() >> TTBR_ASID_SHIFT) &
			    TTBR_ASID_MASK;
	} else {
		map->asid = 0;
	}
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	uint64_t ttbr = 0;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	struct mmu_partition *prtn = get_prtn();
	uint64_t *entries[NUM_BASE_TABLES] = { };
	unsigned int i = 0;

	ttbr = read_ttbr0_el1();
	/* Clear ASID */
	ttbr &= ~((uint64_t)TTBR_ASID_MASK << TTBR_ASID_SHIFT);
	write_ttbr0_el1(ttbr);
	isb();

	for (i = 0; i < NUM_BASE_TABLES; i++)
		entries[i] = core_mmu_get_user_mapping_entry(prtn, i);

	/* Set the new map */
	if (map && map->user_map) {
		for (i = 0; i < NUM_BASE_TABLES; i++)
			*entries[i] = map->user_map;

		dsb();	/* Make sure the write above is visible */
		ttbr |= ((uint64_t)map->asid << TTBR_ASID_SHIFT);
		write_ttbr0_el1(ttbr);
		isb();
	} else {
		for (i = 0; i < NUM_BASE_TABLES; i++)
			*entries[i] = INVALID_DESC;

		dsb();	/* Make sure the write above is visible */
	}

	tlbi_all();
	icache_inv_all();

	thread_unmask_exceptions(exceptions);
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
		case ESR_FSC_SIZE_L0:
		case ESR_FSC_SIZE_L1:
		case ESR_FSC_SIZE_L2:
		case ESR_FSC_SIZE_L3:
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
		case ESR_FSC_TAG_CHECK:
			return CORE_MMU_FAULT_TAG_CHECK;
		default:
			return CORE_MMU_FAULT_OTHER;
		}
	default:
		return CORE_MMU_FAULT_OTHER;
	}
}
#endif /*ARM64*/
