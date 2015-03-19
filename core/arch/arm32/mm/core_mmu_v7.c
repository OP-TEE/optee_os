/*
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
#include <platform_config.h>

#include <stdlib.h>
#include <assert.h>
#include <arm.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <trace.h>
#include <kernel/panic.h>
#include <util.h>
#include "core_mmu_private.h"

/*
 * MMU related values
 */

/* Sharable */
#define TEE_MMU_TTB_S           (1 << 1)

/* Not Outer Sharable */
#define TEE_MMU_TTB_NOS         (1 << 5)

/* Normal memory, Inner Non-cacheable */
#define TEE_MMU_TTB_IRGN_NC     0

/* Normal memory, Inner Write-Back Write-Allocate Cacheable */
#define TEE_MMU_TTB_IRGN_WBWA   (1 << 6)

/* Normal memory, Inner Write-Through Cacheable */
#define TEE_MMU_TTB_IRGN_WT     1

/* Normal memory, Inner Write-Back no Write-Allocate Cacheable */
#define TEE_MMU_TTB_IRGN_WB     (1 | (1 << 6))

/* Normal memory, Outer Write-Back Write-Allocate Cacheable */
#define TEE_MMU_TTB_RNG_WBWA    (1 << 3)

#define TEE_MMU_DEFAULT_ATTRS \
		(TEE_MMU_TTB_S | TEE_MMU_TTB_NOS | \
		 TEE_MMU_TTB_IRGN_WBWA | TEE_MMU_TTB_RNG_WBWA)


#define INVALID_DESC		0x0
#define HIDDEN_DESC		0x4
#define PHYSPAGE_DESC		0x8


#define SECTION_SHIFT		20
#define SECTION_MASK		0x000fffff
#define SECTION_SIZE		0x00100000

/* armv7 memory mapping attributes: section mapping */
#define SECTION_SECURE			(0 << 19)
#define SECTION_NOTSECURE		(1 << 19)
#define SECTION_SHARED			(1 << 16)
#define SECTION_NOTGLOBAL		(1 << 17)
#define SECTION_ACCESS_FLAG		(1 << 10)
#define SECTION_UNPRIV			(1 << 11)
#define SECTION_RO			(1 << 15)
#define SECTION_TEXCB(texcb)		((((texcb) >> 2) << 12) | \
					 ((((texcb) >> 1) & 0x1) << 3) | \
					 (((texcb) & 0x1) << 2))
#define SECTION_DEVICE			SECTION_TEXCB(ATTR_DEVICE_INDEX)
#define SECTION_NORMAL			SECTION_TEXCB(ATTR_DEVICE_INDEX)
#define SECTION_NORMAL_CACHED		SECTION_TEXCB(ATTR_IWBWA_OWBWA_INDEX)

#define SECTION_XN			(1 << 4)
#define SECTION_PXN			(1 << 0)
#define SECTION_SECTION			(2 << 0)

#define SECTION_PT_NOTSECURE		(1 << 3)
#define SECTION_PT_PT			(1 << 0)

#define SMALL_PAGE_SMALL_PAGE		(1 << 1)
#define SMALL_PAGE_SHARED		(1 << 10)
#define SMALL_PAGE_NOTGLOBAL		(1 << 11)
#define SMALL_PAGE_TEXCB(texcb)		((((texcb) >> 2) << 6) | \
					 ((((texcb) >> 1) & 0x1) << 3) | \
					 (((texcb) & 0x1) << 2))
#define SMALL_PAGE_DEVICE		SMALL_PAGE_TEXCB(ATTR_DEVICE_INDEX)
#define SMALL_PAGE_NORMAL		SMALL_PAGE_TEXCB(ATTR_DEVICE_INDEX)
#define SMALL_PAGE_NORMAL_CACHED	SMALL_PAGE_TEXCB(ATTR_IWBWA_OWBWA_INDEX)
#define SMALL_PAGE_ACCESS_FLAG		(1 << 4)
#define SMALL_PAGE_UNPRIV		(1 << 5)
#define SMALL_PAGE_RO			(1 << 9)
#define SMALL_PAGE_XN			(1 << 0)


/* The TEX, C and B bits concatenated */
#define ATTR_DEVICE_INDEX		0x0
#define ATTR_IWBWA_OWBWA_INDEX		0x1

#define PRRR_IDX(idx, tr, nos)		(((tr) << (2 * (idx))) | \
					 ((uint32_t)(nos) << ((idx) + 24)))
#define NMRR_IDX(idx, ir, or)		(((ir) << (2 * (idx))) | \
					 ((uint32_t)(or) << (2 * (idx) + 16)))
#define PRRR_DS0			(1 << 16)
#define PRRR_DS1			(1 << 17)
#define PRRR_NS0			(1 << 18)
#define PRRR_NS1			(1 << 19)

#define ATTR_DEVICE_PRRR		PRRR_IDX(ATTR_DEVICE_INDEX, 1, 0)
#define ATTR_DEVICE_NMRR		NMRR_IDX(ATTR_DEVICE_INDEX, 0, 0)

#define ATTR_IWBWA_OWBWA_PRRR		PRRR_IDX(ATTR_IWBWA_OWBWA_INDEX, 2, 1)
#define ATTR_IWBWA_OWBWA_NMRR		NMRR_IDX(ATTR_IWBWA_OWBWA_INDEX, 1, 1)

enum desc_type {
	DESC_TYPE_PAGE_TABLE,
	DESC_TYPE_SECTION,
	DESC_TYPE_SUPER_SECTION,
	DESC_TYPE_LARGE_PAGE,
	DESC_TYPE_SMALL_PAGE,
	DESC_TYPE_INVALID,
};

static enum desc_type get_desc_type(unsigned level, uint32_t desc)
{
	assert(level >= 1 && level <= 2);

	if (level == 1) {
		if ((desc & 0x3) == 0x1)
			return DESC_TYPE_PAGE_TABLE;

		if ((desc & 0x2) == 0x2) {
			if (desc & (1 << 18))
				return DESC_TYPE_SUPER_SECTION;
			return DESC_TYPE_SECTION;
		}
	} else {
		if ((desc & 0x3) == 0x1)
			return DESC_TYPE_LARGE_PAGE;

		if ((desc & 0x2) == 0x2)
			return DESC_TYPE_SMALL_PAGE;
	}

	return DESC_TYPE_INVALID;
}

static uint32_t texcb_to_mattr(uint32_t texcb)
{
	switch (texcb) {
	case ATTR_IWBWA_OWBWA_INDEX:
		return TEE_MATTR_CACHE_DEFAULT;
	case ATTR_DEVICE_INDEX:
		return TEE_MATTR_NONCACHE;
	default:
		return TEE_MATTR_CACHE_UNKNOWN;
	}
}

static uint32_t mattr_to_texcb(uint32_t attr)
{
	/* Keep in sync with core_mmu.c:core_mmu_mattr_is_ok */
	switch (attr & (TEE_MATTR_I_WRITE_THR | TEE_MATTR_I_WRITE_BACK |
			TEE_MATTR_O_WRITE_THR | TEE_MATTR_O_WRITE_BACK)) {
	case TEE_MATTR_NONCACHE:
		return ATTR_DEVICE_INDEX;
	case TEE_MATTR_I_WRITE_BACK | TEE_MATTR_O_WRITE_BACK:
		return ATTR_IWBWA_OWBWA_INDEX;
	default:
		/*
		 * "Can't happen" the attribute is supposed to be checked
		 * with core_mmu_mattr_is_ok() before.
		 */
		panic();
	}
}


static uint32_t desc_to_mattr(unsigned level, uint32_t desc)
{
	uint32_t a = TEE_MATTR_VALID_BLOCK;

	switch (get_desc_type(level, desc)) {
	case DESC_TYPE_SECTION:
		if (desc & SECTION_ACCESS_FLAG)
			a |= TEE_MATTR_PRX | TEE_MATTR_URX;

		if (!(desc & SECTION_RO))
			a |= TEE_MATTR_PW | TEE_MATTR_UW;

		if (desc & SECTION_XN)
			a &= ~(TEE_MATTR_PX | TEE_MATTR_UX);

		if (desc & SECTION_PXN)
			a &= ~TEE_MATTR_PX;

		a |= texcb_to_mattr(((desc >> 12) & 0x7) | ((desc >> 2) & 0x3));

		if (!(desc & SECTION_NOTGLOBAL))
			a |= TEE_MATTR_GLOBAL;

		if (!(desc & SECTION_NOTSECURE))
			a |= TEE_MATTR_SECURE;

		break;
	case DESC_TYPE_SMALL_PAGE:
		if (desc & SMALL_PAGE_ACCESS_FLAG)
			a |= TEE_MATTR_PRX | TEE_MATTR_URX;

		if (!(desc & SMALL_PAGE_RO))
			a |= TEE_MATTR_PW | TEE_MATTR_UW;

		if (desc & SMALL_PAGE_XN)
			a &= ~(TEE_MATTR_PX | TEE_MATTR_UX);

		a |= texcb_to_mattr(((desc >> 6) & 0x7) | ((desc >> 2) & 0x3));

		if (!(desc & SMALL_PAGE_NOTGLOBAL))
			a |= TEE_MATTR_GLOBAL;
		break;
	case DESC_TYPE_INVALID:
		if (desc & HIDDEN_DESC)
			return TEE_MATTR_HIDDEN_BLOCK;
		if (desc & PHYSPAGE_DESC)
			return TEE_MATTR_PHYS_BLOCK;
		return 0;
	default:
		return 0;
	}

	return a;
}

static uint32_t mattr_to_desc(unsigned level, uint32_t attr)
{
	uint32_t desc;
	uint32_t a = attr;
	unsigned texcb;

	if (a & TEE_MATTR_HIDDEN_BLOCK)
		return INVALID_DESC | HIDDEN_DESC;

	if (a & TEE_MATTR_PHYS_BLOCK)
		return INVALID_DESC | PHYSPAGE_DESC;

	if (level == 1 && (a & TEE_MATTR_TABLE)) {
		desc = SECTION_PT_PT;
		if (!(a & TEE_MATTR_SECURE))
			desc |= SECTION_PT_NOTSECURE;
		return desc;
	}

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


	texcb = mattr_to_texcb(a);

	if (level == 1) {	/* Section */
		desc = SECTION_SECTION | SECTION_SHARED;

		if (!(a & (TEE_MATTR_PX | TEE_MATTR_UX)))
			desc |= SECTION_XN;

#ifdef CFG_HWSUPP_MEM_PERM_PXN
		if (!(a & TEE_MATTR_PX))
			desc |= SECTION_PXN;
#endif

		if (a & TEE_MATTR_UR)
			desc |= SECTION_UNPRIV;

		if (!(a & TEE_MATTR_PW))
			desc |= SECTION_RO;

		if (a & (TEE_MATTR_UR | TEE_MATTR_PR))
			desc |= SECTION_ACCESS_FLAG;

		if (!(a & TEE_MATTR_GLOBAL))
			desc |= SECTION_NOTGLOBAL;

		if (!(a & TEE_MATTR_SECURE))
			desc |= SECTION_NOTSECURE;

		desc |= SECTION_TEXCB(texcb);
	} else {
		desc = SMALL_PAGE_SMALL_PAGE | SMALL_PAGE_SHARED;

		if (!(a & (TEE_MATTR_PX | TEE_MATTR_UX)))
			desc |= SMALL_PAGE_XN;

		if (a & TEE_MATTR_UR)
			desc |= SMALL_PAGE_UNPRIV;

		if (!(a & TEE_MATTR_PW))
			desc |= SMALL_PAGE_RO;

		if (a & (TEE_MATTR_UR | TEE_MATTR_PR))
			desc |= SMALL_PAGE_ACCESS_FLAG;

		if (!(a & TEE_MATTR_GLOBAL))
			desc |= SMALL_PAGE_NOTGLOBAL;

		desc |= SMALL_PAGE_TEXCB(texcb);
	}

	return desc;
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

static paddr_t populate_user_map(struct tee_mmu_info *mmu)
{
	struct core_mmu_table_info tbl_info;
	unsigned n;
	struct tee_mmap_region region;
	vaddr_t va_range_base;
	size_t va_range_size;

	core_mmu_get_user_va_range(&va_range_base, &va_range_size);

	tbl_info.table = (void *)core_mmu_get_ul1_ttb_va();
	tbl_info.va_base = 0;
	tbl_info.level = 1;
	tbl_info.shift = SECTION_SHIFT;
	tbl_info.num_entries = TEE_MMU_UL1_NUM_ENTRIES;

	region.pa = 0;
	region.va = va_range_base;
	region.attr = 0;

	for (n = 0; n < mmu->size; n++) {
		if (!mmu->table[n].size)
			continue;

		/* Empty mapping for gaps */
		region.size = mmu->table[n].va - region.va;
		set_region(&tbl_info, &region);

		set_region(&tbl_info, mmu->table + n);
		region.va = mmu->table[n].va + mmu->table[n].size;
		assert((region.va - va_range_base) <= va_range_size);
	}
	region.size = va_range_size - (region.va - va_range_base);
	set_region(&tbl_info, &region);

	return core_mmu_get_ul1_ttb_pa() | TEE_MMU_DEFAULT_ATTRS;
}

void core_mmu_create_user_map(struct tee_mmu_info *mmu, uint32_t asid,
		struct core_mmu_user_map *map)
{
	if (mmu) {
		map->ttbr0 = populate_user_map(mmu);
		map->ctxid = asid & 0xff;
	} else {
		map->ttbr0 = read_ttbr1();
		map->ctxid = 0;
	}
}

static void set_info_table(struct core_mmu_table_info *tbl_info,
		unsigned level, vaddr_t va_base, void *table)
{
	tbl_info->level = level;
	tbl_info->table = table;
	tbl_info->va_base = va_base;
	if (level == 1) {
		tbl_info->shift = SECTION_SHIFT;
		tbl_info->num_entries = TEE_MMU_L1_NUM_ENTRIES;
	} else {
		tbl_info->shift = SMALL_PAGE_SHIFT;
		tbl_info->num_entries = TEE_MMU_L2_NUM_ENTRIES;
	}
}

bool core_mmu_find_table(vaddr_t va, unsigned max_level,
		struct core_mmu_table_info *tbl_info)
{
	uint32_t *tbl = (uint32_t *)core_mmu_get_main_ttb_va();
	unsigned n = va >> SECTION_SHIFT;

	if (max_level == 1 || (tbl[n] & 0x3) != 0x1) {
		set_info_table(tbl_info, 1, 0, tbl);
	} else {
		uintptr_t ntbl = tbl[n] & ~((1 << 10) - 1);

		set_info_table(tbl_info, 2, n << SECTION_SHIFT, (void *)ntbl);
	}
	return true;
}

void core_mmu_set_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
		paddr_t pa, uint32_t attr)
{
	uint32_t *table = tbl_info->table;
	uint32_t desc = mattr_to_desc(tbl_info->level, attr);

	assert(idx < tbl_info->num_entries);

	table[idx] = desc | pa;
}

static paddr_t desc_to_pa(unsigned level, uint32_t desc)
{
	unsigned shift_mask;

	switch (get_desc_type(level, desc)) {
	case DESC_TYPE_PAGE_TABLE:
		shift_mask = 10;
		break;
	case DESC_TYPE_SECTION:
		shift_mask = 20;
		break;
	case DESC_TYPE_SUPER_SECTION:
		shift_mask = 24; /* We're ignoring bits 32 and above. */
		break;
	case DESC_TYPE_LARGE_PAGE:
		shift_mask = 16;
		break;
	case DESC_TYPE_SMALL_PAGE:
		shift_mask = 12;
		break;
	default:
		/* Invalid section, HIDDEN_DESC, PHYSPAGE_DESC */
		shift_mask = 4;
	}

	return desc & ~((1 << shift_mask) - 1);
}

void core_mmu_get_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
		paddr_t *pa, uint32_t *attr)
{
	uint32_t *table = tbl_info->table;

	assert(idx < tbl_info->num_entries);

	if (pa)
		*pa = desc_to_pa(tbl_info->level, table[idx]);

	if (attr)
		*attr = desc_to_mattr(tbl_info->level, table[idx]);
}

void core_mmu_get_user_va_range(vaddr_t *base, size_t *size)
{
	if (base) {
		/* Leaving the first entry unmapped to make NULL unmapped */
		*base = 1 << SECTION_SHIFT;
	}

	if (size)
		*size = (TEE_MMU_UL1_NUM_ENTRIES - 1) << SECTION_SHIFT;
}



void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	map->ttbr0 = read_ttbr0();
	map->ctxid = read_contextidr();
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	uint32_t cpsr = read_cpsr();

	write_cpsr(cpsr | CPSR_FIA);

	/*
	 * Update the reserved Context ID and TTBR0
	 */

	dsb();  /* ARM erratum 754322 */
	write_contextidr(0);
	isb();

	if (map) {
		write_ttbr0(map->ttbr0);
		isb();
		write_contextidr(map->ctxid);
	} else {
		write_ttbr0(read_ttbr1());
	}
	isb();
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

	write_cpsr(cpsr);
}

bool core_mmu_user_mapping_is_active(void)
{
	return read_ttbr0() != read_ttbr1();
}

static paddr_t map_page_memarea(struct tee_mmap_region *mm)
{
	uint32_t *l2 = core_mmu_alloc_l2(mm);
	size_t pg_idx;
	uint32_t attr;

	TEE_ASSERT(l2);

	attr = mattr_to_desc(2, mm->attr);

	/* Zero fill initial entries */
	pg_idx = 0;
	while ((pg_idx * SMALL_PAGE_SIZE) < (mm->pa & SECTION_MASK)) {
		l2[pg_idx] = 0;
		pg_idx++;
	}

	/* Fill in the entries */
	while ((pg_idx * SMALL_PAGE_SIZE) < mm->size) {
		l2[pg_idx] = ((mm->pa & ~SMALL_PAGE_MASK) +
				pg_idx * SMALL_PAGE_SIZE) | attr;
		pg_idx++;
	}

	/* Zero fill the rest */
	while (pg_idx < ROUNDUP(mm->size, SECTION_SIZE) / SMALL_PAGE_SIZE) {
		l2[pg_idx] = 0;
		pg_idx++;
	}

	return (paddr_t)l2;
}

/*
* map_memarea - load mapping in target L1 table
* A finer mapping must be supported. Currently section mapping only!
*/
static void map_memarea(struct tee_mmap_region *mm, uint32_t *ttb)
{
	size_t m, n;
	uint32_t attr;
	paddr_t pa;
	uint32_t region_size;

	TEE_ASSERT(mm && ttb);

	if ((mm->va | mm->pa | mm->size) & SECTION_MASK) {
		region_size = SMALL_PAGE_SIZE;

		/*
		 * Need finer grained mapping, if small pages aren't
		 * good enough, panic.
		 */
		if ((mm->va | mm->pa | mm->size) & SMALL_PAGE_MASK) {
			EMSG("va 0x%" PRIxVA " pa 0x%" PRIxPA " size 0x%x can't be mapped",
				mm->va, mm->pa, mm->size);
			panic();
		}

		attr = mattr_to_desc(1, mm->attr | TEE_MATTR_TABLE);
		pa = map_page_memarea(mm);
	} else {
		region_size = SECTION_SIZE;

		attr = mattr_to_desc(1, mm->attr);
		pa = mm->pa;
	}

	m = (mm->pa >> SECTION_SHIFT);
	n = ROUNDUP(mm->size, SECTION_SIZE) >> SECTION_SHIFT;
	while (n--) {
		ttb[m] = pa | attr;
		m++;
		if (region_size == SECTION_SIZE)
			pa += SECTION_SIZE;
		else
			pa += TEE_MMU_L2_SIZE;
	}
}

void core_init_mmu_tables(struct tee_mmap_region *mm)
{
	void *ttb1 = (void *)core_mmu_get_main_ttb_va();
	size_t n;

	/* reset L1 table */
	memset(ttb1, 0, TEE_MMU_L1_SIZE);

	for (n = 0; mm[n].size; n++)
		map_memarea(mm + n, ttb1);
}

void core_init_mmu_regs(void)
{
	uint32_t prrr;
	uint32_t nmrr;
	paddr_t ttb_pa = core_mmu_get_main_ttb_pa();

	/* Enable Access flag (simplified access permissions) and TEX remap */
	write_sctlr(read_sctlr() | SCTLR_AFE | SCTLR_TRE);

	prrr = ATTR_DEVICE_PRRR | ATTR_IWBWA_OWBWA_PRRR;
	nmrr = ATTR_DEVICE_NMRR | ATTR_IWBWA_OWBWA_NMRR;

	prrr |= PRRR_NS1 | PRRR_DS1;

	write_prrr(prrr);
	write_nmrr(nmrr);


	/*
	 * Program Domain access control register with two domains:
	 * domain 0: teecore
	 * domain 1: TA
	 */
	write_dacr(DACR_DOMAIN(0, DACR_DOMAIN_PERM_CLIENT) |
		   DACR_DOMAIN(1, DACR_DOMAIN_PERM_CLIENT));

	/*
	 * Enable lookups using TTBR0 and TTBR1 with the split of addresses
	 * defined by TEE_MMU_TTBCR_N_VALUE.
	 */
	write_ttbcr(TEE_MMU_TTBCR_N_VALUE);

	write_ttbr0(ttb_pa | TEE_MMU_DEFAULT_ATTRS);
	write_ttbr1(ttb_pa | TEE_MMU_DEFAULT_ATTRS);
}

__weak void *core_mmu_alloc_l2(struct tee_mmap_region *mm __unused)
{
	/*
	 * This function should be redefined in platform specific part if
	 * needed.
	 */
	return NULL;
}

enum core_mmu_fault core_mmu_get_fault_type(uint32_t fsr)
{
	assert(!(fsr & FSR_LPAE));
	switch (fsr & FSR_FS_MASK) {
	case 0x1: /* DFSR[10,3:0] 0b00001 Alignment fault (DFSR only) */
		return CORE_MMU_FAULT_ALIGNMENT;
	case 0x2: /* DFSR[10,3:0] 0b00010 Debug event */
		return CORE_MMU_FAULT_DEBUG_EVENT;
	case 0x5: /* DFSR[10,3:0] b00101 Translation fault first level */
	case 0x7: /* DFSR[10,3:0] b00111 Translation fault second level */
		return CORE_MMU_FAULT_TRANSLATION;
	case 0xd: /* DFSR[10,3:0] b01101 Permission fault first level */
	case 0xf: /* DFSR[10,3:0] b01111 Permission fault second level */
		return CORE_MMU_FAULT_PERMISSION;

	case (1 << 10) | 0x6:
		/* DFSR[10,3:0] 0b10110 Async external abort (DFSR only) */
		return CORE_MMU_FAULT_ASYNC_EXTERNAL;

	default:
		return CORE_MMU_FAULT_OTHER;
	}
}
