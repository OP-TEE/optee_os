// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <keep.h>
#include <kernel/cache_helpers.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tlb_helpers.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>
#include <platform_config.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#ifdef CFG_WITH_LPAE
#error This file is not to be used with LPAE
#endif

#ifdef CFG_NS_VIRTUALIZATION
#error Currently V7 MMU code does not support virtualization
#endif

#ifndef DEBUG_XLAT_TABLE
#define DEBUG_XLAT_TABLE 0
#endif

#if DEBUG_XLAT_TABLE
#define debug_print(...) DMSG_RAW(__VA_ARGS__)
#else
#define debug_print(...) ((void)0)
#endif

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

/* Normal memory, Outer Write-Back no Write-Allocate Cacheable */
#define TEE_MMU_TTB_RNG_WB      (3 << 3)

#ifndef CFG_NO_SMP
#define TEE_MMU_DEFAULT_ATTRS \
		(TEE_MMU_TTB_S | TEE_MMU_TTB_NOS | \
		 TEE_MMU_TTB_IRGN_WBWA | TEE_MMU_TTB_RNG_WBWA)
#else
#define TEE_MMU_DEFAULT_ATTRS (TEE_MMU_TTB_IRGN_WB | TEE_MMU_TTB_RNG_WB)
#endif


#define INVALID_DESC		0x0

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
#define SECTION_NORMAL_CACHED		SECTION_TEXCB(ATTR_NORMAL_CACHED_INDEX)
#define SECTION_STRONG_O		SECTION_TEXCB(ATTR_STRONG_O_INDEX)
#define SECTION_TAGGED_CACHED		SECTION_TEXCB(ATTR_TAGGED_CACHED_INDEX)

#define SECTION_XN			(1 << 4)
#define SECTION_PXN			(1 << 0)
#define SECTION_SECTION			(2 << 0)

#define SECTION_PT_NOTSECURE		(1 << 3)
#define SECTION_PT_PT			(1 << 0)

#define SECTION_PT_ATTR_MASK		~((1 << 10) - 1)

#define SMALL_PAGE_SMALL_PAGE		(1 << 1)
#define SMALL_PAGE_SHARED		(1 << 10)
#define SMALL_PAGE_NOTGLOBAL		(1 << 11)
#define SMALL_PAGE_TEXCB(texcb)		((((texcb) >> 2) << 6) | \
					 ((((texcb) >> 1) & 0x1) << 3) | \
					 (((texcb) & 0x1) << 2))
#define SMALL_PAGE_DEVICE		SMALL_PAGE_TEXCB(ATTR_DEVICE_INDEX)
#define SMALL_PAGE_NORMAL		SMALL_PAGE_TEXCB(ATTR_DEVICE_INDEX)
#define SMALL_PAGE_NORMAL_CACHED \
	SMALL_PAGE_TEXCB(ATTR_NORMAL_CACHED_INDEX)
#define SMALL_PAGE_STRONG_O		SMALL_PAGE_TEXCB(ATTR_STRONG_O_INDEX)
#define SMALL_PAGE_TAGGED_CACHED \
	SMALL_PAGE_TEXCB(ATTR_TAGGED_CACHED_INDEX)
#define SMALL_PAGE_ACCESS_FLAG		(1 << 4)
#define SMALL_PAGE_UNPRIV		(1 << 5)
#define SMALL_PAGE_RO			(1 << 9)
#define SMALL_PAGE_XN			(1 << 0)


/* The TEX, C and B bits concatenated */
#define ATTR_DEVICE_INDEX		0x0
#define ATTR_NORMAL_CACHED_INDEX	0x1
#define ATTR_STRONG_O_INDEX		0x2
/* Compat with TEE_MATTR_MEM_TYPE_TAGGED */
#define ATTR_TAGGED_CACHED_INDEX	0x3

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

#define ATTR_STRONGLY_O_PRRR		PRRR_IDX(ATTR_STRONG_O_INDEX, 0, 0)
#define ATTR_STRONGLY_O_NMRR		NMRR_IDX(ATTR_STRONG_O_INDEX, 0, 0)

#ifndef CFG_NO_SMP
#define ATTR_NORMAL_CACHED_PRRR		PRRR_IDX(ATTR_NORMAL_CACHED_INDEX, 2, 1)
#define ATTR_NORMAL_CACHED_NMRR		NMRR_IDX(ATTR_NORMAL_CACHED_INDEX, 1, 1)
#define ATTR_TAGGED_CACHED_PRRR		PRRR_IDX(ATTR_TAGGED_CACHED_INDEX, 2, 1)
#define ATTR_TAGGED_CACHED_NMRR		NMRR_IDX(ATTR_TAGGED_CACHED_INDEX, 1, 1)
#else
#define ATTR_NORMAL_CACHED_PRRR		PRRR_IDX(ATTR_NORMAL_CACHED_INDEX, 2, 0)
#define ATTR_NORMAL_CACHED_NMRR		NMRR_IDX(ATTR_NORMAL_CACHED_INDEX, 3, 3)
#define ATTR_TAGGED_CACHED_PRRR		PRRR_IDX(ATTR_TAGGED_CACHED_INDEX, 2, 0)
#define ATTR_TAGGED_CACHED_NMRR		NMRR_IDX(ATTR_TAGGED_CACHED_INDEX, 3, 3)
#endif

#define NUM_L1_ENTRIES		4096
#define NUM_L2_ENTRIES		256

#define L1_TBL_SIZE		(NUM_L1_ENTRIES * 4)
#define L2_TBL_SIZE		(NUM_L2_ENTRIES * 4)
#define L1_ALIGNMENT		L1_TBL_SIZE
#define L2_ALIGNMENT		L2_TBL_SIZE

/* Defined to the smallest possible secondary L1 MMU table */
#define TTBCR_N_VALUE		7

/* Number of sections in ttbr0 when user mapping activated */
#define NUM_UL1_ENTRIES         (1 << (12 - TTBCR_N_VALUE))
#define UL1_ALIGNMENT		(NUM_UL1_ENTRIES * 4)
/* TTB attributes */

/* TTB0 of TTBR0 (depends on TTBCR_N_VALUE) */
#define TTB_UL1_MASK		(~(UL1_ALIGNMENT - 1))
/* TTB1 of TTBR1 */
#define TTB_L1_MASK		(~(L1_ALIGNMENT - 1))

#ifndef MAX_XLAT_TABLES
#ifdef CFG_CORE_ASLR
#	define XLAT_TABLE_ASLR_EXTRA 2
#else
#	define XLAT_TABLE_ASLR_EXTRA 0
#endif
#define MAX_XLAT_TABLES		(4 + XLAT_TABLE_ASLR_EXTRA)
#endif /*!MAX_XLAT_TABLES*/

enum desc_type {
	DESC_TYPE_PAGE_TABLE,
	DESC_TYPE_SECTION,
	DESC_TYPE_SUPER_SECTION,
	DESC_TYPE_LARGE_PAGE,
	DESC_TYPE_SMALL_PAGE,
	DESC_TYPE_INVALID,
};

typedef uint32_t l1_xlat_tbl_t[NUM_L1_ENTRIES];
typedef uint32_t l2_xlat_tbl_t[NUM_L2_ENTRIES];
typedef uint32_t ul1_xlat_tbl_t[NUM_UL1_ENTRIES];

static l1_xlat_tbl_t main_mmu_l1_ttb
		__aligned(L1_ALIGNMENT) __section(".nozi.mmu.l1");

/* L2 MMU tables */
static l2_xlat_tbl_t main_mmu_l2_ttb[MAX_XLAT_TABLES]
		__aligned(L2_ALIGNMENT) __section(".nozi.mmu.l2");

/* MMU L1 table for TAs, one for each thread */
static ul1_xlat_tbl_t main_mmu_ul1_ttb[CFG_NUM_THREADS]
		__aligned(UL1_ALIGNMENT) __section(".nozi.mmu.ul1");

struct mmu_partition {
	l1_xlat_tbl_t *l1_table;
	l2_xlat_tbl_t *l2_tables;
	ul1_xlat_tbl_t *ul1_tables;
	uint32_t tables_used;
};

static struct mmu_partition default_partition = {
	.l1_table = &main_mmu_l1_ttb,
	.l2_tables = main_mmu_l2_ttb,
	.ul1_tables = main_mmu_ul1_ttb,
	.tables_used = 0,
};

#ifdef CFG_NS_VIRTUALIZATION
static struct mmu_partition *current_prtn[CFG_TEE_CORE_NB_CORE];

void core_mmu_set_default_prtn_tbl(void)
{
	size_t n = 0;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
		current_prtn[n] = &default_partition;
}
#endif

static struct mmu_partition *get_prtn(void)
{
#ifdef CFG_NS_VIRTUALIZATION
	return current_prtn[get_core_pos()];
#else
	return &default_partition;
#endif
}

static vaddr_t core_mmu_get_main_ttb_va(struct mmu_partition *prtn)
{
	return (vaddr_t)prtn->l1_table;
}

static paddr_t core_mmu_get_main_ttb_pa(struct mmu_partition *prtn)
{
	paddr_t pa = virt_to_phys((void *)core_mmu_get_main_ttb_va(prtn));

	if (pa & ~TTB_L1_MASK)
		panic("invalid core l1 table");
	return pa;
}

static vaddr_t core_mmu_get_ul1_ttb_va(struct mmu_partition *prtn)
{
	return (vaddr_t)prtn->ul1_tables[thread_get_id()];
}

static paddr_t core_mmu_get_ul1_ttb_pa(struct mmu_partition *prtn)
{
	paddr_t pa = virt_to_phys((void *)core_mmu_get_ul1_ttb_va(prtn));

	if (pa & ~TTB_UL1_MASK)
		panic("invalid user l1 table");
	return pa;
}

static void *core_mmu_alloc_l2(struct mmu_partition *prtn, size_t size)
{
	uint32_t to_alloc = ROUNDUP(size, NUM_L2_ENTRIES * SMALL_PAGE_SIZE) /
		(NUM_L2_ENTRIES * SMALL_PAGE_SIZE);

	DMSG("L2 table used: %d/%d", prtn->tables_used + to_alloc,
	     MAX_XLAT_TABLES);
	if (prtn->tables_used + to_alloc > MAX_XLAT_TABLES)
		return NULL;

	memset(prtn->l2_tables[prtn->tables_used], 0,
		sizeof(l2_xlat_tbl_t) * to_alloc);
	prtn->tables_used += to_alloc;
	return prtn->l2_tables[prtn->tables_used - to_alloc];
}

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
	COMPILE_TIME_ASSERT(ATTR_DEVICE_INDEX == TEE_MATTR_MEM_TYPE_DEV);
	COMPILE_TIME_ASSERT(ATTR_NORMAL_CACHED_INDEX ==
			    TEE_MATTR_MEM_TYPE_CACHED);
	COMPILE_TIME_ASSERT(ATTR_STRONG_O_INDEX ==
			    TEE_MATTR_MEM_TYPE_STRONGLY_O);
	COMPILE_TIME_ASSERT(ATTR_TAGGED_CACHED_INDEX ==
			    TEE_MATTR_MEM_TYPE_TAGGED);

	return texcb << TEE_MATTR_MEM_TYPE_SHIFT;
}

static uint32_t mattr_to_texcb(uint32_t attr)
{
	/* Keep in sync with core_mmu.c:core_mmu_mattr_is_ok */
	return (attr >> TEE_MATTR_MEM_TYPE_SHIFT) & TEE_MATTR_MEM_TYPE_MASK;
}


static uint32_t desc_to_mattr(unsigned level, uint32_t desc)
{
	uint32_t a;

	switch (get_desc_type(level, desc)) {
	case DESC_TYPE_PAGE_TABLE:
		a = TEE_MATTR_TABLE;
		if (!(desc & SECTION_PT_NOTSECURE))
			a |= TEE_MATTR_SECURE;
		break;
	case DESC_TYPE_SECTION:
		a = TEE_MATTR_VALID_BLOCK;
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
		a = TEE_MATTR_VALID_BLOCK;
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

	if (level == 1 && (a & TEE_MATTR_TABLE)) {
		desc = SECTION_PT_PT;
		if (!(a & TEE_MATTR_SECURE))
			desc |= SECTION_PT_NOTSECURE;
		return desc;
	}

	if (!(a & TEE_MATTR_VALID_BLOCK))
		return INVALID_DESC;

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
#ifndef CFG_NO_SMP
		desc = SECTION_SECTION | SECTION_SHARED;
#else
		desc = SECTION_SECTION;
#endif

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
#ifndef CFG_NO_SMP
		desc = SMALL_PAGE_SMALL_PAGE | SMALL_PAGE_SHARED;
#else
		desc = SMALL_PAGE_SMALL_PAGE;
#endif

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

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
		unsigned level, vaddr_t va_base, void *table)
{
	tbl_info->level = level;
	tbl_info->next_level = level + 1;
	tbl_info->table = table;
	tbl_info->va_base = va_base;
	assert(level <= 2);
	if (level == 1) {
		tbl_info->shift = SECTION_SHIFT;
		tbl_info->num_entries = NUM_L1_ENTRIES;
	} else {
		tbl_info->shift = SMALL_PAGE_SHIFT;
		tbl_info->num_entries = NUM_L2_ENTRIES;
	}
}

void core_mmu_get_user_pgdir(struct core_mmu_table_info *pgd_info)
{
	void *tbl = (void *)core_mmu_get_ul1_ttb_va(get_prtn());

	core_mmu_set_info_table(pgd_info, 1, 0, tbl);
	pgd_info->num_entries = NUM_UL1_ENTRIES;
}

void core_mmu_create_user_map(struct user_mode_ctx *uctx,
			      struct core_mmu_user_map *map)
{
	struct core_mmu_table_info dir_info = { };

	COMPILE_TIME_ASSERT(L2_TBL_SIZE == PGT_SIZE);

	core_mmu_get_user_pgdir(&dir_info);
	memset(dir_info.table, 0, dir_info.num_entries * sizeof(uint32_t));
	core_mmu_populate_user_map(&dir_info, uctx);
	map->ttbr0 = core_mmu_get_ul1_ttb_pa(get_prtn()) |
		     TEE_MMU_DEFAULT_ATTRS;
	map->ctxid = uctx->vm_info.asid;
}

bool core_mmu_find_table(struct mmu_partition *prtn, vaddr_t va,
			 unsigned max_level,
			 struct core_mmu_table_info *tbl_info)
{
	uint32_t *tbl;
	unsigned n = va >> SECTION_SHIFT;

	if (!prtn)
		prtn = get_prtn();
	tbl = (uint32_t *)core_mmu_get_main_ttb_va(prtn);

	if (max_level == 1 || (tbl[n] & 0x3) != 0x1) {
		core_mmu_set_info_table(tbl_info, 1, 0, tbl);
	} else {
		paddr_t ntbl = tbl[n] & ~((1 << 10) - 1);
		void *l2tbl = phys_to_virt(ntbl, MEM_AREA_TEE_RAM_RW_DATA,
					   L2_TBL_SIZE);

		if (!l2tbl)
			return false;

		core_mmu_set_info_table(tbl_info, 2, n << SECTION_SHIFT, l2tbl);
	}
	return true;
}

void core_mmu_set_entry_primitive(void *table, size_t level, size_t idx,
				  paddr_t pa, uint32_t attr)
{
	uint32_t *tbl = table;
	uint32_t desc = mattr_to_desc(level, attr);

	tbl[idx] = desc | pa;
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
		/* Invalid section */
		shift_mask = 4;
	}

	return desc & ~((1 << shift_mask) - 1);
}

bool core_mmu_entry_to_finer_grained(struct core_mmu_table_info *tbl_info,
				     unsigned int idx, bool secure)
{
	uint32_t *new_table;
	uint32_t *entry;
	uint32_t new_table_desc;
	uint32_t attr;
	uint32_t desc;
	paddr_t pa;
	int i;

	if (tbl_info->level != 1)
		return false;

	if (idx >= NUM_L1_ENTRIES)
		return false;

	entry = (uint32_t *)tbl_info->table + idx;
	attr = desc_to_mattr(1, *entry);

	if (*entry && get_desc_type(1, *entry) == DESC_TYPE_PAGE_TABLE) {
		/*
		 * If there is page table already,
		 * check the secure attribute fits
		 */
		return secure == (bool)(attr & TEE_MATTR_SECURE);
	}

	/* If there is something mapped, check the secure access flag */
	if (attr && secure != (bool)(attr & TEE_MATTR_SECURE))
		return false;

	new_table = core_mmu_alloc_l2(get_prtn(),
				      NUM_L2_ENTRIES * SMALL_PAGE_SIZE);

	if (!new_table)
		return false;

	new_table_desc = SECTION_PT_PT | virt_to_phys(new_table);

	if (!secure)
		new_table_desc |= SECTION_PT_NOTSECURE;

	if (*entry) {
		pa = desc_to_pa(1, *entry);
		desc = mattr_to_desc(2, attr);
		for (i = 0; i < NUM_L2_ENTRIES; i++, pa += SMALL_PAGE_SIZE)
			new_table[i] = desc | pa;
	}

	/* Update descriptor at current level */
	*entry = new_table_desc;

	return true;
}

void core_mmu_get_entry_primitive(const void *table, size_t level,
				  size_t idx, paddr_t *pa, uint32_t *attr)
{
	const uint32_t *tbl = table;

	if (pa)
		*pa = desc_to_pa(level, tbl[idx]);

	if (attr)
		*attr = desc_to_mattr(level, tbl[idx]);
}

void core_mmu_get_user_va_range(vaddr_t *base, size_t *size)
{
	if (base) {
		/* Leaving the first entry unmapped to make NULL unmapped */
		*base = 1 << SECTION_SHIFT;
	}

	if (size)
		*size = (NUM_UL1_ENTRIES - 1) << SECTION_SHIFT;
}

void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	map->ttbr0 = read_ttbr0();
	map->ctxid = read_contextidr();
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

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
		isb();
	} else {
		write_ttbr0(read_ttbr1());
		isb();
	}

	tlbi_all();
	icache_inv_all();

	/* Restore interrupts */
	thread_unmask_exceptions(exceptions);
}

bool core_mmu_user_mapping_is_active(void)
{
	bool ret;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	ret = read_ttbr0() != read_ttbr1();
	thread_unmask_exceptions(exceptions);

	return ret;
}

static void print_mmap_area(const struct tee_mmap_region *mm __maybe_unused,
				const char *str __maybe_unused)
{
	if (!(mm->attr & TEE_MATTR_VALID_BLOCK))
		debug_print("%s [%08" PRIxVA " %08" PRIxVA "] not mapped",
				str, mm->va, mm->va + mm->size);
	else
		debug_print("%s [%08" PRIxVA " %08" PRIxVA "] %s-%s-%s-%s",
				str, mm->va, mm->va + mm->size,
				mattr_is_cached(mm->attr) ? "MEM" : "DEV",
				mm->attr & TEE_MATTR_PW ? "RW" : "RO",
				mm->attr & TEE_MATTR_PX ? "X" : "XN",
				mm->attr & TEE_MATTR_SECURE ? "S" : "NS");
}

void map_memarea_sections(const struct tee_mmap_region *mm, uint32_t *ttb)
{
	uint32_t attr = mattr_to_desc(1, mm->attr);
	size_t idx = mm->va >> SECTION_SHIFT;
	paddr_t pa = 0;
	size_t n;

	if (core_mmap_is_end_of_table(mm))
		return;

	print_mmap_area(mm, "section map");

	attr = mattr_to_desc(1, mm->attr);
	if (attr != INVALID_DESC)
		pa = mm->pa;

	n = ROUNDUP(mm->size, SECTION_SIZE) >> SECTION_SHIFT;
	while (n--) {
		assert(!attr || !ttb[idx] || ttb[idx] == (pa | attr));

		ttb[idx] = pa | attr;
		idx++;
		pa += SECTION_SIZE;
	}
}

void core_init_mmu_prtn(struct mmu_partition *prtn, struct tee_mmap_region *mm)
{
	void *ttb1 = (void *)core_mmu_get_main_ttb_va(prtn);
	size_t n;

	/* reset L1 table */
	memset(ttb1, 0, L1_TBL_SIZE);

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++)
		if (!core_mmu_is_dynamic_vaspace(mm + n))
			core_mmu_map_region(prtn, mm + n);
}

void core_init_mmu(struct tee_mmap_region *mm)
{
	/* Initialize default pagetables */
	core_init_mmu_prtn(&default_partition, mm);
}

void core_init_mmu_regs(struct core_mmu_config *cfg)
{
	cfg->ttbr = core_mmu_get_main_ttb_pa(&default_partition) |
		    TEE_MMU_DEFAULT_ATTRS;

	cfg->prrr = ATTR_DEVICE_PRRR | ATTR_NORMAL_CACHED_PRRR |
		    ATTR_STRONGLY_O_PRRR | ATTR_TAGGED_CACHED_PRRR;
	cfg->nmrr = ATTR_DEVICE_NMRR | ATTR_NORMAL_CACHED_NMRR |
		    ATTR_STRONGLY_O_NMRR | ATTR_TAGGED_CACHED_NMRR;

	cfg->prrr |= PRRR_NS1 | PRRR_DS1;

	/*
	 * Program Domain access control register with two domains:
	 * domain 0: teecore
	 * domain 1: TA
	 */
	cfg->dacr = DACR_DOMAIN(0, DACR_DOMAIN_PERM_CLIENT) |
		    DACR_DOMAIN(1, DACR_DOMAIN_PERM_CLIENT);

	/*
	 * Enable lookups using TTBR0 and TTBR1 with the split of addresses
	 * defined by TEE_MMU_TTBCR_N_VALUE.
	 */
	cfg->ttbcr = TTBCR_N_VALUE;
}

enum core_mmu_fault core_mmu_get_fault_type(uint32_t fsr)
{
	assert(!(fsr & FSR_LPAE));

	switch (fsr & FSR_FS_MASK) {
	case 0x1: /* DFSR[10,3:0] 0b00001 Alignment fault (DFSR only) */
		return CORE_MMU_FAULT_ALIGNMENT;
	case 0x2: /* DFSR[10,3:0] 0b00010 Debug event */
		return CORE_MMU_FAULT_DEBUG_EVENT;
	case 0x4: /* DFSR[10,3:0] b00100 Fault on instr cache maintenance */
	case 0x5: /* DFSR[10,3:0] b00101 Translation fault first level */
	case 0x7: /* DFSR[10,3:0] b00111 Translation fault second level */
		return CORE_MMU_FAULT_TRANSLATION;
	case 0xd: /* DFSR[10,3:0] b01101 Permission fault first level */
	case 0xf: /* DFSR[10,3:0] b01111 Permission fault second level */
		if (fsr & FSR_WNR)
			return CORE_MMU_FAULT_WRITE_PERMISSION;
		else
			return CORE_MMU_FAULT_READ_PERMISSION;
	case 0x3: /* DFSR[10,3:0] b00011 access bit fault on section */
	case 0x6: /* DFSR[10,3:0] b00110 access bit fault on page */
		return CORE_MMU_FAULT_ACCESS_BIT;
	case (1 << 10) | 0x6:
		/* DFSR[10,3:0] 0b10110 Async external abort (DFSR only) */
		return CORE_MMU_FAULT_ASYNC_EXTERNAL;

	default:
		return CORE_MMU_FAULT_OTHER;
	}
}
