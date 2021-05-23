// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2021, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <io.h>
#include <keep.h>
#include <kernel/abort.h>
#include <kernel/asan.h>
#include <kernel/cache_helpers.h>
#include <kernel/linker.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tlb_helpers.h>
#include <kernel/user_mode_ctx.h>
#include <mm/core_memprot.h>
#include <mm/fobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>


static struct vm_paged_region_head core_vm_regions =
	TAILQ_HEAD_INITIALIZER(core_vm_regions);

#define INVALID_PGIDX		UINT_MAX
#define PMEM_FLAG_DIRTY		BIT(0)
#define PMEM_FLAG_HIDDEN	BIT(1)

/*
 * struct tee_pager_pmem - Represents a physical page used for paging.
 *
 * @flags	flags defined by PMEM_FLAG_* above
 * @fobj_pgidx	index of the page in the @fobj
 * @fobj	File object of which a page is made visible.
 * @va_alias	Virtual address where the physical page always is aliased.
 *		Used during remapping of the page when the content need to
 *		be updated before it's available at the new location.
 */
struct tee_pager_pmem {
	unsigned int flags;
	unsigned int fobj_pgidx;
	struct fobj *fobj;
	void *va_alias;
	TAILQ_ENTRY(tee_pager_pmem) link;
};

struct tblidx {
	struct pgt *pgt;
	unsigned int idx;
};

/* The list of physical pages. The first page in the list is the oldest */
TAILQ_HEAD(tee_pager_pmem_head, tee_pager_pmem);

static struct tee_pager_pmem_head tee_pager_pmem_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_pmem_head);

static struct tee_pager_pmem_head tee_pager_lock_pmem_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_lock_pmem_head);

/* number of pages hidden */
#define TEE_PAGER_NHIDE (tee_pager_npages / 3)

/* Number of registered physical pages, used hiding pages. */
static size_t tee_pager_npages;

/* This area covers the IVs for all fobjs with paged IVs */
static struct vm_paged_region *pager_iv_region;
/* Used by make_iv_available(), see make_iv_available() for details. */
static struct tee_pager_pmem *pager_spare_pmem;

#ifdef CFG_WITH_STATS
static struct tee_pager_stats pager_stats;

static inline void incr_ro_hits(void)
{
	pager_stats.ro_hits++;
}

static inline void incr_rw_hits(void)
{
	pager_stats.rw_hits++;
}

static inline void incr_hidden_hits(void)
{
	pager_stats.hidden_hits++;
}

static inline void incr_zi_released(void)
{
	pager_stats.zi_released++;
}

static inline void incr_npages_all(void)
{
	pager_stats.npages_all++;
}

static inline void set_npages(void)
{
	pager_stats.npages = tee_pager_npages;
}

void tee_pager_get_stats(struct tee_pager_stats *stats)
{
	*stats = pager_stats;

	pager_stats.hidden_hits = 0;
	pager_stats.ro_hits = 0;
	pager_stats.rw_hits = 0;
	pager_stats.zi_released = 0;
}

#else /* CFG_WITH_STATS */
static inline void incr_ro_hits(void) { }
static inline void incr_rw_hits(void) { }
static inline void incr_hidden_hits(void) { }
static inline void incr_zi_released(void) { }
static inline void incr_npages_all(void) { }
static inline void set_npages(void) { }

void tee_pager_get_stats(struct tee_pager_stats *stats)
{
	memset(stats, 0, sizeof(struct tee_pager_stats));
}
#endif /* CFG_WITH_STATS */

#define TBL_NUM_ENTRIES	(CORE_MMU_PGDIR_SIZE / SMALL_PAGE_SIZE)
#define TBL_LEVEL	CORE_MMU_PGDIR_LEVEL
#define TBL_SHIFT	SMALL_PAGE_SHIFT

#define EFFECTIVE_VA_SIZE \
	(ROUNDUP(VCORE_START_VA + TEE_RAM_VA_SIZE, CORE_MMU_PGDIR_SIZE) - \
	 ROUNDDOWN(VCORE_START_VA, CORE_MMU_PGDIR_SIZE))

static struct pager_table {
	struct pgt pgt;
	struct core_mmu_table_info tbl_info;
} *pager_tables;
static unsigned int num_pager_tables;

static unsigned pager_spinlock = SPINLOCK_UNLOCK;

/* Defines the range of the alias area */
static tee_mm_entry_t *pager_alias_area;
/*
 * Physical pages are added in a stack like fashion to the alias area,
 * @pager_alias_next_free gives the address of next free entry if
 * @pager_alias_next_free is != 0
 */
static uintptr_t pager_alias_next_free;

#ifdef CFG_TEE_CORE_DEBUG
#define pager_lock(ai) pager_lock_dldetect(__func__, __LINE__, ai)

static uint32_t pager_lock_dldetect(const char *func, const int line,
				    struct abort_info *ai)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	unsigned int retries = 0;
	unsigned int reminder = 0;

	while (!cpu_spin_trylock(&pager_spinlock)) {
		retries++;
		if (!retries) {
			/* wrapped, time to report */
			trace_printf(func, line, TRACE_ERROR, true,
				     "possible spinlock deadlock reminder %u",
				     reminder);
			if (reminder < UINT_MAX)
				reminder++;
			if (ai)
				abort_print(ai);
		}
	}

	return exceptions;
}
#else
static uint32_t pager_lock(struct abort_info __unused *ai)
{
	return cpu_spin_lock_xsave(&pager_spinlock);
}
#endif

static uint32_t pager_lock_check_stack(size_t stack_size)
{
	if (stack_size) {
		int8_t buf[stack_size];
		size_t n;

		/*
		 * Make sure to touch all pages of the stack that we expect
		 * to use with this lock held. We need to take eventual
		 * page faults before the lock is taken or we'll deadlock
		 * the pager. The pages that are populated in this way will
		 * eventually be released at certain save transitions of
		 * the thread.
		 */
		for (n = 0; n < stack_size; n += SMALL_PAGE_SIZE)
			io_write8((vaddr_t)buf + n, 1);
		io_write8((vaddr_t)buf + stack_size - 1, 1);
	}

	return pager_lock(NULL);
}

static void pager_unlock(uint32_t exceptions)
{
	cpu_spin_unlock_xrestore(&pager_spinlock, exceptions);
}

void *tee_pager_phys_to_virt(paddr_t pa, size_t len)
{
	struct core_mmu_table_info ti;
	unsigned idx;
	uint32_t a;
	paddr_t p;
	vaddr_t v;
	size_t n;

	if (pa & SMALL_PAGE_MASK || len > SMALL_PAGE_SIZE)
		return NULL;

	/*
	 * Most addresses are mapped lineary, try that first if possible.
	 */
	if (!tee_pager_get_table_info(pa, &ti))
		return NULL; /* impossible pa */
	idx = core_mmu_va2idx(&ti, pa);
	core_mmu_get_entry(&ti, idx, &p, &a);
	if ((a & TEE_MATTR_VALID_BLOCK) && p == pa)
		return (void *)core_mmu_idx2va(&ti, idx);

	n = 0;
	idx = core_mmu_va2idx(&pager_tables[n].tbl_info, TEE_RAM_VA_START);
	while (true) {
		while (idx < TBL_NUM_ENTRIES) {
			v = core_mmu_idx2va(&pager_tables[n].tbl_info, idx);
			if (v >= (TEE_RAM_VA_START + TEE_RAM_VA_SIZE))
				return NULL;

			core_mmu_get_entry(&pager_tables[n].tbl_info,
					   idx, &p, &a);
			if ((a & TEE_MATTR_VALID_BLOCK) && p == pa)
				return (void *)v;
			idx++;
		}

		n++;
		if (n >= num_pager_tables)
			return NULL;
		idx = 0;
	}

	return NULL;
}

static bool pmem_is_hidden(struct tee_pager_pmem *pmem)
{
	return pmem->flags & PMEM_FLAG_HIDDEN;
}

static bool pmem_is_dirty(struct tee_pager_pmem *pmem)
{
	return pmem->flags & PMEM_FLAG_DIRTY;
}

static bool pmem_is_covered_by_region(struct tee_pager_pmem *pmem,
				      struct vm_paged_region *reg)
{
	if (pmem->fobj != reg->fobj)
		return false;
	if (pmem->fobj_pgidx < reg->fobj_pgoffs)
		return false;
	if ((pmem->fobj_pgidx - reg->fobj_pgoffs) >=
	    (reg->size >> SMALL_PAGE_SHIFT))
		return false;

	return true;
}

static size_t get_pgt_count(vaddr_t base, size_t size)
{
	assert(size);

	return (base + size - 1) / CORE_MMU_PGDIR_SIZE + 1 -
	       base / CORE_MMU_PGDIR_SIZE;
}

static bool region_have_pgt(struct vm_paged_region *reg, struct pgt *pgt)
{
	size_t n = 0;

	for (n = 0; n < get_pgt_count(reg->base, reg->size); n++)
		if (reg->pgt_array[n] == pgt)
			return true;

	return false;
}

static struct tblidx pmem_get_region_tblidx(struct tee_pager_pmem *pmem,
					    struct vm_paged_region *reg)
{
	size_t tbloffs = (reg->base & CORE_MMU_PGDIR_MASK) >> SMALL_PAGE_SHIFT;
	size_t idx = pmem->fobj_pgidx - reg->fobj_pgoffs + tbloffs;

	assert(pmem->fobj && pmem->fobj_pgidx != INVALID_PGIDX);
	assert(idx / TBL_NUM_ENTRIES < get_pgt_count(reg->base, reg->size));

	return (struct tblidx){
		.idx = idx % TBL_NUM_ENTRIES,
		.pgt = reg->pgt_array[idx / TBL_NUM_ENTRIES],
	};
}

static struct pager_table *find_pager_table_may_fail(vaddr_t va)
{
	size_t n;
	const vaddr_t mask = CORE_MMU_PGDIR_MASK;

	if (!pager_tables)
		return NULL;

	n = ((va & ~mask) - pager_tables[0].tbl_info.va_base) >>
	    CORE_MMU_PGDIR_SHIFT;
	if (n >= num_pager_tables)
		return NULL;

	assert(va >= pager_tables[n].tbl_info.va_base &&
	       va <= (pager_tables[n].tbl_info.va_base | mask));

	return pager_tables + n;
}

static struct pager_table *find_pager_table(vaddr_t va)
{
	struct pager_table *pt = find_pager_table_may_fail(va);

	assert(pt);
	return pt;
}

bool tee_pager_get_table_info(vaddr_t va, struct core_mmu_table_info *ti)
{
	struct pager_table *pt = find_pager_table_may_fail(va);

	if (!pt)
		return false;

	*ti = pt->tbl_info;
	return true;
}

static struct core_mmu_table_info *find_table_info(vaddr_t va)
{
	return &find_pager_table(va)->tbl_info;
}

static struct pgt *find_core_pgt(vaddr_t va)
{
	return &find_pager_table(va)->pgt;
}

void tee_pager_set_alias_area(tee_mm_entry_t *mm)
{
	struct pager_table *pt;
	unsigned idx;
	vaddr_t smem = tee_mm_get_smem(mm);
	size_t nbytes = tee_mm_get_bytes(mm);
	vaddr_t v;
	uint32_t a = 0;

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA, smem, smem + nbytes);

	assert(!pager_alias_area);
	pager_alias_area = mm;
	pager_alias_next_free = smem;

	/* Clear all mapping in the alias area */
	pt = find_pager_table(smem);
	idx = core_mmu_va2idx(&pt->tbl_info, smem);
	while (pt <= (pager_tables + num_pager_tables - 1)) {
		while (idx < TBL_NUM_ENTRIES) {
			v = core_mmu_idx2va(&pt->tbl_info, idx);
			if (v >= (smem + nbytes))
				goto out;

			core_mmu_get_entry(&pt->tbl_info, idx, NULL, &a);
			core_mmu_set_entry(&pt->tbl_info, idx, 0, 0);
			if (a & TEE_MATTR_VALID_BLOCK)
				pgt_dec_used_entries(&pt->pgt);
			idx++;
		}

		pt++;
		idx = 0;
	}

out:
	tlbi_mva_range(smem, nbytes, SMALL_PAGE_SIZE);
}

static size_t tbl_usage_count(struct core_mmu_table_info *ti)
{
	size_t n;
	uint32_t a = 0;
	size_t usage = 0;

	for (n = 0; n < ti->num_entries; n++) {
		core_mmu_get_entry(ti, n, NULL, &a);
		if (a & TEE_MATTR_VALID_BLOCK)
			usage++;
	}
	return usage;
}

static void tblidx_get_entry(struct tblidx tblidx, paddr_t *pa, uint32_t *attr)
{
	assert(tblidx.pgt && tblidx.idx < TBL_NUM_ENTRIES);
	core_mmu_get_entry_primitive(tblidx.pgt->tbl, TBL_LEVEL, tblidx.idx,
				     pa, attr);
}

static void tblidx_set_entry(struct tblidx tblidx, paddr_t pa, uint32_t attr)
{
	assert(tblidx.pgt && tblidx.idx < TBL_NUM_ENTRIES);
	core_mmu_set_entry_primitive(tblidx.pgt->tbl, TBL_LEVEL, tblidx.idx,
				     pa, attr);
}

static struct tblidx region_va2tblidx(struct vm_paged_region *reg, vaddr_t va)
{
	paddr_t mask = CORE_MMU_PGDIR_MASK;
	size_t n = 0;

	assert(va >= reg->base && va < (reg->base + reg->size));
	n = (va - (reg->base & ~mask)) / CORE_MMU_PGDIR_SIZE;

	return (struct tblidx){
		.idx = (va & mask) / SMALL_PAGE_SIZE,
		.pgt = reg->pgt_array[n],
	};
}

static vaddr_t tblidx2va(struct tblidx tblidx)
{
	return tblidx.pgt->vabase + (tblidx.idx << SMALL_PAGE_SHIFT);
}

static void tblidx_tlbi_entry(struct tblidx tblidx)
{
	vaddr_t va = tblidx2va(tblidx);

#if defined(CFG_PAGED_USER_TA)
	if (tblidx.pgt->ctx) {
		uint32_t asid = to_user_mode_ctx(tblidx.pgt->ctx)->vm_info.asid;

		tlbi_mva_asid(va, asid);
		return;
	}
#endif
	tlbi_mva_allasid(va);
}

static void pmem_assign_fobj_page(struct tee_pager_pmem *pmem,
				  struct vm_paged_region *reg, vaddr_t va)
{
	struct tee_pager_pmem *p = NULL;
	unsigned int fobj_pgidx = 0;

	assert(!pmem->fobj && pmem->fobj_pgidx == INVALID_PGIDX);

	assert(va >= reg->base && va < (reg->base + reg->size));
	fobj_pgidx = (va - reg->base) / SMALL_PAGE_SIZE + reg->fobj_pgoffs;

	TAILQ_FOREACH(p, &tee_pager_pmem_head, link)
		assert(p->fobj != reg->fobj || p->fobj_pgidx != fobj_pgidx);

	pmem->fobj = reg->fobj;
	pmem->fobj_pgidx = fobj_pgidx;
}

static void pmem_clear(struct tee_pager_pmem *pmem)
{
	pmem->fobj = NULL;
	pmem->fobj_pgidx = INVALID_PGIDX;
	pmem->flags = 0;
}

static void pmem_unmap(struct tee_pager_pmem *pmem, struct pgt *only_this_pgt)
{
	struct vm_paged_region *reg = NULL;
	struct tblidx tblidx = { };
	uint32_t a = 0;

	TAILQ_FOREACH(reg, &pmem->fobj->regions, fobj_link) {
		/*
		 * If only_this_pgt points to a pgt then the pgt of this
		 * region has to match or we'll skip over it.
		 */
		if (only_this_pgt && !region_have_pgt(reg, only_this_pgt))
			continue;
		if (!pmem_is_covered_by_region(pmem, reg))
			continue;
		tblidx = pmem_get_region_tblidx(pmem, reg);
		if (!tblidx.pgt)
			continue;
		tblidx_get_entry(tblidx, NULL, &a);
		if (a & TEE_MATTR_VALID_BLOCK) {
			tblidx_set_entry(tblidx, 0, 0);
			pgt_dec_used_entries(tblidx.pgt);
			tblidx_tlbi_entry(tblidx);
		}
	}
}

void tee_pager_early_init(void)
{
	size_t n = 0;

	num_pager_tables = EFFECTIVE_VA_SIZE / CORE_MMU_PGDIR_SIZE;
	pager_tables = calloc(num_pager_tables, sizeof(*pager_tables));
	if (!pager_tables)
		panic("Cannot allocate pager_tables");

	/*
	 * Note that this depends on add_pager_vaspace() adding vaspace
	 * after end of memory.
	 */
	for (n = 0; n < num_pager_tables; n++) {
		if (!core_mmu_find_table(NULL, VCORE_START_VA +
					 n * CORE_MMU_PGDIR_SIZE, UINT_MAX,
					 &pager_tables[n].tbl_info))
			panic("can't find mmu tables");

		if (pager_tables[n].tbl_info.shift != TBL_SHIFT)
			panic("Unsupported page size in translation table");
		assert(pager_tables[n].tbl_info.num_entries == TBL_NUM_ENTRIES);
		assert(pager_tables[n].tbl_info.level == TBL_LEVEL);

		pager_tables[n].pgt.tbl = pager_tables[n].tbl_info.table;
		pager_tables[n].pgt.vabase = pager_tables[n].tbl_info.va_base;
		pgt_set_used_entries(&pager_tables[n].pgt,
				tbl_usage_count(&pager_tables[n].tbl_info));
	}
}

static void *pager_add_alias_page(paddr_t pa)
{
	unsigned idx;
	struct core_mmu_table_info *ti;
	/* Alias pages mapped without write permission: runtime will care */
	uint32_t attr = TEE_MATTR_VALID_BLOCK |
			(TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT) |
			TEE_MATTR_SECURE | TEE_MATTR_PR;

	DMSG("0x%" PRIxPA, pa);

	ti = find_table_info(pager_alias_next_free);
	idx = core_mmu_va2idx(ti, pager_alias_next_free);
	core_mmu_set_entry(ti, idx, pa, attr);
	pgt_inc_used_entries(find_core_pgt(pager_alias_next_free));
	pager_alias_next_free += SMALL_PAGE_SIZE;
	if (pager_alias_next_free >= (tee_mm_get_smem(pager_alias_area) +
				      tee_mm_get_bytes(pager_alias_area)))
		pager_alias_next_free = 0;
	return (void *)core_mmu_idx2va(ti, idx);
}

static void region_insert(struct vm_paged_region_head *regions,
			  struct vm_paged_region *reg,
			  struct vm_paged_region *r_prev)
{
	uint32_t exceptions = pager_lock_check_stack(8);

	if (r_prev)
		TAILQ_INSERT_AFTER(regions, r_prev, reg, link);
	else
		TAILQ_INSERT_HEAD(regions, reg, link);
	TAILQ_INSERT_TAIL(&reg->fobj->regions, reg, fobj_link);

	pager_unlock(exceptions);
}
DECLARE_KEEP_PAGER(region_insert);

static struct vm_paged_region *alloc_region(vaddr_t base, size_t size)
{
	struct vm_paged_region *reg = NULL;

	if ((base & SMALL_PAGE_MASK) || !size) {
		EMSG("invalid pager region [%" PRIxVA " +0x%zx]", base, size);
		panic();
	}

	reg = calloc(1, sizeof(*reg));
	if (!reg)
		return NULL;
	reg->pgt_array = calloc(get_pgt_count(base, size),
				sizeof(struct pgt *));
	if (!reg->pgt_array) {
		free(reg);
		return NULL;
	}

	reg->base = base;
	reg->size = size;
	return reg;
}

void tee_pager_add_core_region(vaddr_t base, enum vm_paged_region_type type,
			       struct fobj *fobj)
{
	struct vm_paged_region *reg = NULL;
	size_t n = 0;

	assert(fobj);

	DMSG("0x%" PRIxPTR " - 0x%" PRIxPTR " : type %d",
	     base, base + fobj->num_pages * SMALL_PAGE_SIZE, type);

	reg = alloc_region(base, fobj->num_pages * SMALL_PAGE_SIZE);
	if (!reg)
		panic("alloc_region");

	reg->fobj = fobj_get(fobj);
	reg->fobj_pgoffs = 0;
	reg->type = type;

	switch (type) {
	case PAGED_REGION_TYPE_RO:
		reg->flags = TEE_MATTR_PRX;
		break;
	case PAGED_REGION_TYPE_RW:
	case PAGED_REGION_TYPE_LOCK:
		reg->flags = TEE_MATTR_PRW;
		break;
	default:
		panic();
	}

	for (n = 0; n < get_pgt_count(reg->base, reg->size); n++)
		reg->pgt_array[n] = find_core_pgt(base +
						  n * CORE_MMU_PGDIR_SIZE);
	region_insert(&core_vm_regions, reg, NULL);
}

static struct vm_paged_region *find_region(struct vm_paged_region_head *regions,
					   vaddr_t va)
{
	struct vm_paged_region *reg;

	if (!regions)
		return NULL;

	TAILQ_FOREACH(reg, regions, link) {
		if (core_is_buffer_inside(va, 1, reg->base, reg->size))
			return reg;
	}
	return NULL;
}

#ifdef CFG_PAGED_USER_TA
static struct vm_paged_region *find_uta_region(vaddr_t va)
{
	struct ts_ctx *ctx = thread_get_tsd()->ctx;

	if (!is_user_mode_ctx(ctx))
		return NULL;
	return find_region(to_user_mode_ctx(ctx)->regions, va);
}
#else
static struct vm_paged_region *find_uta_region(vaddr_t va __unused)
{
	return NULL;
}
#endif /*CFG_PAGED_USER_TA*/


static uint32_t get_region_mattr(uint32_t reg_flags)
{
	uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_SECURE |
			TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT |
			(reg_flags & (TEE_MATTR_PRWX | TEE_MATTR_URWX));

	return attr;
}

static paddr_t get_pmem_pa(struct tee_pager_pmem *pmem)
{
	struct core_mmu_table_info *ti;
	paddr_t pa;
	unsigned idx;

	ti = find_table_info((vaddr_t)pmem->va_alias);
	idx = core_mmu_va2idx(ti, (vaddr_t)pmem->va_alias);
	core_mmu_get_entry(ti, idx, &pa, NULL);
	return pa;
}

#ifdef CFG_PAGED_USER_TA
static void unlink_region(struct vm_paged_region_head *regions,
			  struct vm_paged_region *reg)
{
	uint32_t exceptions = pager_lock_check_stack(64);

	TAILQ_REMOVE(regions, reg, link);
	TAILQ_REMOVE(&reg->fobj->regions, reg, fobj_link);

	pager_unlock(exceptions);
}
DECLARE_KEEP_PAGER(unlink_region);

static void free_region(struct vm_paged_region *reg)
{
	fobj_put(reg->fobj);
	free(reg->pgt_array);
	free(reg);
}

static TEE_Result pager_add_um_region(struct user_mode_ctx *uctx, vaddr_t base,
				      struct fobj *fobj, uint32_t prot)
{
	struct vm_paged_region *r_prev = NULL;
	struct vm_paged_region *reg = NULL;
	vaddr_t b = base;
	size_t fobj_pgoffs = 0;
	size_t s = fobj->num_pages * SMALL_PAGE_SIZE;

	if (!uctx->regions) {
		uctx->regions = malloc(sizeof(*uctx->regions));
		if (!uctx->regions)
			return TEE_ERROR_OUT_OF_MEMORY;
		TAILQ_INIT(uctx->regions);
	}

	reg = TAILQ_FIRST(uctx->regions);
	while (reg) {
		if (core_is_buffer_intersect(b, s, reg->base, reg->size))
			return TEE_ERROR_BAD_PARAMETERS;
		if (b < reg->base)
			break;
		r_prev = reg;
		reg = TAILQ_NEXT(reg, link);
	}

	reg = alloc_region(b, s);
	if (!reg)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Table info will be set when the context is activated. */
	reg->fobj = fobj_get(fobj);
	reg->fobj_pgoffs = fobj_pgoffs;
	reg->type = PAGED_REGION_TYPE_RW;
	reg->flags = prot;

	region_insert(uctx->regions, reg, r_prev);

	return TEE_SUCCESS;
}

static void map_pgts(struct vm_paged_region *reg)
{
	struct core_mmu_table_info dir_info = { NULL };
	size_t n = 0;

	core_mmu_get_user_pgdir(&dir_info);

	for (n = 0; n < get_pgt_count(reg->base, reg->size); n++) {
		struct pgt *pgt = reg->pgt_array[n];
		uint32_t attr = 0;
		paddr_t pa = 0;
		size_t idx = 0;

		idx = core_mmu_va2idx(&dir_info, pgt->vabase);
		core_mmu_get_entry(&dir_info, idx, &pa, &attr);

		/*
		 * Check if the page table already is used, if it is, it's
		 * already registered.
		 */
		if (pgt->num_used_entries) {
			assert(attr & TEE_MATTR_TABLE);
			assert(pa == virt_to_phys(pgt->tbl));
			continue;
		}

		attr = TEE_MATTR_SECURE | TEE_MATTR_TABLE;
		pa = virt_to_phys(pgt->tbl);
		assert(pa);
		/*
		 * Note that the update of the table entry is guaranteed to
		 * be atomic.
		 */
		core_mmu_set_entry(&dir_info, idx, pa, attr);
	}
}

TEE_Result tee_pager_add_um_region(struct user_mode_ctx *uctx, vaddr_t base,
				   struct fobj *fobj, uint32_t prot)
{
	TEE_Result res = TEE_SUCCESS;
	struct thread_specific_data *tsd = thread_get_tsd();
	struct vm_paged_region *reg = NULL;

	res = pager_add_um_region(uctx, base, fobj, prot);
	if (res)
		return res;

	if (uctx->ts_ctx == tsd->ctx) {
		/*
		 * We're chaning the currently active utc. Assign page
		 * tables to the new regions and make sure that the page
		 * tables are registered in the upper table.
		 */
		tee_pager_assign_um_tables(uctx);
		TAILQ_FOREACH(reg, uctx->regions, link)
			map_pgts(reg);
	}

	return TEE_SUCCESS;
}

static void split_region(struct vm_paged_region *reg,
			 struct vm_paged_region *r2, vaddr_t va)
{
	uint32_t exceptions = pager_lock_check_stack(64);
	size_t diff = va - reg->base;
	size_t r2_pgt_count = 0;
	size_t reg_pgt_count = 0;
	size_t n0 = 0;
	size_t n = 0;

	assert(r2->base == va);
	assert(r2->size == reg->size - diff);

	r2->fobj = fobj_get(reg->fobj);
	r2->fobj_pgoffs = reg->fobj_pgoffs + diff / SMALL_PAGE_SIZE;
	r2->type = reg->type;
	r2->flags = reg->flags;

	r2_pgt_count = get_pgt_count(r2->base, r2->size);
	reg_pgt_count = get_pgt_count(reg->base, reg->size);
	n0 = reg_pgt_count - r2_pgt_count;
	for (n = n0; n < reg_pgt_count; n++)
		r2->pgt_array[n - n0] = reg->pgt_array[n];
	reg->size = diff;

	TAILQ_INSERT_BEFORE(reg, r2, link);
	TAILQ_INSERT_AFTER(&reg->fobj->regions, reg, r2, fobj_link);

	pager_unlock(exceptions);
}
DECLARE_KEEP_PAGER(split_region);

TEE_Result tee_pager_split_um_region(struct user_mode_ctx *uctx, vaddr_t va)
{
	struct vm_paged_region *reg = NULL;
	struct vm_paged_region *r2 = NULL;

	if (va & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	TAILQ_FOREACH(reg, uctx->regions, link) {
		if (va == reg->base || va == reg->base + reg->size)
			return TEE_SUCCESS;
		if (va > reg->base && va < reg->base + reg->size) {
			size_t diff = va - reg->base;

			r2 = alloc_region(va, reg->size - diff);
			if (!r2)
				return TEE_ERROR_OUT_OF_MEMORY;
			split_region(reg, r2, va);
			return TEE_SUCCESS;
		}
	}

	return TEE_SUCCESS;
}

static struct pgt **
merge_region_with_next(struct vm_paged_region_head *regions,
		       struct vm_paged_region *reg,
		       struct vm_paged_region *r_next, struct pgt **pgt_array)
{
	uint32_t exceptions = pager_lock_check_stack(64);
	struct pgt **old_pgt_array = reg->pgt_array;

	reg->pgt_array = pgt_array;
	TAILQ_REMOVE(regions, r_next, link);
	TAILQ_REMOVE(&r_next->fobj->regions, r_next, fobj_link);

	pager_unlock(exceptions);
	return old_pgt_array;
}
DECLARE_KEEP_PAGER(merge_region_with_next);

static struct pgt **alloc_merged_pgt_array(struct vm_paged_region *a,
					   struct vm_paged_region *a_next)
{
	size_t a_next_pgt_count = get_pgt_count(a_next->base, a_next->size);
	size_t a_pgt_count = get_pgt_count(a->base, a->size);
	size_t pgt_count = get_pgt_count(a->base, a->size + a_next->size);
	struct pgt **pgt_array = NULL;
	bool have_shared_pgt = false;

	have_shared_pgt = ((a->base + a->size) & ~CORE_MMU_PGDIR_MASK) ==
			  (a_next->base & ~CORE_MMU_PGDIR_MASK);

	if (have_shared_pgt)
		assert(pgt_count == a_pgt_count + a_next_pgt_count - 1);
	else
		assert(pgt_count == a_pgt_count + a_next_pgt_count);

	/* In case there's a shared pgt they must match */
	if (have_shared_pgt &&
	    a->pgt_array[a_pgt_count - 1] != a_next->pgt_array[0])
		return NULL;

	pgt_array = calloc(sizeof(struct pgt *), pgt_count);
	if (!pgt_array)
		return NULL;

	/*
	 * Copy and merge the two pgt_arrays, note the special case
	 * where a pgt is shared.
	 */
	memcpy(pgt_array, a->pgt_array, a_pgt_count * sizeof(struct pgt *));
	if (have_shared_pgt)
		memcpy(pgt_array + a_pgt_count, a_next->pgt_array + 1,
		       (a_next_pgt_count - 1) * sizeof(struct pgt *));
	else
		memcpy(pgt_array + a_pgt_count, a_next->pgt_array,
		       a_next_pgt_count * sizeof(struct pgt *));

	return pgt_array;
}

void tee_pager_merge_um_region(struct user_mode_ctx *uctx, vaddr_t va,
			       size_t len)
{
	struct vm_paged_region *r_next = NULL;
	struct vm_paged_region *reg = NULL;
	struct pgt **pgt_array = NULL;
	vaddr_t end_va = 0;

	if ((va | len) & SMALL_PAGE_MASK)
		return;
	if (ADD_OVERFLOW(va, len, &end_va))
		return;

	for (reg = TAILQ_FIRST(uctx->regions);; reg = r_next) {
		r_next = TAILQ_NEXT(reg, link);
		if (!r_next)
			return;

		/* Try merging with the area just before va */
		if (reg->base + reg->size < va)
			continue;

		/*
		 * If reg->base is well past our range we're done.
		 * Note that if it's just the page after our range we'll
		 * try to merge.
		 */
		if (reg->base > end_va)
			return;

		if (reg->base + reg->size != r_next->base)
			continue;
		if (reg->fobj != r_next->fobj || reg->type != r_next->type ||
		    reg->flags != r_next->flags)
			continue;
		if (reg->fobj_pgoffs + reg->size / SMALL_PAGE_SIZE !=
		    r_next->fobj_pgoffs)
			continue;

		pgt_array = alloc_merged_pgt_array(reg, r_next);
		if (!pgt_array)
			continue;

		/*
		 * merge_region_with_next() returns the old pgt array which
		 * was replaced in reg. We don't want to call free()
		 * directly from merge_region_with_next() that would pull
		 * free() and its dependencies into the unpaged area.
		 */
		free(merge_region_with_next(uctx->regions, reg, r_next,
					    pgt_array));
		free_region(r_next);
		r_next = reg;
	}
}

static void rem_region(struct vm_paged_region_head *regions,
		       struct vm_paged_region *reg)
{
	struct tee_pager_pmem *pmem;
	size_t last_pgoffs = reg->fobj_pgoffs +
			     (reg->size >> SMALL_PAGE_SHIFT) - 1;
	uint32_t exceptions;
	struct tblidx tblidx = { };
	uint32_t a = 0;

	exceptions = pager_lock_check_stack(64);

	TAILQ_REMOVE(regions, reg, link);
	TAILQ_REMOVE(&reg->fobj->regions, reg, fobj_link);

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (pmem->fobj != reg->fobj ||
		    pmem->fobj_pgidx < reg->fobj_pgoffs ||
		    pmem->fobj_pgidx > last_pgoffs)
			continue;

		tblidx = pmem_get_region_tblidx(pmem, reg);
		tblidx_get_entry(tblidx, NULL, &a);
		if (!(a & TEE_MATTR_VALID_BLOCK))
			continue;

		tblidx_set_entry(tblidx, 0, 0);
		tblidx_tlbi_entry(tblidx);
		pgt_dec_used_entries(tblidx.pgt);
	}

	pager_unlock(exceptions);
}
DECLARE_KEEP_PAGER(rem_region);

void tee_pager_rem_um_region(struct user_mode_ctx *uctx, vaddr_t base,
			     size_t size)
{
	struct vm_paged_region *reg;
	struct vm_paged_region *r_next;
	size_t s = ROUNDUP(size, SMALL_PAGE_SIZE);

	TAILQ_FOREACH_SAFE(reg, uctx->regions, link, r_next) {
		if (core_is_buffer_inside(reg->base, reg->size, base, s)) {
			rem_region(uctx->regions, reg);
			free_region(reg);
		}
	}
	tlbi_asid(uctx->vm_info.asid);
}

void tee_pager_rem_um_regions(struct user_mode_ctx *uctx)
{
	struct vm_paged_region *reg = NULL;

	if (!uctx->regions)
		return;

	while (true) {
		reg = TAILQ_FIRST(uctx->regions);
		if (!reg)
			break;
		unlink_region(uctx->regions, reg);
		free_region(reg);
	}

	free(uctx->regions);
}

static bool __maybe_unused same_context(struct tee_pager_pmem *pmem)
{
	struct vm_paged_region *reg = TAILQ_FIRST(&pmem->fobj->regions);
	void *ctx = reg->pgt_array[0]->ctx;

	do {
		reg = TAILQ_NEXT(reg, fobj_link);
		if (!reg)
			return true;
	} while (reg->pgt_array[0]->ctx == ctx);

	return false;
}

bool tee_pager_set_um_region_attr(struct user_mode_ctx *uctx, vaddr_t base,
				  size_t size, uint32_t flags)
{
	bool ret = false;
	vaddr_t b = base;
	size_t s = size;
	size_t s2 = 0;
	struct vm_paged_region *reg = find_region(uctx->regions, b);
	uint32_t exceptions = 0;
	struct tee_pager_pmem *pmem = NULL;
	uint32_t a = 0;
	uint32_t f = 0;
	uint32_t mattr = 0;
	uint32_t f2 = 0;
	struct tblidx tblidx = { };

	f = (flags & TEE_MATTR_URWX) | TEE_MATTR_UR | TEE_MATTR_PR;
	if (f & TEE_MATTR_UW)
		f |= TEE_MATTR_PW;
	mattr = get_region_mattr(f);

	exceptions = pager_lock_check_stack(SMALL_PAGE_SIZE);

	while (s) {
		if (!reg) {
			ret = false;
			goto out;
		}
		s2 = MIN(reg->size, s);
		b += s2;
		s -= s2;

		if (reg->flags == f)
			goto next_region;

		TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
			if (!pmem_is_covered_by_region(pmem, reg))
				continue;

			tblidx = pmem_get_region_tblidx(pmem, reg);
			tblidx_get_entry(tblidx, NULL, &a);
			if (a == f)
				continue;
			tblidx_set_entry(tblidx, 0, 0);
			tblidx_tlbi_entry(tblidx);

			pmem->flags &= ~PMEM_FLAG_HIDDEN;
			if (pmem_is_dirty(pmem))
				f2 = mattr;
			else
				f2 = mattr & ~(TEE_MATTR_UW | TEE_MATTR_PW);
			tblidx_set_entry(tblidx, get_pmem_pa(pmem), f2);
			if (!(a & TEE_MATTR_VALID_BLOCK))
				pgt_inc_used_entries(tblidx.pgt);
			/*
			 * Make sure the table update is visible before
			 * continuing.
			 */
			dsb_ishst();

			/*
			 * Here's a problem if this page already is shared.
			 * We need do icache invalidate for each context
			 * in which it is shared. In practice this will
			 * never happen.
			 */
			if (flags & TEE_MATTR_UX) {
				void *va = (void *)tblidx2va(tblidx);

				/* Assert that the pmem isn't shared. */
				assert(same_context(pmem));

				dcache_clean_range_pou(va, SMALL_PAGE_SIZE);
				icache_inv_user_range(va, SMALL_PAGE_SIZE);
			}
		}

		reg->flags = f;
next_region:
		reg = TAILQ_NEXT(reg, link);
	}

	ret = true;
out:
	pager_unlock(exceptions);
	return ret;
}

DECLARE_KEEP_PAGER(tee_pager_set_um_region_attr);
#endif /*CFG_PAGED_USER_TA*/

void tee_pager_invalidate_fobj(struct fobj *fobj)
{
	struct tee_pager_pmem *pmem;
	uint32_t exceptions;

	exceptions = pager_lock_check_stack(64);

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link)
		if (pmem->fobj == fobj)
			pmem_clear(pmem);

	pager_unlock(exceptions);
}
DECLARE_KEEP_PAGER(tee_pager_invalidate_fobj);

static struct tee_pager_pmem *pmem_find(struct vm_paged_region *reg, vaddr_t va)
{
	struct tee_pager_pmem *pmem = NULL;
	size_t fobj_pgidx = 0;

	assert(va >= reg->base && va < (reg->base + reg->size));
	fobj_pgidx = (va - reg->base) / SMALL_PAGE_SIZE + reg->fobj_pgoffs;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link)
		if (pmem->fobj == reg->fobj && pmem->fobj_pgidx == fobj_pgidx)
			return pmem;

	return NULL;
}

static bool tee_pager_unhide_page(struct vm_paged_region *reg, vaddr_t page_va)
{
	struct tblidx tblidx = region_va2tblidx(reg, page_va);
	struct tee_pager_pmem *pmem = pmem_find(reg, page_va);
	uint32_t a = get_region_mattr(reg->flags);
	uint32_t attr = 0;
	paddr_t pa = 0;

	if (!pmem)
		return false;

	tblidx_get_entry(tblidx, NULL, &attr);
	if (attr & TEE_MATTR_VALID_BLOCK)
		return false;

	/*
	 * The page is hidden, or not not mapped yet. Unhide the page and
	 * move it to the tail.
	 *
	 * Since the page isn't mapped there doesn't exist a valid TLB entry
	 * for this address, so no TLB invalidation is required after setting
	 * the new entry. A DSB is needed though, to make the write visible.
	 *
	 * For user executable pages it's more complicated. Those pages can
	 * be shared between multiple TA mappings and thus populated by
	 * another TA. The reference manual states that:
	 *
	 * "instruction cache maintenance is required only after writing
	 * new data to a physical address that holds an instruction."
	 *
	 * So for hidden pages we would not need to invalidate i-cache, but
	 * for newly populated pages we do. Since we don't know which we
	 * have to assume the worst and always invalidate the i-cache. We
	 * don't need to clean the d-cache though, since that has already
	 * been done earlier.
	 *
	 * Additional bookkeeping to tell if the i-cache invalidation is
	 * needed or not is left as a future optimization.
	 */

	/* If it's not a dirty block, then it should be read only. */
	if (!pmem_is_dirty(pmem))
		a &= ~(TEE_MATTR_PW | TEE_MATTR_UW);

	pa = get_pmem_pa(pmem);
	pmem->flags &= ~PMEM_FLAG_HIDDEN;
	if (reg->flags & TEE_MATTR_UX) {
		void *va = (void *)tblidx2va(tblidx);

		/* Set a temporary read-only mapping */
		assert(!(a & (TEE_MATTR_UW | TEE_MATTR_PW)));
		tblidx_set_entry(tblidx, pa, a & ~TEE_MATTR_UX);
		dsb_ishst();

		icache_inv_user_range(va, SMALL_PAGE_SIZE);

		/* Set the final mapping */
		tblidx_set_entry(tblidx, pa, a);
		tblidx_tlbi_entry(tblidx);
	} else {
		tblidx_set_entry(tblidx, pa, a);
		dsb_ishst();
	}
	pgt_inc_used_entries(tblidx.pgt);

	TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
	TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	incr_hidden_hits();
	return true;
}

static void tee_pager_hide_pages(void)
{
	struct tee_pager_pmem *pmem = NULL;
	size_t n = 0;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (n >= TEE_PAGER_NHIDE)
			break;
		n++;

		/* we cannot hide pages when pmem->fobj is not defined. */
		if (!pmem->fobj)
			continue;

		if (pmem_is_hidden(pmem))
			continue;

		pmem->flags |= PMEM_FLAG_HIDDEN;
		pmem_unmap(pmem, NULL);
	}
}

static unsigned int __maybe_unused
num_regions_with_pmem(struct tee_pager_pmem *pmem)
{
	struct vm_paged_region *reg = NULL;
	unsigned int num_matches = 0;

	TAILQ_FOREACH(reg, &pmem->fobj->regions, fobj_link)
		if (pmem_is_covered_by_region(pmem, reg))
			num_matches++;

	return num_matches;
}

/*
 * Find mapped pmem, hide and move to pageble pmem.
 * Return false if page was not mapped, and true if page was mapped.
 */
static bool tee_pager_release_one_phys(struct vm_paged_region *reg,
				       vaddr_t page_va)
{
	struct tee_pager_pmem *pmem = NULL;
	struct tblidx tblidx = { };
	size_t fobj_pgidx = 0;

	assert(page_va >= reg->base && page_va < (reg->base + reg->size));
	fobj_pgidx = (page_va - reg->base) / SMALL_PAGE_SIZE +
		     reg->fobj_pgoffs;

	TAILQ_FOREACH(pmem, &tee_pager_lock_pmem_head, link) {
		if (pmem->fobj != reg->fobj || pmem->fobj_pgidx != fobj_pgidx)
			continue;

		/*
		 * Locked pages may not be shared. We're asserting that the
		 * number of regions using this pmem is one and only one as
		 * we're about to unmap it.
		 */
		assert(num_regions_with_pmem(pmem) == 1);

		tblidx = pmem_get_region_tblidx(pmem, reg);
		tblidx_set_entry(tblidx, 0, 0);
		pgt_dec_used_entries(tblidx.pgt);
		TAILQ_REMOVE(&tee_pager_lock_pmem_head, pmem, link);
		pmem_clear(pmem);
		tee_pager_npages++;
		set_npages();
		TAILQ_INSERT_HEAD(&tee_pager_pmem_head, pmem, link);
		incr_zi_released();
		return true;
	}

	return false;
}

static void pager_deploy_page(struct tee_pager_pmem *pmem,
			      struct vm_paged_region *reg, vaddr_t page_va,
			      bool clean_user_cache, bool writable)
{
	struct tblidx tblidx = region_va2tblidx(reg, page_va);
	uint32_t attr = get_region_mattr(reg->flags);
	struct core_mmu_table_info *ti = NULL;
	uint8_t *va_alias = pmem->va_alias;
	paddr_t pa = get_pmem_pa(pmem);
	unsigned int idx_alias = 0;
	uint32_t attr_alias = 0;
	paddr_t pa_alias = 0;

	/* Ensure we are allowed to write to aliased virtual page */
	ti = find_table_info((vaddr_t)va_alias);
	idx_alias = core_mmu_va2idx(ti, (vaddr_t)va_alias);
	core_mmu_get_entry(ti, idx_alias, &pa_alias, &attr_alias);
	if (!(attr_alias & TEE_MATTR_PW)) {
		attr_alias |= TEE_MATTR_PW;
		core_mmu_set_entry(ti, idx_alias, pa_alias, attr_alias);
		tlbi_mva_allasid((vaddr_t)va_alias);
	}

	asan_tag_access(va_alias, va_alias + SMALL_PAGE_SIZE);
	if (fobj_load_page(pmem->fobj, pmem->fobj_pgidx, va_alias)) {
		EMSG("PH 0x%" PRIxVA " failed", page_va);
		panic();
	}
	switch (reg->type) {
	case PAGED_REGION_TYPE_RO:
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
		incr_ro_hits();
		/* Forbid write to aliases for read-only (maybe exec) pages */
		attr_alias &= ~TEE_MATTR_PW;
		core_mmu_set_entry(ti, idx_alias, pa_alias, attr_alias);
		tlbi_mva_allasid((vaddr_t)va_alias);
		break;
	case PAGED_REGION_TYPE_RW:
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
		if (writable && (attr & (TEE_MATTR_PW | TEE_MATTR_UW)))
			pmem->flags |= PMEM_FLAG_DIRTY;
		incr_rw_hits();
		break;
	case PAGED_REGION_TYPE_LOCK:
		/* Move page to lock list */
		if (tee_pager_npages <= 0)
			panic("Running out of pages");
		tee_pager_npages--;
		set_npages();
		TAILQ_INSERT_TAIL(&tee_pager_lock_pmem_head, pmem, link);
		break;
	default:
		panic();
	}
	asan_tag_no_access(va_alias, va_alias + SMALL_PAGE_SIZE);

	if (!writable)
		attr &= ~(TEE_MATTR_PW | TEE_MATTR_UW);

	/*
	 * We've updated the page using the aliased mapping and
	 * some cache maintenance is now needed if it's an
	 * executable page.
	 *
	 * Since the d-cache is a Physically-indexed,
	 * physically-tagged (PIPT) cache we can clean either the
	 * aliased address or the real virtual address. In this
	 * case we choose the real virtual address.
	 *
	 * The i-cache can also be PIPT, but may be something else
	 * too like VIPT. The current code requires the caches to
	 * implement the IVIPT extension, that is:
	 * "instruction cache maintenance is required only after
	 * writing new data to a physical address that holds an
	 * instruction."
	 *
	 * To portably invalidate the icache the page has to
	 * be mapped at the final virtual address but not
	 * executable.
	 */
	if (reg->flags & (TEE_MATTR_PX | TEE_MATTR_UX)) {
		uint32_t mask = TEE_MATTR_PX | TEE_MATTR_UX |
				TEE_MATTR_PW | TEE_MATTR_UW;
		void *va = (void *)page_va;

		/* Set a temporary read-only mapping */
		tblidx_set_entry(tblidx, pa, attr & ~mask);
		tblidx_tlbi_entry(tblidx);

		dcache_clean_range_pou(va, SMALL_PAGE_SIZE);
		if (clean_user_cache)
			icache_inv_user_range(va, SMALL_PAGE_SIZE);
		else
			icache_inv_range(va, SMALL_PAGE_SIZE);

		/* Set the final mapping */
		tblidx_set_entry(tblidx, pa, attr);
		tblidx_tlbi_entry(tblidx);
	} else {
		tblidx_set_entry(tblidx, pa, attr);
		/*
		 * No need to flush TLB for this entry, it was
		 * invalid. We should use a barrier though, to make
		 * sure that the change is visible.
		 */
		dsb_ishst();
	}
	pgt_inc_used_entries(tblidx.pgt);

	FMSG("Mapped 0x%" PRIxVA " -> 0x%" PRIxPA, page_va, pa);
}

static void make_dirty_page(struct tee_pager_pmem *pmem,
			    struct vm_paged_region *reg, struct tblidx tblidx,
			    paddr_t pa)
{
	assert(reg->flags & (TEE_MATTR_UW | TEE_MATTR_PW));
	assert(!(pmem->flags & PMEM_FLAG_DIRTY));

	FMSG("Dirty %#"PRIxVA, tblidx2va(tblidx));
	pmem->flags |= PMEM_FLAG_DIRTY;
	tblidx_set_entry(tblidx, pa, get_region_mattr(reg->flags));
	tblidx_tlbi_entry(tblidx);
}

/*
 * This function takes a reference to a page (@fobj + fobj_pgidx) and makes
 * the corresponding IV available.
 *
 * In case the page needs to be saved the IV must be writable, consequently
 * is the page holding the IV made dirty. If the page instead only is to
 * be verified it's enough that the page holding the IV is readonly and
 * thus doesn't have to be made dirty too.
 *
 * This function depends on pager_spare_pmem pointing to a free pmem when
 * entered. In case the page holding the needed IV isn't mapped this spare
 * pmem is used to map the page. If this function has used pager_spare_pmem
 * and assigned it to NULL it must be reassigned with a new free pmem
 * before this function can be called again.
 */
static void make_iv_available(struct fobj *fobj, unsigned int fobj_pgidx,
			      bool writable)
{
	struct vm_paged_region *reg = pager_iv_region;
	struct tee_pager_pmem *pmem = NULL;
	struct tblidx tblidx = { };
	vaddr_t page_va = 0;
	uint32_t attr = 0;
	paddr_t pa = 0;

	page_va = fobj_get_iv_vaddr(fobj, fobj_pgidx) & ~SMALL_PAGE_MASK;
	if (!IS_ENABLED(CFG_CORE_PAGE_TAG_AND_IV) || !page_va) {
		assert(!page_va);
		return;
	}

	assert(reg && reg->type == PAGED_REGION_TYPE_RW);
	assert(pager_spare_pmem);
	assert(core_is_buffer_inside(page_va, 1, reg->base, reg->size));

	tblidx = region_va2tblidx(reg, page_va);
	/*
	 * We don't care if tee_pager_unhide_page() succeeds or not, we're
	 * still checking the attributes afterwards.
	 */
	tee_pager_unhide_page(reg, page_va);
	tblidx_get_entry(tblidx, &pa, &attr);
	if (!(attr & TEE_MATTR_VALID_BLOCK)) {
		/*
		 * We're using the spare pmem to map the IV corresponding
		 * to another page.
		 */
		pmem = pager_spare_pmem;
		pager_spare_pmem = NULL;
		pmem_assign_fobj_page(pmem, reg, page_va);

		if (writable)
			pmem->flags |= PMEM_FLAG_DIRTY;

		pager_deploy_page(pmem, reg, page_va,
				  false /*!clean_user_cache*/, writable);
	} else if (writable && !(attr & TEE_MATTR_PW)) {
		pmem = pmem_find(reg, page_va);
		/* Note that pa is valid since TEE_MATTR_VALID_BLOCK is set */
		make_dirty_page(pmem, reg, tblidx, pa);
	}
}

static void pager_get_page(struct vm_paged_region *reg, struct abort_info *ai,
			   bool clean_user_cache)
{
	vaddr_t page_va = ai->va & ~SMALL_PAGE_MASK;
	struct tblidx tblidx = region_va2tblidx(reg, page_va);
	struct tee_pager_pmem *pmem = NULL;
	bool writable = false;
	uint32_t attr = 0;

	/*
	 * Get a pmem to load code and data into, also make sure
	 * the corresponding IV page is available.
	 */
	while (true) {
		pmem = TAILQ_FIRST(&tee_pager_pmem_head);
		if (!pmem) {
			EMSG("No pmem entries");
			abort_print(ai);
			panic();
		}

		if (pmem->fobj) {
			pmem_unmap(pmem, NULL);
			if (pmem_is_dirty(pmem)) {
				uint8_t *va = pmem->va_alias;

				make_iv_available(pmem->fobj, pmem->fobj_pgidx,
						  true /*writable*/);
				asan_tag_access(va, va + SMALL_PAGE_SIZE);
				if (fobj_save_page(pmem->fobj, pmem->fobj_pgidx,
						   pmem->va_alias))
					panic("fobj_save_page");
				asan_tag_no_access(va, va + SMALL_PAGE_SIZE);

				pmem_clear(pmem);

				/*
				 * If the spare pmem was used by
				 * make_iv_available() we need to replace
				 * it with the just freed pmem.
				 *
				 * See make_iv_available() for details.
				 */
				if (IS_ENABLED(CFG_CORE_PAGE_TAG_AND_IV) &&
				    !pager_spare_pmem) {
					TAILQ_REMOVE(&tee_pager_pmem_head,
						     pmem, link);
					pager_spare_pmem = pmem;
					pmem = NULL;
				}

				/*
				 * Check if the needed virtual page was
				 * made available as a side effect of the
				 * call to make_iv_available() above. If so
				 * we're done.
				 */
				tblidx_get_entry(tblidx, NULL, &attr);
				if (attr & TEE_MATTR_VALID_BLOCK)
					return;

				/*
				 * The freed pmem was used to replace the
				 * consumed pager_spare_pmem above. Restart
				 * to find another pmem.
				 */
				if (!pmem)
					continue;
			}
		}

		TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
		pmem_clear(pmem);

		pmem_assign_fobj_page(pmem, reg, page_va);
		make_iv_available(pmem->fobj, pmem->fobj_pgidx,
				  false /*!writable*/);
		if (!IS_ENABLED(CFG_CORE_PAGE_TAG_AND_IV) || pager_spare_pmem)
			break;

		/*
		 * The spare pmem was used by make_iv_available(). We need
		 * to replace it with the just freed pmem. And get another
		 * pmem.
		 *
		 * See make_iv_available() for details.
		 */
		pmem_clear(pmem);
		pager_spare_pmem = pmem;
	}

	/*
	 * PAGED_REGION_TYPE_LOCK are always writable while PAGED_REGION_TYPE_RO
	 * are never writable.
	 *
	 * Pages from PAGED_REGION_TYPE_RW starts read-only to be
	 * able to tell when they are updated and should be tagged
	 * as dirty.
	 */
	if (reg->type == PAGED_REGION_TYPE_LOCK ||
	    (reg->type == PAGED_REGION_TYPE_RW && abort_is_write_fault(ai)))
		writable = true;
	else
		writable = false;

	pager_deploy_page(pmem, reg, page_va, clean_user_cache, writable);
}

static bool pager_update_permissions(struct vm_paged_region *reg,
				     struct abort_info *ai, bool *handled)
{
	struct tblidx tblidx = region_va2tblidx(reg, ai->va);
	struct tee_pager_pmem *pmem = NULL;
	uint32_t attr = 0;
	paddr_t pa = 0;

	*handled = false;

	tblidx_get_entry(tblidx, &pa, &attr);

	/* Not mapped */
	if (!(attr & TEE_MATTR_VALID_BLOCK))
		return false;

	/* Not readable, should not happen */
	if (abort_is_user_exception(ai)) {
		if (!(attr & TEE_MATTR_UR))
			return true;
	} else {
		if (!(attr & TEE_MATTR_PR)) {
			abort_print_error(ai);
			panic();
		}
	}

	switch (core_mmu_get_fault_type(ai->fault_descr)) {
	case CORE_MMU_FAULT_TRANSLATION:
	case CORE_MMU_FAULT_READ_PERMISSION:
		if (ai->abort_type == ABORT_TYPE_PREFETCH) {
			/* Check attempting to execute from an NOX page */
			if (abort_is_user_exception(ai)) {
				if (!(attr & TEE_MATTR_UX))
					return true;
			} else {
				if (!(attr & TEE_MATTR_PX)) {
					abort_print_error(ai);
					panic();
				}
			}
		}
		/* Since the page is mapped now it's OK */
		break;
	case CORE_MMU_FAULT_WRITE_PERMISSION:
		/* Check attempting to write to an RO page */
		pmem = pmem_find(reg, ai->va);
		if (!pmem)
			panic();
		if (abort_is_user_exception(ai)) {
			if (!(reg->flags & TEE_MATTR_UW))
				return true;
			if (!(attr & TEE_MATTR_UW))
				make_dirty_page(pmem, reg, tblidx, pa);
		} else {
			if (!(reg->flags & TEE_MATTR_PW)) {
				abort_print_error(ai);
				panic();
			}
			if (!(attr & TEE_MATTR_PW))
				make_dirty_page(pmem, reg, tblidx, pa);
		}
		/* Since permissions has been updated now it's OK */
		break;
	default:
		/* Some fault we can't deal with */
		if (abort_is_user_exception(ai))
			return true;
		abort_print_error(ai);
		panic();
	}
	*handled = true;
	return true;
}

#ifdef CFG_TEE_CORE_DEBUG
static void stat_handle_fault(void)
{
	static size_t num_faults;
	static size_t min_npages = SIZE_MAX;
	static size_t total_min_npages = SIZE_MAX;

	num_faults++;
	if ((num_faults % 1024) == 0 || tee_pager_npages < total_min_npages) {
		DMSG("nfaults %zu npages %zu (min %zu)",
		     num_faults, tee_pager_npages, min_npages);
		min_npages = tee_pager_npages; /* reset */
	}
	if (tee_pager_npages < min_npages)
		min_npages = tee_pager_npages;
	if (tee_pager_npages < total_min_npages)
		total_min_npages = tee_pager_npages;
}
#else
static void stat_handle_fault(void)
{
}
#endif

bool tee_pager_handle_fault(struct abort_info *ai)
{
	struct vm_paged_region *reg;
	vaddr_t page_va = ai->va & ~SMALL_PAGE_MASK;
	uint32_t exceptions;
	bool ret;
	bool clean_user_cache = false;

#ifdef TEE_PAGER_DEBUG_PRINT
	if (!abort_is_user_exception(ai))
		abort_print(ai);
#endif

	/*
	 * We're updating pages that can affect several active CPUs at a
	 * time below. We end up here because a thread tries to access some
	 * memory that isn't available. We have to be careful when making
	 * that memory available as other threads may succeed in accessing
	 * that address the moment after we've made it available.
	 *
	 * That means that we can't just map the memory and populate the
	 * page, instead we use the aliased mapping to populate the page
	 * and once everything is ready we map it.
	 */
	exceptions = pager_lock(ai);

	stat_handle_fault();

	/* check if the access is valid */
	if (abort_is_user_exception(ai)) {
		reg = find_uta_region(ai->va);
		clean_user_cache = true;
	} else {
		reg = find_region(&core_vm_regions, ai->va);
		if (!reg) {
			reg = find_uta_region(ai->va);
			clean_user_cache = true;
		}
	}
	if (!reg || !reg->pgt_array[0]) {
		ret = false;
		goto out;
	}

	if (tee_pager_unhide_page(reg, page_va))
		goto out_success;

	/*
	 * The page wasn't hidden, but some other core may have
	 * updated the table entry before we got here or we need
	 * to make a read-only page read-write (dirty).
	 */
	if (pager_update_permissions(reg, ai, &ret)) {
		/*
		 * Nothing more to do with the abort. The problem
		 * could already have been dealt with from another
		 * core or if ret is false the TA will be paniced.
		 */
		goto out;
	}

	pager_get_page(reg, ai, clean_user_cache);

out_success:
	tee_pager_hide_pages();
	ret = true;
out:
	pager_unlock(exceptions);
	return ret;
}

void tee_pager_add_pages(vaddr_t vaddr, size_t npages, bool unmap)
{
	size_t n = 0;

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA " : %d",
	     vaddr, vaddr + npages * SMALL_PAGE_SIZE, (int)unmap);

	/* setup memory */
	for (n = 0; n < npages; n++) {
		struct core_mmu_table_info *ti = NULL;
		struct tee_pager_pmem *pmem = NULL;
		vaddr_t va = vaddr + n * SMALL_PAGE_SIZE;
		struct tblidx tblidx = { };
		unsigned int pgidx = 0;
		paddr_t pa = 0;
		uint32_t attr = 0;

		ti = find_table_info(va);
		pgidx = core_mmu_va2idx(ti, va);
		/*
		 * Note that we can only support adding pages in the
		 * valid range of this table info, currently not a problem.
		 */
		core_mmu_get_entry(ti, pgidx, &pa, &attr);

		/* Ignore unmapped pages/blocks */
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;

		pmem = calloc(1, sizeof(struct tee_pager_pmem));
		if (!pmem)
			panic("out of mem");
		pmem_clear(pmem);

		pmem->va_alias = pager_add_alias_page(pa);

		if (unmap) {
			core_mmu_set_entry(ti, pgidx, 0, 0);
			pgt_dec_used_entries(find_core_pgt(va));
		} else {
			struct vm_paged_region *reg = NULL;

			/*
			 * The page is still mapped, let's assign the region
			 * and update the protection bits accordingly.
			 */
			reg = find_region(&core_vm_regions, va);
			assert(reg);
			pmem_assign_fobj_page(pmem, reg, va);
			tblidx = pmem_get_region_tblidx(pmem, reg);
			assert(tblidx.pgt == find_core_pgt(va));
			assert(pa == get_pmem_pa(pmem));
			tblidx_set_entry(tblidx, pa,
					 get_region_mattr(reg->flags));
		}

		if (unmap && IS_ENABLED(CFG_CORE_PAGE_TAG_AND_IV) &&
		    !pager_spare_pmem) {
			pager_spare_pmem = pmem;
		} else {
			tee_pager_npages++;
			incr_npages_all();
			set_npages();
			TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
		}
	}

	/*
	 * As this is done at inits, invalidate all TLBs once instead of
	 * targeting only the modified entries.
	 */
	tlbi_all();
}

#ifdef CFG_PAGED_USER_TA
static struct pgt *find_pgt(struct pgt *pgt, vaddr_t va)
{
	struct pgt *p = pgt;

	while (p && (va & ~CORE_MMU_PGDIR_MASK) != p->vabase)
		p = SLIST_NEXT(p, link);
	return p;
}

void tee_pager_assign_um_tables(struct user_mode_ctx *uctx)
{
	struct vm_paged_region *reg = NULL;
	struct pgt *pgt = NULL;
	size_t n = 0;

	if (!uctx->regions)
		return;

	pgt = SLIST_FIRST(&thread_get_tsd()->pgt_cache);
	TAILQ_FOREACH(reg, uctx->regions, link) {
		for (n = 0; n < get_pgt_count(reg->base, reg->size); n++) {
			vaddr_t va = reg->base + CORE_MMU_PGDIR_SIZE * n;
			struct pgt *p __maybe_unused = find_pgt(pgt, va);

			if (!reg->pgt_array[n])
				reg->pgt_array[n] = p;
			else
				assert(reg->pgt_array[n] == p);
		}
	}
}

void tee_pager_pgt_save_and_release_entries(struct pgt *pgt)
{
	struct tee_pager_pmem *pmem = NULL;
	struct vm_paged_region *reg = NULL;
	struct vm_paged_region_head *regions = NULL;
	uint32_t exceptions = pager_lock_check_stack(SMALL_PAGE_SIZE);
	size_t n = 0;

	if (!pgt->num_used_entries)
		goto out;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (pmem->fobj)
			pmem_unmap(pmem, pgt);
	}
	assert(!pgt->num_used_entries);

out:
	regions = to_user_mode_ctx(pgt->ctx)->regions;
	if (regions) {
		TAILQ_FOREACH(reg, regions, link) {
			for (n = 0; n < get_pgt_count(reg->base, reg->size);
			     n++) {
				if (reg->pgt_array[n] == pgt) {
					reg->pgt_array[n] = NULL;
					break;
				}
			}
		}
	}

	pager_unlock(exceptions);
}
DECLARE_KEEP_PAGER(tee_pager_pgt_save_and_release_entries);
#endif /*CFG_PAGED_USER_TA*/

void tee_pager_release_phys(void *addr, size_t size)
{
	bool unmaped = false;
	vaddr_t va = (vaddr_t)addr;
	vaddr_t begin = ROUNDUP(va, SMALL_PAGE_SIZE);
	vaddr_t end = ROUNDDOWN(va + size, SMALL_PAGE_SIZE);
	struct vm_paged_region *reg;
	uint32_t exceptions;

	if (end <= begin)
		return;

	exceptions = pager_lock_check_stack(128);

	for (va = begin; va < end; va += SMALL_PAGE_SIZE) {
		reg = find_region(&core_vm_regions, va);
		if (!reg)
			panic();
		unmaped |= tee_pager_release_one_phys(reg, va);
	}

	if (unmaped)
		tlbi_mva_range(begin, end - begin, SMALL_PAGE_SIZE);

	pager_unlock(exceptions);
}
DECLARE_KEEP_PAGER(tee_pager_release_phys);

void *tee_pager_alloc(size_t size)
{
	tee_mm_entry_t *mm = NULL;
	uint8_t *smem = NULL;
	size_t num_pages = 0;
	struct fobj *fobj = NULL;

	if (!size)
		return NULL;

	mm = tee_mm_alloc(&tee_mm_vcore, ROUNDUP(size, SMALL_PAGE_SIZE));
	if (!mm)
		return NULL;

	smem = (uint8_t *)tee_mm_get_smem(mm);
	num_pages = tee_mm_get_bytes(mm) / SMALL_PAGE_SIZE;
	fobj = fobj_locked_paged_alloc(num_pages);
	if (!fobj) {
		tee_mm_free(mm);
		return NULL;
	}

	tee_pager_add_core_region((vaddr_t)smem, PAGED_REGION_TYPE_LOCK, fobj);
	fobj_put(fobj);

	asan_tag_access(smem, smem + num_pages * SMALL_PAGE_SIZE);

	return smem;
}

vaddr_t tee_pager_init_iv_region(struct fobj *fobj)
{
	tee_mm_entry_t *mm = NULL;
	uint8_t *smem = NULL;

	assert(!pager_iv_region);

	mm = tee_mm_alloc(&tee_mm_vcore, fobj->num_pages * SMALL_PAGE_SIZE);
	if (!mm)
		panic();

	smem = (uint8_t *)tee_mm_get_smem(mm);
	tee_pager_add_core_region((vaddr_t)smem, PAGED_REGION_TYPE_RW, fobj);
	fobj_put(fobj);

	asan_tag_access(smem, smem + fobj->num_pages * SMALL_PAGE_SIZE);

	pager_iv_region = find_region(&core_vm_regions, (vaddr_t)smem);
	assert(pager_iv_region && pager_iv_region->fobj == fobj);

	return (vaddr_t)smem;
}
