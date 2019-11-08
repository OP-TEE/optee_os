// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <io.h>
#include <keep.h>
#include <kernel/abort.h>
#include <kernel/asan.h>
#include <kernel/cache_helpers.h>
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


static struct tee_pager_area_head tee_pager_area_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_area_head);

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
	(ROUNDUP(TEE_RAM_VA_START + TEE_RAM_VA_SIZE, \
		 CORE_MMU_PGDIR_SIZE) - \
	 ROUNDDOWN(TEE_RAM_VA_START, CORE_MMU_PGDIR_SIZE))

static struct pager_table {
	struct pgt pgt;
	struct core_mmu_table_info tbl_info;
} pager_tables[EFFECTIVE_VA_SIZE / CORE_MMU_PGDIR_SIZE];

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

void *tee_pager_phys_to_virt(paddr_t pa)
{
	struct core_mmu_table_info ti;
	unsigned idx;
	uint32_t a;
	paddr_t p;
	vaddr_t v;
	size_t n;

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
		if (n >= ARRAY_SIZE(pager_tables))
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

static bool pmem_is_covered_by_area(struct tee_pager_pmem *pmem,
				    struct tee_pager_area *area)
{
	if (pmem->fobj != area->fobj)
		return false;
	if (pmem->fobj_pgidx < area->fobj_pgoffs)
		return false;
	if ((pmem->fobj_pgidx - area->fobj_pgoffs) >=
	    (area->size >> SMALL_PAGE_SHIFT))
		return false;

	return true;
}

static size_t pmem_get_area_tblidx(struct tee_pager_pmem *pmem,
				   struct tee_pager_area *area)
{
	size_t tbloffs = (area->base & CORE_MMU_PGDIR_MASK) >> SMALL_PAGE_SHIFT;

	return pmem->fobj_pgidx - area->fobj_pgoffs + tbloffs;
}

static struct pager_table *find_pager_table_may_fail(vaddr_t va)
{
	size_t n;
	const vaddr_t mask = CORE_MMU_PGDIR_MASK;

	n = ((va & ~mask) - pager_tables[0].tbl_info.va_base) >>
	    CORE_MMU_PGDIR_SHIFT;
	if (n >= ARRAY_SIZE(pager_tables))
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
	while (pt <= (pager_tables + ARRAY_SIZE(pager_tables) - 1)) {
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

static void area_get_entry(struct tee_pager_area *area, size_t idx,
			   paddr_t *pa, uint32_t *attr)
{
	assert(area->pgt);
	assert(idx < TBL_NUM_ENTRIES);
	core_mmu_get_entry_primitive(area->pgt->tbl, TBL_LEVEL, idx, pa, attr);
}

static void area_set_entry(struct tee_pager_area *area, size_t idx,
			   paddr_t pa, uint32_t attr)
{
	assert(area->pgt);
	assert(idx < TBL_NUM_ENTRIES);
	core_mmu_set_entry_primitive(area->pgt->tbl, TBL_LEVEL, idx, pa, attr);
}

static size_t area_va2idx(struct tee_pager_area *area, vaddr_t va)
{
	return (va - (area->base & ~CORE_MMU_PGDIR_MASK)) >> SMALL_PAGE_SHIFT;
}

static vaddr_t area_idx2va(struct tee_pager_area *area, size_t idx)
{
	return (idx << SMALL_PAGE_SHIFT) + (area->base & ~CORE_MMU_PGDIR_MASK);
}

static void area_tlbi_entry(struct tee_pager_area *area, size_t idx)
{
	vaddr_t va = area_idx2va(area, idx);

#if defined(CFG_PAGED_USER_TA)
	assert(area->pgt);
	if (area->pgt->ctx) {
		uint32_t asid = to_user_mode_ctx(area->pgt->ctx)->vm_info.asid;

		tlbi_mva_asid(va, asid);
		return;
	}
#endif
	tlbi_mva_allasid(va);
}

static void pmem_unmap(struct tee_pager_pmem *pmem, struct pgt *only_this_pgt)
{
	struct tee_pager_area *area = NULL;
	size_t tblidx = 0;
	uint32_t a = 0;

	TAILQ_FOREACH(area, &pmem->fobj->areas, fobj_link) {
		/*
		 * If only_this_pgt points to a pgt then the pgt of this
		 * area has to match or we'll skip over it.
		 */
		if (only_this_pgt && area->pgt != only_this_pgt)
			continue;
		if (!area->pgt || !pmem_is_covered_by_area(pmem, area))
			continue;
		tblidx = pmem_get_area_tblidx(pmem, area);
		area_get_entry(area, tblidx, NULL, &a);
		if (a & TEE_MATTR_VALID_BLOCK) {
			area_set_entry(area, tblidx, 0, 0);
			pgt_dec_used_entries(area->pgt);
			area_tlbi_entry(area, tblidx);
		}
	}
}

void tee_pager_early_init(void)
{
	size_t n;

	/*
	 * Note that this depends on add_pager_vaspace() adding vaspace
	 * after end of memory.
	 */
	for (n = 0; n < ARRAY_SIZE(pager_tables); n++) {
		if (!core_mmu_find_table(NULL, TEE_RAM_VA_START +
					 n * CORE_MMU_PGDIR_SIZE, UINT_MAX,
					 &pager_tables[n].tbl_info))
			panic("can't find mmu tables");

		if (pager_tables[n].tbl_info.shift != TBL_SHIFT)
			panic("Unsupported page size in translation table");
		assert(pager_tables[n].tbl_info.num_entries == TBL_NUM_ENTRIES);
		assert(pager_tables[n].tbl_info.level == TBL_LEVEL);

		pager_tables[n].pgt.tbl = pager_tables[n].tbl_info.table;
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

static void area_insert(struct tee_pager_area_head *head,
			struct tee_pager_area *area,
			struct tee_pager_area *a_prev)
{
	uint32_t exceptions = pager_lock_check_stack(8);

	if (a_prev)
		TAILQ_INSERT_AFTER(head, a_prev, area, link);
	else
		TAILQ_INSERT_HEAD(head, area, link);
	TAILQ_INSERT_TAIL(&area->fobj->areas, area, fobj_link);

	pager_unlock(exceptions);
}
KEEP_PAGER(area_insert);

void tee_pager_add_core_area(vaddr_t base, enum tee_pager_area_type type,
			     struct fobj *fobj)
{
	struct tee_pager_area *area = NULL;
	uint32_t flags = 0;
	size_t fobj_pgoffs = 0;
	vaddr_t b = base;
	size_t s = fobj->num_pages * SMALL_PAGE_SIZE;
	size_t s2 = 0;

	DMSG("0x%" PRIxPTR " - 0x%" PRIxPTR " : type %d", base, base + s, type);

	if (base & SMALL_PAGE_MASK || !s) {
		EMSG("invalid pager area [%" PRIxVA " +0x%zx]", base, s);
		panic();
	}

	switch (type) {
	case PAGER_AREA_TYPE_RO:
		flags = TEE_MATTR_PRX;
		break;
	case PAGER_AREA_TYPE_RW:
	case PAGER_AREA_TYPE_LOCK:
		flags = TEE_MATTR_PRW;
		break;
	default:
		panic();
	}

	if (!fobj)
		panic();

	while (s) {
		s2 = MIN(CORE_MMU_PGDIR_SIZE - (b & CORE_MMU_PGDIR_MASK), s);
		area = calloc(1, sizeof(*area));
		if (!area)
			panic("alloc_area");

		area->fobj = fobj_get(fobj);
		area->fobj_pgoffs = fobj_pgoffs;
		area->type = type;
		area->pgt = find_core_pgt(b);
		area->base = b;
		area->size = s2;
		area->flags = flags;
		area_insert(&tee_pager_area_head, area, NULL);

		b += s2;
		s -= s2;
		fobj_pgoffs += s2 / SMALL_PAGE_SIZE;
	}
}

static struct tee_pager_area *find_area(struct tee_pager_area_head *areas,
					vaddr_t va)
{
	struct tee_pager_area *area;

	if (!areas)
		return NULL;

	TAILQ_FOREACH(area, areas, link) {
		if (core_is_buffer_inside(va, 1, area->base, area->size))
			return area;
	}
	return NULL;
}

#ifdef CFG_PAGED_USER_TA
static struct tee_pager_area *find_uta_area(vaddr_t va)
{
	struct tee_ta_ctx *ctx = thread_get_tsd()->ctx;

	if (!is_user_mode_ctx(ctx))
		return NULL;
	return find_area(to_user_mode_ctx(ctx)->areas, va);
}
#else
static struct tee_pager_area *find_uta_area(vaddr_t va __unused)
{
	return NULL;
}
#endif /*CFG_PAGED_USER_TA*/


static uint32_t get_area_mattr(uint32_t area_flags)
{
	uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_SECURE |
			TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT |
			(area_flags & (TEE_MATTR_PRWX | TEE_MATTR_URWX));

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

static void tee_pager_load_page(struct tee_pager_area *area, vaddr_t page_va,
			void *va_alias)
{
	size_t fobj_pgoffs = ((page_va - area->base) >> SMALL_PAGE_SHIFT) +
			     area->fobj_pgoffs;
	struct core_mmu_table_info *ti;
	uint32_t attr_alias;
	paddr_t pa_alias;
	unsigned int idx_alias;

	/* Insure we are allowed to write to aliased virtual page */
	ti = find_table_info((vaddr_t)va_alias);
	idx_alias = core_mmu_va2idx(ti, (vaddr_t)va_alias);
	core_mmu_get_entry(ti, idx_alias, &pa_alias, &attr_alias);
	if (!(attr_alias & TEE_MATTR_PW)) {
		attr_alias |= TEE_MATTR_PW;
		core_mmu_set_entry(ti, idx_alias, pa_alias, attr_alias);
		tlbi_mva_allasid((vaddr_t)va_alias);
	}

	asan_tag_access(va_alias, (uint8_t *)va_alias + SMALL_PAGE_SIZE);
	if (fobj_load_page(area->fobj, fobj_pgoffs, va_alias)) {
		EMSG("PH 0x%" PRIxVA " failed", page_va);
		panic();
	}
	switch (area->type) {
	case PAGER_AREA_TYPE_RO:
		incr_ro_hits();
		/* Forbid write to aliases for read-only (maybe exec) pages */
		attr_alias &= ~TEE_MATTR_PW;
		core_mmu_set_entry(ti, idx_alias, pa_alias, attr_alias);
		tlbi_mva_allasid((vaddr_t)va_alias);
		break;
	case PAGER_AREA_TYPE_RW:
		incr_rw_hits();
		break;
	case PAGER_AREA_TYPE_LOCK:
		break;
	default:
		panic();
	}
	asan_tag_no_access(va_alias, (uint8_t *)va_alias + SMALL_PAGE_SIZE);
}

static void tee_pager_save_page(struct tee_pager_pmem *pmem)
{
	if (pmem_is_dirty(pmem)) {
		asan_tag_access(pmem->va_alias,
				(uint8_t *)pmem->va_alias + SMALL_PAGE_SIZE);
		if (fobj_save_page(pmem->fobj, pmem->fobj_pgidx,
				   pmem->va_alias))
			panic("fobj_save_page");
		asan_tag_no_access(pmem->va_alias,
				   (uint8_t *)pmem->va_alias + SMALL_PAGE_SIZE);
	}
}

#ifdef CFG_PAGED_USER_TA
static void unlink_area(struct tee_pager_area_head *area_head,
			struct tee_pager_area *area)
{
	uint32_t exceptions = pager_lock_check_stack(64);

	TAILQ_REMOVE(area_head, area, link);
	TAILQ_REMOVE(&area->fobj->areas, area, fobj_link);

	pager_unlock(exceptions);
}
KEEP_PAGER(unlink_area);

static void free_area(struct tee_pager_area *area)
{
	fobj_put(area->fobj);
	free(area);
}

static TEE_Result pager_add_um_area(struct user_mode_ctx *uctx, vaddr_t base,
				    struct fobj *fobj, uint32_t prot)
{
	struct tee_pager_area *a_prev = NULL;
	struct tee_pager_area *area = NULL;
	vaddr_t b = base;
	size_t fobj_pgoffs = 0;
	size_t s = fobj->num_pages * SMALL_PAGE_SIZE;

	if (!uctx->areas) {
		uctx->areas = malloc(sizeof(*uctx->areas));
		if (!uctx->areas)
			return TEE_ERROR_OUT_OF_MEMORY;
		TAILQ_INIT(uctx->areas);
	}

	area = TAILQ_FIRST(uctx->areas);
	while (area) {
		if (core_is_buffer_intersect(b, s, area->base,
					     area->size))
			return TEE_ERROR_BAD_PARAMETERS;
		if (b < area->base)
			break;
		a_prev = area;
		area = TAILQ_NEXT(area, link);
	}

	while (s) {
		size_t s2;

		s2 = MIN(CORE_MMU_PGDIR_SIZE - (b & CORE_MMU_PGDIR_MASK), s);
		area = calloc(1, sizeof(*area));
		if (!area)
			return TEE_ERROR_OUT_OF_MEMORY;

		/* Table info will be set when the context is activated. */
		area->fobj = fobj_get(fobj);
		area->fobj_pgoffs = fobj_pgoffs;
		area->type = PAGER_AREA_TYPE_RW;
		area->base = b;
		area->size = s2;
		area->flags = prot;

		area_insert(uctx->areas, area, a_prev);

		a_prev = area;
		b += s2;
		s -= s2;
		fobj_pgoffs += s2 / SMALL_PAGE_SIZE;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_pager_add_um_area(struct user_mode_ctx *uctx, vaddr_t base,
				 struct fobj *fobj, uint32_t prot)
{
	TEE_Result res = TEE_SUCCESS;
	struct thread_specific_data *tsd = thread_get_tsd();
	struct tee_pager_area *area = NULL;
	struct core_mmu_table_info dir_info = { NULL };

	if (&uctx->ctx != tsd->ctx) {
		/*
		 * Changes are to an utc that isn't active. Just add the
		 * areas page tables will be dealt with later.
		 */
		return pager_add_um_area(uctx, base, fobj, prot);
	}

	/*
	 * Assign page tables before adding areas to be able to tell which
	 * are newly added and should be removed in case of failure.
	 */
	tee_pager_assign_um_tables(uctx);
	res = pager_add_um_area(uctx, base, fobj, prot);
	if (res) {
		struct tee_pager_area *next_a;

		/* Remove all added areas */
		TAILQ_FOREACH_SAFE(area, uctx->areas, link, next_a) {
			if (!area->pgt) {
				unlink_area(uctx->areas, area);
				free_area(area);
			}
		}
		return res;
	}

	/*
	 * Assign page tables to the new areas and make sure that the page
	 * tables are registered in the upper table.
	 */
	tee_pager_assign_um_tables(uctx);
	core_mmu_get_user_pgdir(&dir_info);
	TAILQ_FOREACH(area, uctx->areas, link) {
		paddr_t pa;
		size_t idx;
		uint32_t attr;

		idx = core_mmu_va2idx(&dir_info, area->pgt->vabase);
		core_mmu_get_entry(&dir_info, idx, &pa, &attr);

		/*
		 * Check if the page table already is used, if it is, it's
		 * already registered.
		 */
		if (area->pgt->num_used_entries) {
			assert(attr & TEE_MATTR_TABLE);
			assert(pa == virt_to_phys(area->pgt->tbl));
			continue;
		}

		attr = TEE_MATTR_SECURE | TEE_MATTR_TABLE;
		pa = virt_to_phys(area->pgt->tbl);
		assert(pa);
		/*
		 * Note that the update of the table entry is guaranteed to
		 * be atomic.
		 */
		core_mmu_set_entry(&dir_info, idx, pa, attr);
	}

	return TEE_SUCCESS;
}

static void split_area(struct tee_pager_area_head *area_head,
		       struct tee_pager_area *area, struct tee_pager_area *a2,
		       vaddr_t va)
{
	uint32_t exceptions = pager_lock_check_stack(64);
	size_t diff = va - area->base;

	a2->fobj = fobj_get(area->fobj);
	a2->fobj_pgoffs = area->fobj_pgoffs + diff / SMALL_PAGE_SIZE;
	a2->type = area->type;
	a2->flags = area->flags;
	a2->base = va;
	a2->size = area->size - diff;
	a2->pgt = area->pgt;
	area->size = diff;

	TAILQ_INSERT_AFTER(area_head, area, a2, link);
	TAILQ_INSERT_AFTER(&area->fobj->areas, area, a2, fobj_link);

	pager_unlock(exceptions);
}
KEEP_PAGER(split_area);

TEE_Result tee_pager_split_um_region(struct user_mode_ctx *uctx, vaddr_t va)
{
	struct tee_pager_area *area = NULL;
	struct tee_pager_area *a2 = NULL;

	if (va & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	TAILQ_FOREACH(area, uctx->areas, link) {
		if (va == area->base || va == area->base + area->size)
			return TEE_SUCCESS;
		if (va > area->base && va < area->base + area->size) {
			a2 = calloc(1, sizeof(*a2));
			if (!a2)
				return TEE_ERROR_OUT_OF_MEMORY;
			split_area(uctx->areas, area, a2, va);
			return TEE_SUCCESS;
		}
	}

	return TEE_SUCCESS;
}

static void merge_area_with_next(struct tee_pager_area_head *area_head,
				 struct tee_pager_area *a,
				 struct tee_pager_area *a_next)
{
	uint32_t exceptions = pager_lock_check_stack(64);

	TAILQ_REMOVE(area_head, a_next, link);
	TAILQ_REMOVE(&a_next->fobj->areas, a_next, fobj_link);
	a->size += a_next->size;

	pager_unlock(exceptions);
}
KEEP_PAGER(merge_area_with_next);

void tee_pager_merge_um_region(struct user_mode_ctx *uctx, vaddr_t va,
			       size_t len)
{
	struct tee_pager_area *a_next = NULL;
	struct tee_pager_area *a = NULL;

	if ((va | len) & SMALL_PAGE_MASK)
		return;

	for (a = TAILQ_FIRST(uctx->areas);; a = a_next) {
		a_next = TAILQ_NEXT(a, link);
		if (!a_next)
			return;

		/* Try merging with the area just before va */
		if (a->base + a->size < va)
			continue;

		/*
		 * If a->base is well past our range we're done.
		 * Note that if it's just the page after our range we'll
		 * try to merge.
		 */
		if (a->base > va + len)
			return;

		if (a->base + a->size != a_next->base)
			continue;
		if (a->fobj != a_next->fobj || a->type != a_next->type ||
		    a->flags != a_next->flags || a->pgt != a_next->pgt)
			continue;
		if (a->fobj_pgoffs + a->size / SMALL_PAGE_SIZE !=
		    a_next->fobj_pgoffs)
			continue;

		merge_area_with_next(uctx->areas, a, a_next);
		free_area(a_next);
		a_next = a;
	}
}

static void rem_area(struct tee_pager_area_head *area_head,
		     struct tee_pager_area *area)
{
	struct tee_pager_pmem *pmem;
	size_t last_pgoffs = area->fobj_pgoffs +
			     (area->size >> SMALL_PAGE_SHIFT) - 1;
	uint32_t exceptions;
	size_t idx = 0;
	uint32_t a = 0;

	exceptions = pager_lock_check_stack(64);

	TAILQ_REMOVE(area_head, area, link);
	TAILQ_REMOVE(&area->fobj->areas, area, fobj_link);

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (pmem->fobj != area->fobj ||
		    pmem->fobj_pgidx < area->fobj_pgoffs ||
		    pmem->fobj_pgidx > last_pgoffs)
			continue;

		idx = pmem_get_area_tblidx(pmem, area);
		area_get_entry(area, idx, NULL, &a);
		if (!(a & TEE_MATTR_VALID_BLOCK))
			continue;

		area_set_entry(area, idx, 0, 0);
		area_tlbi_entry(area, idx);
		pgt_dec_used_entries(area->pgt);
	}

	pager_unlock(exceptions);

	free_area(area);
}
KEEP_PAGER(rem_area);

void tee_pager_rem_um_region(struct user_mode_ctx *uctx, vaddr_t base,
			     size_t size)
{
	struct tee_pager_area *area;
	struct tee_pager_area *next_a;
	size_t s = ROUNDUP(size, SMALL_PAGE_SIZE);

	TAILQ_FOREACH_SAFE(area, uctx->areas, link, next_a) {
		if (core_is_buffer_inside(area->base, area->size, base, s))
			rem_area(uctx->areas, area);
	}
	tlbi_asid(uctx->vm_info.asid);
}

void tee_pager_rem_um_areas(struct user_mode_ctx *uctx)
{
	struct tee_pager_area *area = NULL;

	if (!uctx->areas)
		return;

	while (true) {
		area = TAILQ_FIRST(uctx->areas);
		if (!area)
			break;
		unlink_area(uctx->areas, area);
		free_area(area);
	}

	free(uctx->areas);
}

static bool __maybe_unused same_context(struct tee_pager_pmem *pmem)
{
	struct tee_pager_area *a = TAILQ_FIRST(&pmem->fobj->areas);
	void *ctx = a->pgt->ctx;

	do {
		a = TAILQ_NEXT(a, fobj_link);
		if (!a)
			return true;
	} while (a->pgt->ctx == ctx);

	return false;
}

bool tee_pager_set_um_area_attr(struct user_mode_ctx *uctx, vaddr_t base,
				size_t size, uint32_t flags)
{
	bool ret = false;
	vaddr_t b = base;
	size_t s = size;
	size_t s2 = 0;
	struct tee_pager_area *area = find_area(uctx->areas, b);
	uint32_t exceptions = 0;
	struct tee_pager_pmem *pmem = NULL;
	uint32_t a = 0;
	uint32_t f = 0;
	uint32_t mattr = 0;
	uint32_t f2 = 0;
	size_t tblidx = 0;

	f = (flags & TEE_MATTR_URWX) | TEE_MATTR_UR | TEE_MATTR_PR;
	if (f & TEE_MATTR_UW)
		f |= TEE_MATTR_PW;
	mattr = get_area_mattr(f);

	exceptions = pager_lock_check_stack(SMALL_PAGE_SIZE);

	while (s) {
		s2 = MIN(CORE_MMU_PGDIR_SIZE - (b & CORE_MMU_PGDIR_MASK), s);
		if (!area || area->base != b || area->size != s2) {
			ret = false;
			goto out;
		}
		b += s2;
		s -= s2;

		if (area->flags == f)
			goto next_area;

		TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
			if (!pmem_is_covered_by_area(pmem, area))
				continue;

			tblidx = pmem_get_area_tblidx(pmem, area);
			area_get_entry(area, tblidx, NULL, &a);
			if (a == f)
				continue;
			area_set_entry(area, tblidx, 0, 0);
			area_tlbi_entry(area, tblidx);

			pmem->flags &= ~PMEM_FLAG_HIDDEN;
			if (pmem_is_dirty(pmem))
				f2 = mattr;
			else
				f2 = mattr & ~(TEE_MATTR_UW | TEE_MATTR_PW);
			area_set_entry(area, tblidx, get_pmem_pa(pmem), f2);
			if (!(a & TEE_MATTR_VALID_BLOCK))
				pgt_inc_used_entries(area->pgt);
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
				void *va = (void *)area_idx2va(area, tblidx);

				/* Assert that the pmem isn't shared. */
				assert(same_context(pmem));

				dcache_clean_range_pou(va, SMALL_PAGE_SIZE);
				icache_inv_user_range(va, SMALL_PAGE_SIZE);
			}
		}

		area->flags = f;
next_area:
		area = TAILQ_NEXT(area, link);
	}

	ret = true;
out:
	pager_unlock(exceptions);
	return ret;
}

KEEP_PAGER(tee_pager_set_um_area_attr);
#endif /*CFG_PAGED_USER_TA*/

void tee_pager_invalidate_fobj(struct fobj *fobj)
{
	struct tee_pager_pmem *pmem;
	uint32_t exceptions;

	exceptions = pager_lock_check_stack(64);

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (pmem->fobj == fobj) {
			pmem->fobj = NULL;
			pmem->fobj_pgidx = INVALID_PGIDX;
		}
	}

	pager_unlock(exceptions);
}
KEEP_PAGER(tee_pager_invalidate_fobj);

static struct tee_pager_pmem *pmem_find(struct tee_pager_area *area,
					unsigned int tblidx)
{
	struct tee_pager_pmem *pmem = NULL;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link)
		if (pmem->fobj == area->fobj &&
		    pmem_get_area_tblidx(pmem, area) == tblidx)
			return pmem;

	return NULL;
}

static bool tee_pager_unhide_page(struct tee_pager_area *area,
				  unsigned int tblidx)
{
	struct tee_pager_pmem *pmem = pmem_find(area, tblidx);
	uint32_t a = get_area_mattr(area->flags);
	uint32_t attr = 0;
	paddr_t pa = 0;

	if (!pmem)
		return false;

	area_get_entry(area, tblidx, NULL, &attr);
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
	if (area->flags & TEE_MATTR_UX) {
		void *va = (void *)area_idx2va(area, tblidx);

		/* Set a temporary read-only mapping */
		assert(!(a & (TEE_MATTR_UW | TEE_MATTR_PW)));
		area_set_entry(area, tblidx, pa, a & ~TEE_MATTR_UX);
		dsb_ishst();

		icache_inv_user_range(va, SMALL_PAGE_SIZE);

		/* Set the final mapping */
		area_set_entry(area, tblidx, pa, a);
		area_tlbi_entry(area, tblidx);
	} else {
		area_set_entry(area, tblidx, pa, a);
		dsb_ishst();
	}
	pgt_inc_used_entries(area->pgt);

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

/*
 * Find mapped pmem, hide and move to pageble pmem.
 * Return false if page was not mapped, and true if page was mapped.
 */
static bool tee_pager_release_one_phys(struct tee_pager_area *area,
				       vaddr_t page_va)
{
	struct tee_pager_pmem *pmem;
	size_t tblidx = 0;
	size_t pgidx = area_va2idx(area, page_va) + area->fobj_pgoffs -
		       ((area->base & CORE_MMU_PGDIR_MASK) >> SMALL_PAGE_SHIFT);

	TAILQ_FOREACH(pmem, &tee_pager_lock_pmem_head, link) {
		if (pmem->fobj != area->fobj || pmem->fobj_pgidx != pgidx)
			continue;

		/*
		 * Locked pages may not be shared, these two asserts checks
		 * that there's only a signed area recorded with this pmem.
		 */
		assert(TAILQ_FIRST(&pmem->fobj->areas) == area);
		assert(TAILQ_LAST(&pmem->fobj->areas,
				  tee_pager_area_head) == area);

		tblidx = pmem_get_area_tblidx(pmem, area);
		area_set_entry(area, tblidx, 0, 0);
		pgt_dec_used_entries(area->pgt);
		TAILQ_REMOVE(&tee_pager_lock_pmem_head, pmem, link);
		pmem->fobj = NULL;
		pmem->fobj_pgidx = INVALID_PGIDX;
		tee_pager_npages++;
		set_npages();
		TAILQ_INSERT_HEAD(&tee_pager_pmem_head, pmem, link);
		incr_zi_released();
		return true;
	}

	return false;
}

/* Finds the oldest page and unmaps it from all tables */
static struct tee_pager_pmem *tee_pager_get_page(enum tee_pager_area_type at)
{
	struct tee_pager_pmem *pmem;

	pmem = TAILQ_FIRST(&tee_pager_pmem_head);
	if (!pmem) {
		EMSG("No pmem entries");
		return NULL;
	}

	if (pmem->fobj) {
		pmem_unmap(pmem, NULL);
		tee_pager_save_page(pmem);
	}

	TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
	pmem->fobj = NULL;
	pmem->fobj_pgidx = INVALID_PGIDX;
	pmem->flags = 0;
	if (at == PAGER_AREA_TYPE_LOCK) {
		/* Move page to lock list */
		if (tee_pager_npages <= 0)
			panic("running out of page");
		tee_pager_npages--;
		set_npages();
		TAILQ_INSERT_TAIL(&tee_pager_lock_pmem_head, pmem, link);
	} else {
		/* move page to back */
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	}

	return pmem;
}

static bool pager_update_permissions(struct tee_pager_area *area,
			struct abort_info *ai, bool *handled)
{
	unsigned int pgidx = area_va2idx(area, ai->va);
	struct tee_pager_pmem *pmem = NULL;
	uint32_t attr = 0;
	paddr_t pa = 0;

	*handled = false;

	area_get_entry(area, pgidx, &pa, &attr);

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
		pmem = pmem_find(area, pgidx);
		if (!pmem)
			panic();
		if (abort_is_user_exception(ai)) {
			if (!(area->flags & TEE_MATTR_UW))
				return true;
			if (!(attr & TEE_MATTR_UW)) {
				FMSG("Dirty %p",
				     (void *)(ai->va & ~SMALL_PAGE_MASK));
				pmem->flags |= PMEM_FLAG_DIRTY;
				area_set_entry(area, pgidx, pa,
					       get_area_mattr(area->flags));
				area_tlbi_entry(area, pgidx);
			}

		} else {
			if (!(area->flags & TEE_MATTR_PW)) {
				abort_print_error(ai);
				panic();
			}
			if (!(attr & TEE_MATTR_PW)) {
				FMSG("Dirty %p",
				     (void *)(ai->va & ~SMALL_PAGE_MASK));
				pmem->flags |= PMEM_FLAG_DIRTY;
				area_set_entry(area, pgidx, pa,
					       get_area_mattr(area->flags));
				tlbi_mva_allasid(ai->va & ~SMALL_PAGE_MASK);
			}
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
	struct tee_pager_area *area;
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
		area = find_uta_area(ai->va);
		clean_user_cache = true;
	} else {
		area = find_area(&tee_pager_area_head, ai->va);
		if (!area) {
			area = find_uta_area(ai->va);
			clean_user_cache = true;
		}
	}
	if (!area || !area->pgt) {
		ret = false;
		goto out;
	}

	if (!tee_pager_unhide_page(area, area_va2idx(area, page_va))) {
		struct tee_pager_pmem *pmem = NULL;
		uint32_t attr = 0;
		paddr_t pa = 0;
		size_t tblidx = 0;

		/*
		 * The page wasn't hidden, but some other core may have
		 * updated the table entry before we got here or we need
		 * to make a read-only page read-write (dirty).
		 */
		if (pager_update_permissions(area, ai, &ret)) {
			/*
			 * Nothing more to do with the abort. The problem
			 * could already have been dealt with from another
			 * core or if ret is false the TA will be paniced.
			 */
			goto out;
		}

		pmem = tee_pager_get_page(area->type);
		if (!pmem) {
			abort_print(ai);
			panic();
		}

		/* load page code & data */
		tee_pager_load_page(area, page_va, pmem->va_alias);


		pmem->fobj = area->fobj;
		pmem->fobj_pgidx = area_va2idx(area, page_va) +
				   area->fobj_pgoffs -
				   ((area->base & CORE_MMU_PGDIR_MASK) >>
					SMALL_PAGE_SHIFT);
		tblidx = pmem_get_area_tblidx(pmem, area);
		attr = get_area_mattr(area->flags);
		/*
		 * Pages from PAGER_AREA_TYPE_RW starts read-only to be
		 * able to tell when they are updated and should be tagged
		 * as dirty.
		 */
		if (area->type == PAGER_AREA_TYPE_RW)
			attr &= ~(TEE_MATTR_PW | TEE_MATTR_UW);
		pa = get_pmem_pa(pmem);

		/*
		 * We've updated the page using the aliased mapping and
		 * some cache maintenence is now needed if it's an
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
		if (area->flags & (TEE_MATTR_PX | TEE_MATTR_UX)) {
			uint32_t mask = TEE_MATTR_PX | TEE_MATTR_UX |
					TEE_MATTR_PW | TEE_MATTR_UW;
			void *va = (void *)page_va;

			/* Set a temporary read-only mapping */
			area_set_entry(area, tblidx, pa, attr & ~mask);
			area_tlbi_entry(area, tblidx);

			dcache_clean_range_pou(va, SMALL_PAGE_SIZE);
			if (clean_user_cache)
				icache_inv_user_range(va, SMALL_PAGE_SIZE);
			else
				icache_inv_range(va, SMALL_PAGE_SIZE);

			/* Set the final mapping */
			area_set_entry(area, tblidx, pa, attr);
			area_tlbi_entry(area, tblidx);
		} else {
			area_set_entry(area, tblidx, pa, attr);
			/*
			 * No need to flush TLB for this entry, it was
			 * invalid. We should use a barrier though, to make
			 * sure that the change is visible.
			 */
			dsb_ishst();
		}
		pgt_inc_used_entries(area->pgt);

		FMSG("Mapped 0x%" PRIxVA " -> 0x%" PRIxPA, page_va, pa);

	}

	tee_pager_hide_pages();
	ret = true;
out:
	pager_unlock(exceptions);
	return ret;
}

void tee_pager_add_pages(vaddr_t vaddr, size_t npages, bool unmap)
{
	size_t n;

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA " : %d",
	     vaddr, vaddr + npages * SMALL_PAGE_SIZE, (int)unmap);

	/* setup memory */
	for (n = 0; n < npages; n++) {
		struct core_mmu_table_info *ti;
		struct tee_pager_pmem *pmem;
		vaddr_t va = vaddr + n * SMALL_PAGE_SIZE;
		unsigned int pgidx;
		paddr_t pa;
		uint32_t attr;

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

		pmem->va_alias = pager_add_alias_page(pa);

		if (unmap) {
			pmem->fobj = NULL;
			pmem->fobj_pgidx = INVALID_PGIDX;
			core_mmu_set_entry(ti, pgidx, 0, 0);
			pgt_dec_used_entries(find_core_pgt(va));
		} else {
			struct tee_pager_area *area = NULL;

			/*
			 * The page is still mapped, let's assign the area
			 * and update the protection bits accordingly.
			 */
			area = find_area(&tee_pager_area_head, va);
			assert(area && area->pgt == find_core_pgt(va));
			pmem->fobj = area->fobj;
			pmem->fobj_pgidx = pgidx + area->fobj_pgoffs -
					   ((area->base &
							CORE_MMU_PGDIR_MASK) >>
						SMALL_PAGE_SHIFT);
			assert(pgidx == pmem_get_area_tblidx(pmem, area));
			assert(pa == get_pmem_pa(pmem));
			area_set_entry(area, pgidx, pa,
				       get_area_mattr(area->flags));
		}

		tee_pager_npages++;
		incr_npages_all();
		set_npages();
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
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
	struct tee_pager_area *area = NULL;
	struct pgt *pgt = NULL;

	if (!uctx->areas)
		return;

	pgt = SLIST_FIRST(&thread_get_tsd()->pgt_cache);
	TAILQ_FOREACH(area, uctx->areas, link) {
		if (!area->pgt)
			area->pgt = find_pgt(pgt, area->base);
		else
			assert(area->pgt == find_pgt(pgt, area->base));
		if (!area->pgt)
			panic();
	}
}

void tee_pager_pgt_save_and_release_entries(struct pgt *pgt)
{
	struct tee_pager_pmem *pmem = NULL;
	struct tee_pager_area *area = NULL;
	struct tee_pager_area_head *areas = NULL;
	uint32_t exceptions = pager_lock_check_stack(SMALL_PAGE_SIZE);

	if (!pgt->num_used_entries)
		goto out;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (pmem->fobj)
			pmem_unmap(pmem, pgt);
	}
	assert(!pgt->num_used_entries);

out:
	areas = to_user_ta_ctx(pgt->ctx)->uctx.areas;
	if (areas) {
		TAILQ_FOREACH(area, areas, link) {
			if (area->pgt == pgt)
				area->pgt = NULL;
		}
	}

	pager_unlock(exceptions);
}
KEEP_PAGER(tee_pager_pgt_save_and_release_entries);
#endif /*CFG_PAGED_USER_TA*/

void tee_pager_release_phys(void *addr, size_t size)
{
	bool unmaped = false;
	vaddr_t va = (vaddr_t)addr;
	vaddr_t begin = ROUNDUP(va, SMALL_PAGE_SIZE);
	vaddr_t end = ROUNDDOWN(va + size, SMALL_PAGE_SIZE);
	struct tee_pager_area *area;
	uint32_t exceptions;

	if (end <= begin)
		return;

	exceptions = pager_lock_check_stack(128);

	for (va = begin; va < end; va += SMALL_PAGE_SIZE) {
		area = find_area(&tee_pager_area_head, va);
		if (!area)
			panic();
		unmaped |= tee_pager_release_one_phys(area, va);
	}

	if (unmaped)
		tlbi_mva_range(begin, end - begin, SMALL_PAGE_SIZE);

	pager_unlock(exceptions);
}
KEEP_PAGER(tee_pager_release_phys);

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

	tee_pager_add_core_area((vaddr_t)smem, PAGER_AREA_TYPE_LOCK, fobj);
	fobj_put(fobj);

	asan_tag_access(smem, smem + num_pages * SMALL_PAGE_SIZE);

	return smem;
}
