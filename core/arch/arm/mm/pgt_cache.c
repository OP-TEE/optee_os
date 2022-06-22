// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <assert.h>
#include <kernel/mutex.h>
#include <kernel/tee_misc.h>
#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>
#include <mm/tee_pager.h>
#include <stdlib.h>
#include <trace.h>
#include <util.h>

/*
 * With pager enabled we allocate page table from the pager.
 *
 * For LPAE each page table is a complete page which is allocated and freed
 * using the interface provided by the pager.
 *
 * For compat v7 page tables there's room for four page table in one page
 * so we need to keep track of how much of an allocated page is used. When
 * a page is completely unused it's returned to the pager.
 *
 * With pager disabled we have a static allocation of page tables instead.
 *
 * In all cases we limit the number of active page tables to
 * PGT_CACHE_SIZE.  This pool of page tables are shared between all
 * threads. In case a thread can't allocate the needed number of pager
 * tables it will release all its current tables and wait for some more to
 * be freed. A threads allocated tables are freed each time a TA is
 * unmapped so each thread should be able to allocate the needed tables in
 * turn if needed.
 */

#if defined(CFG_WITH_PAGER) && !defined(CFG_WITH_LPAE)
struct pgt_parent {
	size_t num_used;
	struct pgt_cache pgt_cache;
};

static struct pgt_parent pgt_parents[PGT_CACHE_SIZE / PGT_NUM_PGT_PER_PAGE];
#else

static struct pgt_cache pgt_free_list = SLIST_HEAD_INITIALIZER(pgt_free_list);
#endif

/*
 * When a user TA context is temporarily unmapped the used struct pgt's of
 * the context (page tables holding valid physical pages) are saved in this
 * cache in the hope that it will remain in the cache when the context is
 * mapped again.
 */
static struct pgt_cache pgt_cache_list = SLIST_HEAD_INITIALIZER(pgt_cache_list);

static struct pgt pgt_entries[PGT_CACHE_SIZE];

static struct mutex pgt_mu = MUTEX_INITIALIZER;
static struct condvar pgt_cv = CONDVAR_INITIALIZER;

#if defined(CFG_WITH_PAGER) && defined(CFG_WITH_LPAE)
/*
 * Simple allocation of translation tables from pager, one translation
 * table is one page.
 */
void pgt_init(void)
{
	size_t n;

	for (n = 0; n < PGT_CACHE_SIZE; n++) {
		struct pgt *p = pgt_entries + n;

		p->tbl = tee_pager_alloc(PGT_SIZE);
		SLIST_INSERT_HEAD(&pgt_free_list, p, link);
	}
}
#elif defined(CFG_WITH_PAGER) && !defined(CFG_WITH_LPAE)
/*
 * Four translation tables per page -> need to keep track of the page
 * allocated from the pager.
 */
void pgt_init(void)
{
	size_t n;
	size_t m;

	COMPILE_TIME_ASSERT(PGT_CACHE_SIZE % PGT_NUM_PGT_PER_PAGE == 0);
	COMPILE_TIME_ASSERT(PGT_SIZE * PGT_NUM_PGT_PER_PAGE == SMALL_PAGE_SIZE);

	for (n = 0; n < ARRAY_SIZE(pgt_parents); n++) {
		uint8_t *tbl = tee_pager_alloc(SMALL_PAGE_SIZE);

		SLIST_INIT(&pgt_parents[n].pgt_cache);
		for (m = 0; m < PGT_NUM_PGT_PER_PAGE; m++) {
			struct pgt *p = pgt_entries +
					n * PGT_NUM_PGT_PER_PAGE + m;

			p->tbl = tbl + m * PGT_SIZE;
			p->parent = &pgt_parents[n];
			SLIST_INSERT_HEAD(&pgt_parents[n].pgt_cache, p, link);
		}
	}
}
#else
/* Static allocation of translation tables */
void pgt_init(void)
{
	/*
	 * We're putting this in .nozi.* instead of .bss because .nozi.* already
	 * has a large alignment, while .bss has a small alignment. The current
	 * link script is optimized for small alignment in .bss
	 */
	static uint8_t pgt_tables[PGT_CACHE_SIZE][PGT_SIZE]
			__aligned(PGT_SIZE) __section(".nozi.pgt_cache");
	size_t n;

	for (n = 0; n < ARRAY_SIZE(pgt_tables); n++) {
		struct pgt *p = pgt_entries + n;

		p->tbl = pgt_tables[n];
		SLIST_INSERT_HEAD(&pgt_free_list, p, link);
	}
}
#endif

#if defined(CFG_WITH_LPAE) || !defined(CFG_WITH_PAGER)
/* Simple allocation of translation tables from pager or static allocation */
static struct pgt *pop_from_free_list(void)
{
	struct pgt *p = SLIST_FIRST(&pgt_free_list);

	if (p) {
		SLIST_REMOVE_HEAD(&pgt_free_list, link);
		memset(p->tbl, 0, PGT_SIZE);
		p->populated = false;
	}
	return p;
}

static void push_to_free_list(struct pgt *p)
{
	SLIST_INSERT_HEAD(&pgt_free_list, p, link);
#if defined(CFG_WITH_PAGER)
	tee_pager_release_phys(p->tbl, PGT_SIZE);
#endif
}
#else
/*
 * Four translation tables per page -> need to keep track of the page
 * allocated from the pager.
 */
static struct pgt *pop_from_free_list(void)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(pgt_parents); n++) {
		struct pgt *p = SLIST_FIRST(&pgt_parents[n].pgt_cache);

		if (p) {
			SLIST_REMOVE_HEAD(&pgt_parents[n].pgt_cache, link);
			pgt_parents[n].num_used++;
			memset(p->tbl, 0, PGT_SIZE);
			p->populated = false;
			return p;
		}
	}
	return NULL;
}

static void push_to_free_list(struct pgt *p)
{
	SLIST_INSERT_HEAD(&p->parent->pgt_cache, p, link);
	assert(p->parent->num_used > 0);
	p->parent->num_used--;
	if (!p->parent->num_used) {
		vaddr_t va = (vaddr_t)p->tbl & ~SMALL_PAGE_MASK;

		tee_pager_release_phys((void *)va, SMALL_PAGE_SIZE);
	}
}
#endif

static void push_to_cache_list(struct pgt *pgt)
{
	SLIST_INSERT_HEAD(&pgt_cache_list, pgt, link);
}

static bool match_pgt(struct pgt *pgt, vaddr_t vabase, void *ctx)
{
	return pgt->ctx == ctx && pgt->vabase == vabase;
}

static struct pgt *pop_from_cache_list(vaddr_t vabase, void *ctx)
{
	struct pgt *pgt;
	struct pgt *p;

	pgt = SLIST_FIRST(&pgt_cache_list);
	if (!pgt)
		return NULL;
	if (match_pgt(pgt, vabase, ctx)) {
		SLIST_REMOVE_HEAD(&pgt_cache_list, link);
		return pgt;
	}

	while (true) {
		p = SLIST_NEXT(pgt, link);
		if (!p)
			break;
		if (match_pgt(p, vabase, ctx)) {
			SLIST_REMOVE_AFTER(pgt, link);
			break;
		}
		pgt = p;
	}
	return p;
}

static uint16_t get_num_used_entries(struct pgt *pgt __maybe_unused)
{
#ifdef CFG_PAGED_USER_TA
	return pgt->num_used_entries;
#else
	return 0;
#endif
}

static struct pgt *pop_least_used_from_cache_list(void)
{
	struct pgt *pgt = NULL;
	struct pgt *p_prev = NULL;
	size_t least_used = 0;
	size_t next_used = 0;

	pgt = SLIST_FIRST(&pgt_cache_list);
	if (!pgt)
		return NULL;
	least_used = get_num_used_entries(pgt);

	while (true) {
		if (!SLIST_NEXT(pgt, link))
			break;
		next_used = get_num_used_entries(SLIST_NEXT(pgt, link));
		if (next_used <= least_used) {
			p_prev = pgt;
			least_used = next_used;
		}
		pgt = SLIST_NEXT(pgt, link);
	}

	if (p_prev) {
		pgt = SLIST_NEXT(p_prev, link);
		SLIST_REMOVE_AFTER(p_prev, link);
	} else {
		pgt = SLIST_FIRST(&pgt_cache_list);
		SLIST_REMOVE_HEAD(&pgt_cache_list, link);
	}
	return pgt;
}

static void pgt_free_unlocked(struct pgt_cache *pgt_cache)
{
	while (!SLIST_EMPTY(pgt_cache)) {
		struct pgt *p = SLIST_FIRST(pgt_cache);

		SLIST_REMOVE_HEAD(pgt_cache, link);

		/*
		 * With paging enabled we free all tables which doesn't
		 * refer to any paged pages any longer. This reduces the
		 * pressure the pool of physical pages.
		 */
		if (IS_ENABLED(CFG_PAGED_USER_TA) && !get_num_used_entries(p)) {
			tee_pager_pgt_save_and_release_entries(p);
			p->ctx = NULL;
			p->vabase = 0;

			push_to_free_list(p);
			continue;
		}

		push_to_cache_list(p);
	}
}

static struct pgt *pop_from_some_list(vaddr_t vabase, void *ctx)
{
	struct pgt *p = pop_from_cache_list(vabase, ctx);

	if (p)
		return p;
	p = pop_from_free_list();
	if (!p) {
		p = pop_least_used_from_cache_list();
		if (!p)
			return NULL;
		tee_pager_pgt_save_and_release_entries(p);
		memset(p->tbl, 0, PGT_SIZE);
		p->populated = false;
	}
	p->ctx = ctx;
	p->vabase = vabase;
	return p;
}

void pgt_flush_ctx(struct ts_ctx *ctx)
{
	struct pgt *p;
	struct pgt *pp = NULL;

	mutex_lock(&pgt_mu);

	while (true) {
		p = SLIST_FIRST(&pgt_cache_list);
		if (!p)
			goto out;
		if (p->ctx != ctx)
			break;
		SLIST_REMOVE_HEAD(&pgt_cache_list, link);
		tee_pager_pgt_save_and_release_entries(p);
		p->ctx = NULL;
		p->vabase = 0;
		push_to_free_list(p);
	}

	pp = p;
	while (true) {
		p = SLIST_NEXT(pp, link);
		if (!p)
			break;
		if (p->ctx == ctx) {
			SLIST_REMOVE_AFTER(pp, link);
			tee_pager_pgt_save_and_release_entries(p);
			p->ctx = NULL;
			p->vabase = 0;
			push_to_free_list(p);
		} else {
			pp = p;
		}
	}

out:
	mutex_unlock(&pgt_mu);
}

static void flush_pgt_entry(struct pgt *p)
{
	tee_pager_pgt_save_and_release_entries(p);
	p->ctx = NULL;
	p->vabase = 0;
}

static bool pgt_entry_matches(struct pgt *p, void *ctx, vaddr_t begin,
			      vaddr_t last)
{
	if (!p)
		return false;
	if (p->ctx != ctx)
		return false;
	if (last <= begin)
		return false;
	if (!core_is_buffer_inside(p->vabase, SMALL_PAGE_SIZE, begin,
				   last - begin))
		return false;

	return true;
}

static void flush_ctx_range_from_list(struct pgt_cache *pgt_cache, void *ctx,
				      vaddr_t begin, vaddr_t last)
{
	struct pgt *p;
	struct pgt *next_p;

	/*
	 * Do the special case where the first element in the list is
	 * removed first.
	 */
	p = SLIST_FIRST(pgt_cache);
	while (pgt_entry_matches(p, ctx, begin, last)) {
		flush_pgt_entry(p);
		SLIST_REMOVE_HEAD(pgt_cache, link);
		push_to_free_list(p);
		p = SLIST_FIRST(pgt_cache);
	}

	/*
	 * p either points to the first element in the list or it's NULL,
	 * if NULL the list is empty and we're done.
	 */
	if (!p)
		return;

	/*
	 * Do the common case where the next element in the list is
	 * removed.
	 */
	while (true) {
		next_p = SLIST_NEXT(p, link);
		if (!next_p)
			break;
		if (pgt_entry_matches(next_p, ctx, begin, last)) {
			flush_pgt_entry(next_p);
			SLIST_REMOVE_AFTER(p, link);
			push_to_free_list(next_p);
			continue;
		}

		p = SLIST_NEXT(p, link);
	}
}

void pgt_flush_ctx_range(struct pgt_cache *pgt_cache, struct ts_ctx *ctx,
			 vaddr_t begin, vaddr_t last)
{
	mutex_lock(&pgt_mu);

	if (pgt_cache)
		flush_ctx_range_from_list(pgt_cache, ctx, begin, last);
	flush_ctx_range_from_list(&pgt_cache_list, ctx, begin, last);

	condvar_broadcast(&pgt_cv);
	mutex_unlock(&pgt_mu);
}

static void clear_ctx_range_from_list(struct pgt_cache *pgt_cache,
				      void *ctx, vaddr_t begin, vaddr_t end)
{
	struct pgt *p = NULL;
#ifdef CFG_WITH_LPAE
	uint64_t *tbl = NULL;
#else
	uint32_t *tbl = NULL;
#endif
	unsigned int idx = 0;
	unsigned int n = 0;

	SLIST_FOREACH(p, pgt_cache, link) {
		vaddr_t b = MAX(p->vabase, begin);
		vaddr_t e = MIN(p->vabase + CORE_MMU_PGDIR_SIZE, end);

		if (p->ctx != ctx)
			continue;
		if (b >= e)
			continue;

		tbl = p->tbl;
		idx = (b - p->vabase) / SMALL_PAGE_SIZE;
		n = (e - b) / SMALL_PAGE_SIZE;
		memset(tbl + idx, 0, n * sizeof(*tbl));
	}
}

void pgt_clear_ctx_range(struct pgt_cache *pgt_cache, struct ts_ctx *ctx,
			 vaddr_t begin, vaddr_t end)
{
	mutex_lock(&pgt_mu);

	if (pgt_cache)
		clear_ctx_range_from_list(pgt_cache, ctx, begin, end);
	clear_ctx_range_from_list(&pgt_cache_list, ctx, begin, end);

	mutex_unlock(&pgt_mu);
}

static bool pgt_alloc_unlocked(struct pgt_cache *pgt_cache, struct ts_ctx *ctx,
			       struct vm_info *vm_info)
{
	struct vm_region *r = NULL;
	struct pgt *pp = NULL;
	struct pgt *p = NULL;
	vaddr_t va = 0;

	TAILQ_FOREACH(r, &vm_info->regions, link) {
		for (va = ROUNDDOWN(r->va, CORE_MMU_PGDIR_SIZE);
		     va < r->va + r->size; va += CORE_MMU_PGDIR_SIZE) {
			if (p && p->vabase == va)
				continue;
			p = pop_from_some_list(va, ctx);
			if (!p) {
				pgt_free_unlocked(pgt_cache);
				return false;
			}
			if (pp)
				SLIST_INSERT_AFTER(pp, p, link);
			else
				SLIST_INSERT_HEAD(pgt_cache, p, link);
			pp = p;
		}
	}

	return true;
}

bool pgt_check_avail(struct vm_info *vm_info)
{
	struct vm_region *r = NULL;
	size_t tbl_count = 0;
	vaddr_t last_va = 0;
	vaddr_t va = 0;

	TAILQ_FOREACH(r, &vm_info->regions, link) {
		for (va = ROUNDDOWN(r->va, CORE_MMU_PGDIR_SIZE);
		     va < r->va + r->size; va += CORE_MMU_PGDIR_SIZE) {
			if (va == last_va)
				continue;
			tbl_count++;
			last_va = va;
		}
	}

	return tbl_count <= PGT_CACHE_SIZE;
}

void pgt_get_all(struct pgt_cache *pgt_cache, struct ts_ctx *ctx,
		 struct vm_info *vm_info)
{
	if (TAILQ_EMPTY(&vm_info->regions))
		return;

	mutex_lock(&pgt_mu);

	pgt_free_unlocked(pgt_cache);
	while (!pgt_alloc_unlocked(pgt_cache, ctx, vm_info)) {
		assert(pgt_check_avail(vm_info));
		DMSG("Waiting for page tables");
		condvar_broadcast(&pgt_cv);
		condvar_wait(&pgt_cv, &pgt_mu);
	}

	mutex_unlock(&pgt_mu);
}

void pgt_put_all(struct pgt_cache *pgt_cache)
{
	if (SLIST_EMPTY(pgt_cache))
		return;

	mutex_lock(&pgt_mu);

	pgt_free_unlocked(pgt_cache);

	condvar_broadcast(&pgt_cv);
	mutex_unlock(&pgt_mu);
}

struct pgt *pgt_pop_from_cache_list(vaddr_t vabase, struct ts_ctx *ctx)
{
	struct pgt *pgt = NULL;

	mutex_lock(&pgt_mu);
	pgt = pop_from_cache_list(vabase, ctx);
	mutex_unlock(&pgt_mu);

	return pgt;
}

void pgt_push_to_cache_list(struct pgt *pgt)
{
	mutex_lock(&pgt_mu);
	push_to_cache_list(pgt);
	mutex_unlock(&pgt_mu);
}
