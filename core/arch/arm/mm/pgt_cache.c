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

#ifdef CFG_PAGED_USER_TA
/*
 * When a user TA context is temporarily unmapped the used struct pgt's of
 * the context (page tables holding valid physical pages) are saved in this
 * cache in the hope that some of the valid physical pages may still be
 * valid when the context is mapped again.
 */
static struct pgt_cache pgt_cache_list = SLIST_HEAD_INITIALIZER(pgt_cache_list);
#endif

static struct pgt pgt_entries[PGT_CACHE_SIZE];

static struct mutex pgt_mu = MUTEX_INITIALIZER;
static struct condvar pgt_cv = CONDVAR_INITIALIZER;

#if defined(CFG_WITH_PAGER) && defined(CFG_WITH_LPAE)
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
static struct pgt *pop_from_free_list(void)
{
	struct pgt *p = SLIST_FIRST(&pgt_free_list);

	if (p) {
		SLIST_REMOVE_HEAD(&pgt_free_list, link);
		memset(p->tbl, 0, PGT_SIZE);
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
static struct pgt *pop_from_free_list(void)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(pgt_parents); n++) {
		struct pgt *p = SLIST_FIRST(&pgt_parents[n].pgt_cache);

		if (p) {
			SLIST_REMOVE_HEAD(&pgt_parents[n].pgt_cache, link);
			pgt_parents[n].num_used++;
			memset(p->tbl, 0, PGT_SIZE);
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

#ifdef CFG_PAGED_USER_TA
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

static struct pgt *pop_least_used_from_cache_list(void)
{
	struct pgt *pgt;
	struct pgt *p_prev = NULL;
	size_t least_used;

	pgt = SLIST_FIRST(&pgt_cache_list);
	if (!pgt)
		return NULL;
	if (!pgt->num_used_entries)
		goto out;
	least_used = pgt->num_used_entries;

	while (true) {
		if (!SLIST_NEXT(pgt, link))
			break;
		if (SLIST_NEXT(pgt, link)->num_used_entries <= least_used) {
			p_prev = pgt;
			least_used = SLIST_NEXT(pgt, link)->num_used_entries;
		}
		pgt = SLIST_NEXT(pgt, link);
	}

out:
	if (p_prev) {
		pgt = SLIST_NEXT(p_prev, link);
		SLIST_REMOVE_AFTER(p_prev, link);
	} else {
		pgt = SLIST_FIRST(&pgt_cache_list);
		SLIST_REMOVE_HEAD(&pgt_cache_list, link);
	}
	return pgt;
}

static void pgt_free_unlocked(struct pgt_cache *pgt_cache, bool save_ctx)
{
	while (!SLIST_EMPTY(pgt_cache)) {
		struct pgt *p = SLIST_FIRST(pgt_cache);

		SLIST_REMOVE_HEAD(pgt_cache, link);
		if (save_ctx && p->num_used_entries) {
			push_to_cache_list(p);
		} else {
			tee_pager_pgt_save_and_release_entries(p);
			assert(!p->num_used_entries);
			p->ctx = NULL;
			p->vabase = 0;

			push_to_free_list(p);
		}
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
	}
	assert(!p->num_used_entries);
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
		assert(!p->num_used_entries);
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
			assert(!p->num_used_entries);
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
	assert(!p->num_used_entries);
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

#else /*!CFG_PAGED_USER_TA*/

static void pgt_free_unlocked(struct pgt_cache *pgt_cache,
			      bool save_ctx __unused)
{
	while (!SLIST_EMPTY(pgt_cache)) {
		struct pgt *p = SLIST_FIRST(pgt_cache);

		SLIST_REMOVE_HEAD(pgt_cache, link);
		push_to_free_list(p);
	}
}

static struct pgt *pop_from_some_list(vaddr_t vabase,
				      struct ts_ctx *ctx __unused)
{
	struct pgt *p = pop_from_free_list();

	if (p)
		p->vabase = vabase;

	return p;
}
#endif /*!CFG_PAGED_USER_TA*/

static void clear_ctx_range_from_list(struct pgt_cache *pgt_cache,
				      void *ctx __maybe_unused,
				      vaddr_t begin, vaddr_t end)
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

#ifdef CFG_PAGED_USER_TA
		if (p->ctx != ctx)
			continue;
#endif
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
#ifdef CFG_PAGED_USER_TA
	clear_ctx_range_from_list(&pgt_cache_list, ctx, begin, end);
#endif

	mutex_unlock(&pgt_mu);
}

static bool pgt_alloc_unlocked(struct pgt_cache *pgt_cache, struct ts_ctx *ctx,
			       vaddr_t begin, vaddr_t last)
{
	const vaddr_t base = ROUNDDOWN(begin, CORE_MMU_PGDIR_SIZE);
	const size_t num_tbls = ((last - base) >> CORE_MMU_PGDIR_SHIFT) + 1;
	size_t n = 0;
	struct pgt *p;
	struct pgt *pp = NULL;

	while (n < num_tbls) {
		p = pop_from_some_list(base + n * CORE_MMU_PGDIR_SIZE, ctx);
		if (!p) {
			pgt_free_unlocked(pgt_cache, ctx);
			return false;
		}

		if (pp)
			SLIST_INSERT_AFTER(pp, p, link);
		else
			SLIST_INSERT_HEAD(pgt_cache, p, link);
		pp = p;
		n++;
	}

	return true;
}

void pgt_alloc(struct pgt_cache *pgt_cache, struct ts_ctx *ctx,
	       vaddr_t begin, vaddr_t last)
{
	if (last <= begin)
		return;

	mutex_lock(&pgt_mu);

	pgt_free_unlocked(pgt_cache, ctx);
	while (!pgt_alloc_unlocked(pgt_cache, ctx, begin, last)) {
		DMSG("Waiting for page tables");
		condvar_broadcast(&pgt_cv);
		condvar_wait(&pgt_cv, &pgt_mu);
	}

	mutex_unlock(&pgt_mu);
}

void pgt_free(struct pgt_cache *pgt_cache, bool save_ctx)
{
	if (SLIST_EMPTY(pgt_cache))
		return;

	mutex_lock(&pgt_mu);

	pgt_free_unlocked(pgt_cache, save_ctx);

	condvar_broadcast(&pgt_cv);
	mutex_unlock(&pgt_mu);
}
