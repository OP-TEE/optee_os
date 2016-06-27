/*
 * Copyright (c) 2016, Linaro Limited
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

#include <mm/pgt_cache.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <mm/tee_pager.h>
#include <mm/core_mmu.h>
#include <stdlib.h>
#include <util.h>
#include <trace.h>
#include <assert.h>

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
static struct pgt pgt_entries[PGT_CACHE_SIZE];

static struct mutex pgt_mu = MUTEX_INITIALIZER;
static struct condvar pgt_cv = CONDVAR_INITIALIZER;

#if defined(CFG_WITH_PAGER) && defined(CFG_WITH_LPAE)
void pgt_init(void)
{
	size_t n;

	for (n = 0; n < PGT_CACHE_SIZE; n++) {
		struct pgt *p = pgt_entries + n;

		p->tbl = tee_pager_alloc(PGT_SIZE, TEE_MATTR_LOCKED);
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
		uint8_t *tbl = tee_pager_alloc(SMALL_PAGE_SIZE,
					       TEE_MATTR_LOCKED);

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

	if (p)
		SLIST_REMOVE_HEAD(&pgt_free_list, link);
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

static void pgt_free_unlocked(struct pgt_cache *pgt_cache)
{
	while (!SLIST_EMPTY(pgt_cache)) {
		struct pgt *p = SLIST_FIRST(pgt_cache);

		SLIST_REMOVE_HEAD(pgt_cache, link);
		push_to_free_list(p);
	}
}

static bool pgt_alloc_unlocked(struct pgt_cache *pgt_cache, size_t num_tbls)
{
	size_t n = 0;

	while (n < num_tbls) {
		struct pgt *p = pop_from_free_list();

		if (!p) {
			pgt_free_unlocked(pgt_cache);
			return false;
		}

		SLIST_INSERT_HEAD(pgt_cache, p, link);
		n++;
	}

	return true;
}

void pgt_alloc(struct pgt_cache *pgt_cache, size_t num_tbls)
{
	mutex_lock(&pgt_mu);

	pgt_free_unlocked(pgt_cache);
	while (!pgt_alloc_unlocked(pgt_cache, num_tbls)) {
		DMSG("Waiting for page tables");
		condvar_broadcast(&pgt_cv);
		condvar_wait(&pgt_cv, &pgt_mu);
	}

	mutex_unlock(&pgt_mu);
}

void pgt_free(struct pgt_cache *pgt_cache)
{
	if (SLIST_EMPTY(pgt_cache))
		return;

	mutex_lock(&pgt_mu);

	pgt_free_unlocked(pgt_cache);

	condvar_broadcast(&pgt_cv);
	mutex_unlock(&pgt_mu);
}
