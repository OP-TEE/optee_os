/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */
#ifndef MM_PGT_CACHE_H
#define MM_PGT_CACHE_H

#ifdef CFG_WITH_LPAE
#define PGT_SIZE	(4 * 1024)
#define PGT_NUM_PGT_PER_PAGE	1
#else
#define PGT_SIZE	(1 * 1024)
#define PGT_NUM_PGT_PER_PAGE	4
#endif

#include <assert.h>
#include <kernel/tee_ta_manager.h>
#include <sys/queue.h>
#include <types_ext.h>
#include <util.h>

struct ts_ctx;

struct pgt {
	void *tbl;
	vaddr_t vabase;
#if defined(CFG_PAGED_USER_TA)
	struct ts_ctx *ctx;
	size_t num_used_entries;
#endif
#if defined(CFG_WITH_PAGER)
#if !defined(CFG_WITH_LPAE)
	struct pgt_parent *parent;
#endif
#endif
	SLIST_ENTRY(pgt) link;
};

/*
 * A proper value for PGT_CACHE_SIZE depends on many factors: CFG_WITH_LPAE,
 * CFG_TA_ASLR, size of TA, size of memrefs passed to TA, CFG_ULIBS_SHARED and
 * possibly others. The value is based on the number of threads as an indicator
 * on how large the system might be.
 */
#if CFG_NUM_THREADS < 2
#define PGT_CACHE_SIZE	4
#elif (CFG_NUM_THREADS == 2 && !defined(CFG_WITH_LPAE))
#define PGT_CACHE_SIZE	8
#else
#define PGT_CACHE_SIZE	ROUNDUP(CFG_NUM_THREADS * 2, PGT_NUM_PGT_PER_PAGE)
#endif

SLIST_HEAD(pgt_cache, pgt);

static inline bool pgt_check_avail(size_t num_tbls)
{
	return num_tbls <= PGT_CACHE_SIZE;
}

void pgt_alloc(struct pgt_cache *pgt_cache, struct ts_ctx *owning_ctx,
	       vaddr_t begin, vaddr_t last);
void pgt_free(struct pgt_cache *pgt_cache, bool save_ctx);

void pgt_clear_ctx_range(struct pgt_cache *pgt_cache, struct ts_ctx *ctx,
			 vaddr_t begin, vaddr_t end);
#ifdef CFG_PAGED_USER_TA
void pgt_flush_ctx_range(struct pgt_cache *pgt_cache, struct ts_ctx *ctx,
			 vaddr_t begin, vaddr_t last);
#else
static inline void pgt_flush_ctx_range(struct pgt_cache *pgt_cache __unused,
				       struct ts_ctx *ctx __unused,
				       vaddr_t begin __unused,
				       vaddr_t last __unused)
{
}
#endif

void pgt_init(void);

#if defined(CFG_PAGED_USER_TA)
void pgt_flush_ctx(struct ts_ctx *ctx);

static inline void pgt_inc_used_entries(struct pgt *pgt)
{
	pgt->num_used_entries++;
	assert(pgt->num_used_entries);
}

static inline void pgt_dec_used_entries(struct pgt *pgt)
{
	assert(pgt->num_used_entries);
	pgt->num_used_entries--;
}

static inline void pgt_set_used_entries(struct pgt *pgt, size_t val)
{
	pgt->num_used_entries = val;
}

#else
static inline void pgt_flush_ctx(struct ts_ctx *ctx __unused)
{
}

static inline void pgt_inc_used_entries(struct pgt *pgt __unused)
{
}

static inline void pgt_dec_used_entries(struct pgt *pgt __unused)
{
}

static inline void pgt_set_used_entries(struct pgt *pgt __unused,
					size_t val __unused)
{
}

#endif

#endif /*MM_PGT_CACHE_H*/
