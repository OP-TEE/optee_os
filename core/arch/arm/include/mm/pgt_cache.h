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
#ifndef MM_PGT_CACHE_H
#define MM_PGT_CACHE_H

#ifdef CFG_WITH_LPAE
#define PGT_SIZE	(4 * 1024)
#define PGT_NUM_PGT_PER_PAGE	1
#else
#define PGT_SIZE	(1 * 1024)
#define PGT_NUM_PGT_PER_PAGE	4
#endif

#include <kernel/tee_ta_manager.h>
#include <sys/queue.h>
#include <types_ext.h>
#include <util.h>

struct pgt {
	void *tbl;
#if defined(CFG_PAGED_USER_TA)
	vaddr_t vabase;
	struct tee_ta_ctx *ctx;
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
 * Reserve 2 page tables per thread, but at least 4 page tables in total
 */
#if CFG_NUM_THREADS < 2
#define PGT_CACHE_SIZE	4
#else
#define PGT_CACHE_SIZE	ROUNDUP(CFG_NUM_THREADS * 2, PGT_NUM_PGT_PER_PAGE)
#endif

SLIST_HEAD(pgt_cache, pgt);

static inline bool pgt_check_avail(size_t num_tbls)
{
	return num_tbls <= PGT_CACHE_SIZE;
}

void pgt_alloc(struct pgt_cache *pgt_cache, void *owning_ctx,
	       vaddr_t begin, vaddr_t last);
void pgt_free(struct pgt_cache *pgt_cache, bool save_ctx);

#ifdef CFG_PAGED_USER_TA
void pgt_flush_ctx_range(struct pgt_cache *pgt_cache, void *ctx,
			 vaddr_t begin, vaddr_t last);
#else
static inline void pgt_flush_ctx_range(struct pgt_cache *pgt_cache __unused,
				       void *ctx __unused,
				       vaddr_t begin __unused,
				       vaddr_t last __unused)
{
}
#endif

void pgt_transfer(struct pgt_cache *pgt_cache, void *old_ctx, vaddr_t old_va,
		  void *new_ctx, vaddr_t new_va, size_t size);

void pgt_init(void);

#if defined(CFG_PAGED_USER_TA)
void pgt_flush_ctx(struct tee_ta_ctx *ctx);

static inline void pgt_inc_used_entries(struct pgt *pgt)
{
	pgt->num_used_entries++;
}

static inline void pgt_dec_used_entries(struct pgt *pgt)
{
	pgt->num_used_entries--;
}

static inline void pgt_set_used_entries(struct pgt *pgt, size_t val)
{
	pgt->num_used_entries = val;
}

#else
static inline void pgt_flush_ctx(struct tee_ta_ctx *ctx __unused)
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
