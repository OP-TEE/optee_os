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

#include <kernel/tee_common.h>
#include <util.h>
#include <trace.h>

#include <mm/tee_mm.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>

bool tee_mm_init(tee_mm_pool_t *pool, uint32_t lo, uint32_t hi, uint8_t shift,
		 uint32_t flags)
{
	if (pool == NULL)
		return false;

	lo = ROUNDUP(lo, 1 << shift);
	hi = ROUNDDOWN(hi, 1 << shift);
	pool->lo = lo;
	pool->hi = hi;
	pool->shift = shift;
	pool->flags = flags;
	pool->entry = calloc(1, sizeof(tee_mm_entry_t));

	if (pool->entry == NULL)
		return false;

	if (pool->flags & TEE_MM_POOL_HI_ALLOC)
		pool->entry->offset = ((hi - lo - 1) >> shift) + 1;
	pool->entry->pool = pool;

	return true;
}

void tee_mm_final(tee_mm_pool_t *pool)
{
	if (pool == NULL || pool->entry == NULL)
		return;

	while (pool->entry->next != NULL)
		tee_mm_free(pool->entry->next);
	free(pool->entry);
	pool->entry = NULL;
}

static tee_mm_entry_t *tee_mm_add(tee_mm_entry_t *p)
{
	/* add to list */
	if (p->next == NULL) {
		p->next = malloc(sizeof(tee_mm_entry_t));
		if (p->next == NULL)
			return NULL;
		p->next->next = NULL;
	} else {
		tee_mm_entry_t *nn = malloc(sizeof(tee_mm_entry_t));

		if (nn == NULL)
			return NULL;
		nn->next = p->next;
		p->next = nn;
	}
	return p->next;
}

#ifdef CFG_WITH_STATS
static size_t tee_mm_stats_allocated(tee_mm_pool_t *pool)
{
	tee_mm_entry_t *entry;
	uint32_t sz = 0;

	if (!pool)
		return 0;

	entry = pool->entry;
	while (entry) {
		sz += entry->size;
		entry = entry->next;
	}

	return sz << pool->shift;
}

void tee_mm_get_pool_stats(tee_mm_pool_t *pool, struct tee_mm_pool_stats *stats,
			   bool reset)
{
	stats->size = pool->hi - pool->lo;
	stats->max_allocated = pool->max_allocated;
	stats->allocated = tee_mm_stats_allocated(pool);

	if (reset)
		stats->max_allocated = 0;
}

static void update_max_allocated(tee_mm_pool_t *pool)
{
	size_t sz = tee_mm_stats_allocated(pool);

	if (sz > pool->max_allocated)
		pool->max_allocated = sz;
}
#else /* CFG_WITH_STATS */
static inline void update_max_allocated(tee_mm_pool_t *pool __unused)
{
}
#endif /* CFG_WITH_STATS */

tee_mm_entry_t *tee_mm_alloc(tee_mm_pool_t *pool, uint32_t size)
{
	uint32_t psize;
	tee_mm_entry_t *entry;
	tee_mm_entry_t *nn;
	uint32_t remaining;

	/* Check that pool is initialized */
	if (!pool || !pool->entry)
		return NULL;

	entry = pool->entry;
	if (size == 0)
		psize = 0;
	else
		psize = ((size - 1) >> pool->shift) + 1;
	/* Protect with mutex (multi thread) */

	/* find free slot */
	if (pool->flags & TEE_MM_POOL_HI_ALLOC) {
		while (entry->next != NULL && psize >
		       (entry->offset - entry->next->offset -
			entry->next->size))
			entry = entry->next;
	} else {
		while (entry->next != NULL && psize >
		       (entry->next->offset - entry->size - entry->offset))
			entry = entry->next;
	}

	/* check if we have enough memory */
	if (entry->next == NULL) {
		if (pool->flags & TEE_MM_POOL_HI_ALLOC) {
			/*
			 * entry->offset is a "block count" offset from
			 * pool->lo. The byte offset is
			 * (entry->offset << pool->shift).
			 * In the HI_ALLOC allocation scheme the memory is
			 * allocated from the end of the segment, thus to
			 * validate there is sufficient memory validate that
			 * (entry->offset << pool->shift) > size.
			 */
			if ((entry->offset << pool->shift) < size)
				/* out of memory */
				return NULL;
		} else {
			TEE_ASSERT(pool->hi > pool->lo);
			remaining = (pool->hi - pool->lo);
			remaining -= ((entry->offset + entry->size) <<
				      pool->shift);

			if (remaining < size)
				/* out of memory */
				return NULL;
		}
	}

	nn = tee_mm_add(entry);
	if (nn == NULL)
		return NULL;

	if (pool->flags & TEE_MM_POOL_HI_ALLOC)
		nn->offset = entry->offset - psize;
	else
		nn->offset = entry->offset + entry->size;
	nn->size = psize;
	nn->pool = pool;

	update_max_allocated(pool);

	/* Protect with mutex end (multi thread) */

	return nn;
}

static inline bool fit_in_gap(tee_mm_pool_t *pool, tee_mm_entry_t *e,
			      uint32_t offslo, uint32_t offshi)
{
	if (pool->flags & TEE_MM_POOL_HI_ALLOC) {
		if (offshi > e->offset ||
		    (e->next != NULL &&
		     (offslo < e->next->offset + e->next->size)) ||
		    (offshi << pool->shift) - 1 > (pool->hi - pool->lo))
			/* memory not available */
			return false;
	} else {
		if (offslo < (e->offset + e->size) ||
		    (e->next != NULL && (offshi > e->next->offset)) ||
		    (offshi << pool->shift) > (pool->hi - pool->lo))
			/* memory not available */
			return false;
	}

	return true;
}

tee_mm_entry_t *tee_mm_alloc2(tee_mm_pool_t *pool, tee_vaddr_t base,
			      size_t size)
{
	tee_mm_entry_t *entry;
	uint32_t offslo;
	uint32_t offshi;
	tee_mm_entry_t *mm;

	/* Check that pool is initialized */
	if (!pool || !pool->entry)
		return NULL;

	/* Wrapping and sanity check */
	if ((base + size) < base || base < pool->lo)
		return NULL;

	entry = pool->entry;
	offslo = (base - pool->lo) >> pool->shift;
	offshi = ((base - pool->lo + size - 1) >> pool->shift) + 1;

	/* find slot */
	if (pool->flags & TEE_MM_POOL_HI_ALLOC) {
		while (entry->next != NULL &&
		       offshi < entry->next->offset + entry->next->size)
			entry = entry->next;
	} else {
		while (entry->next != NULL && offslo > entry->next->offset)
			entry = entry->next;
	}

	/* Check that memory is available */
	if (!fit_in_gap(pool, entry, offslo, offshi))
		return NULL;

	mm = tee_mm_add(entry);
	if (mm == NULL)
		return NULL;

	mm->offset = offslo;
	mm->size = offshi - offslo;
	mm->pool = pool;

	update_max_allocated(pool);

	return mm;
}

void tee_mm_free(tee_mm_entry_t *p)
{
	tee_mm_entry_t *entry;

	if (!p || !p->pool)
		return;

	entry = p->pool->entry;

	/* Protect with mutex (multi thread) */

	/* remove entry from list */
	while (entry->next != NULL && entry->next != p)
		entry = entry->next;

	if (entry->next == NULL) {
		DMSG("invalid mm_entry %p", (void *)p);
		TEE_ASSERT(0);
	}
	entry->next = entry->next->next;

	free(p);

	/* Protect with mutex end (multi thread) */
}

size_t tee_mm_get_bytes(const tee_mm_entry_t *mm)
{
	if (!mm || !mm->pool)
		return 0;
	else
		return mm->size << mm->pool->shift;
}

bool tee_mm_addr_is_within_range(tee_mm_pool_t *pool, uint32_t addr)
{
	return (pool && ((addr >= pool->lo) && (addr <= pool->hi)));
}

bool tee_mm_is_empty(tee_mm_pool_t *pool)
{
	return pool == NULL || pool->entry == NULL || pool->entry->next == NULL;
}

/* Physical Public DDR pool */
tee_mm_pool_t tee_mm_pub_ddr __data; /* XXX __data is a workaround */

/* Physical Secure DDR pool */
tee_mm_pool_t tee_mm_sec_ddr __data; /* XXX __data is a workaround */

/* Virtual eSRAM pool */
tee_mm_pool_t tee_mm_vcore __data; /* XXX __data is a workaround */

tee_mm_entry_t *tee_mm_find(const tee_mm_pool_t *pool, uint32_t addr)
{
	tee_mm_entry_t *entry = pool->entry;
	uint16_t offset = (addr - pool->lo) >> pool->shift;

	if (addr > pool->hi || addr < pool->lo)
		return NULL;

	while (entry->next != NULL) {
		entry = entry->next;

		if ((offset >= entry->offset) &&
		    (offset < (entry->offset + entry->size))) {
			return entry;
		}
	}

	return NULL;
}

uintptr_t tee_mm_get_smem(const tee_mm_entry_t *mm)
{
	return (mm->offset << mm->pool->shift) + mm->pool->lo;
}
