// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2018-2019, Linaro Limited
 */


#include <assert.h>
#include <compiler.h>
#include <malloc.h>
#include <mempool.h>
#include <pta_stats.h>
#include <string.h>
#include <util.h>

#if defined(__KERNEL__)
#include <kernel/mutex.h>
#include <kernel/panic.h>
#endif

/*
 * Allocation of temporary memory buffers which are used in a stack like
 * fashion. One exmaple is when a Big Number is needed for a temporary
 * variable in a Big Number computation: Big Number operations (add,...),
 * crypto algorithms (rsa, ecc,,...).
 *
 *  The allocation algorithm takes memory buffers from a pool,
 *  characterized by (cf. struct mempool):
 * - the total size (in bytes) of the pool
 * - the offset of the last item allocated in the pool (struct
 *   mempool_item). This offset is -1 is nothing is allocated yet.
 *
 * Each item consists of (struct mempool_item)
 * - the size of the item
 * - the offsets, in the pool, of the previous and next items
 *
 * The allocation allocates an item for a given size.
 * The allocation is performed in the pool after the last
 * allocated items. This means:
 * - the heap is never used.
 * - there is no assumption on the size of the allocated memory buffers. Only
 *   the size of the pool will limit the allocation.
 * - a constant time allocation and free as there is no list scan
 * - but a potentially fragmented memory as the allocation does not take into
 *   account "holes" in the pool (allocation is performed after the last
 *   allocated variable). Indeed, this interface is supposed to be used
 *   with stack like allocations to avoid this issue. This means that
 *   allocated items:
 *   - should have a short life cycle
 *   - if an item A is allocated before another item B, then A should be
 *     released after B.
 *   So the potential fragmentation is mitigated.
 */


struct mempool {
	size_t size;  /* size of the memory pool, in bytes */
	vaddr_t data;
	struct malloc_ctx *mctx;
#ifdef CFG_MEMPOOL_REPORT_LAST_OFFSET
	size_t max_allocated;
#endif
#if defined(__KERNEL__)
	void (*release_mem)(void *ptr, size_t size);
	struct recursive_mutex mu;
#endif
};

#if defined(__KERNEL__)
struct mempool *mempool_default;
#endif

static void init_mpool(struct mempool *pool)
{
	size_t sz = pool->size - raw_malloc_get_ctx_size();
	vaddr_t v = ROUNDDOWN(pool->data + sz, sizeof(long) * 2);

	/*
	 * v is the placed as close to the end of the data pool as possible
	 * where the struct malloc_ctx can be placed. This location is selected
	 * as an optimization for the pager case to get better data
	 * locality since raw_malloc() starts to allocate from the end of
	 * the supplied data pool.
	 */
	assert(v > pool->data);
	pool->mctx = (struct malloc_ctx *)v;
	raw_malloc_init_ctx(pool->mctx);
	raw_malloc_add_pool(pool->mctx, (void *)pool->data, v - pool->data);
}

static void get_pool(struct mempool *pool __maybe_unused)
{
#if defined(__KERNEL__)
	mutex_lock_recursive(&pool->mu);
	if (!pool->mctx)
		init_mpool(pool);

#endif
}

static void put_pool(struct mempool *pool __maybe_unused)
{
#if defined(__KERNEL__)
	if (mutex_get_recursive_lock_depth(&pool->mu) == 1) {
		/*
		 * As the refcount is about to become 0 there should be no items
		 * left
		 */
		if (pool->release_mem) {
			pool->mctx = NULL;
			pool->release_mem((void *)pool->data, pool->size);
		}
	}
	mutex_unlock_recursive(&pool->mu);
#endif
}

struct mempool *
mempool_alloc_pool(void *data, size_t size,
		   void (*release_mem)(void *ptr, size_t size) __maybe_unused)
{
	struct mempool *pool = calloc(1, sizeof(*pool));

	COMPILE_TIME_ASSERT(MEMPOOL_ALIGN >= __alignof__(struct mempool_item));
	assert(!((vaddr_t)data & (MEMPOOL_ALIGN - 1)));

	if (pool) {
		pool->size = size;
		pool->data = (vaddr_t)data;
#if defined(__KERNEL__)
		pool->release_mem = release_mem;
		mutex_init_recursive(&pool->mu);
#else
		init_mpool(pool);
#endif
	}

	return pool;
}

void *mempool_alloc(struct mempool *pool, size_t size)
{
	void *p = NULL;

	get_pool(pool);

	p = raw_malloc(0, 0, size, pool->mctx);
	if (p) {
#ifdef CFG_MEMPOOL_REPORT_LAST_OFFSET
		struct pta_stats_alloc stats = { };

		raw_malloc_get_stats(pool->mctx, &stats);
		if (stats.max_allocated > pool->max_allocated) {
			pool->max_allocated = stats.max_allocated;
			DMSG("Max memory usage increased to %zu",
			     pool->max_allocated);
		}
#endif
		return p;
	}

	EMSG("Failed to allocate %zu bytes, please tune the pool size", size);
	put_pool(pool);
	return NULL;
}

void *mempool_calloc(struct mempool *pool, size_t nmemb, size_t size)
{
	size_t sz;
	void *p;

	if (MUL_OVERFLOW(nmemb, size, &sz))
		return NULL;

	p = mempool_alloc(pool, sz);
	if (p)
		memset(p, 0, sz);

	return p;
}

void mempool_free(struct mempool *pool, void *ptr)
{
	if (ptr) {
		raw_free(ptr, pool->mctx, false /*!wipe*/);
		put_pool(pool);
	}
}
