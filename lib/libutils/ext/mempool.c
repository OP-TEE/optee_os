// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2018, Linaro Limited
 */


#include <assert.h>
#include <compiler.h>
#include <malloc.h>
#include <mempool.h>
#include <util.h>

#if defined(__KERNEL__)
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
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

#define POOL_ALIGN	__alignof__(long)

struct mempool {
	size_t size;  /* size of the memory pool, in bytes */
	ssize_t last_offset;   /* offset to the last one */
	vaddr_t data;
#if defined(__KERNEL__)
	void (*release_mem)(void *ptr, size_t size);
	struct mutex mu;
	struct condvar cv;
	size_t count;
	int owner;
#endif
};

static void get_pool(struct mempool *pool __maybe_unused)
{
#if defined(__KERNEL__)
	mutex_lock(&pool->mu);

	if (pool->owner != thread_get_id()) {
		/* Wait until the pool is available */
		while (pool->owner != THREAD_ID_INVALID)
			condvar_wait(&pool->cv, &pool->mu);

		pool->owner = thread_get_id();
		assert(pool->count == 0);
	}

	pool->count++;

	mutex_unlock(&pool->mu);
#endif
}

static void put_pool(struct mempool *pool __maybe_unused)
{
#if defined(__KERNEL__)
	mutex_lock(&pool->mu);

	assert(pool->owner == thread_get_id());
	assert(pool->count > 0);

	pool->count--;
	if (!pool->count) {
		pool->owner = THREAD_ID_INVALID;
		condvar_signal(&pool->cv);
		/* As the refcount is 0 there should be no items left */
		if (pool->last_offset >= 0)
			panic();
		if (pool->release_mem)
			pool->release_mem((void *)pool->data, pool->size);
	}

	mutex_unlock(&pool->mu);
#endif
}

struct mempool *
mempool_alloc_pool(void *data, size_t size,
		   void (*release_mem)(void *ptr, size_t size) __maybe_unused)
{
	struct mempool *pool = calloc(1, sizeof(*pool));

	COMPILE_TIME_ASSERT(POOL_ALIGN >= __alignof__(struct mempool_item));
	assert(!((vaddr_t)data & (POOL_ALIGN - 1)));

	if (pool) {
		pool->size = size;
		pool->data = (vaddr_t)data;
		pool->last_offset = -1;
#if defined(__KERNEL__)
		pool->release_mem = release_mem;
		mutex_init(&pool->mu);
		condvar_init(&pool->cv);
		pool->owner = THREAD_ID_INVALID;
#endif
	}

	return pool;
}

void *mempool_alloc(struct mempool *pool, size_t size)
{
	size_t offset;
	struct mempool_item *new_item;
	struct mempool_item *last_item = NULL;

	get_pool(pool);

	if (pool->last_offset < 0) {
		offset = 0;
	} else {
		last_item = (struct mempool_item *)(pool->data +
						    pool->last_offset);
		offset = pool->last_offset + last_item->size;

		offset = ROUNDUP(offset, POOL_ALIGN);
		if (offset > pool->size)
			goto error;
	}

	size = sizeof(struct mempool_item) + size;
	size = ROUNDUP(size, POOL_ALIGN);
	if (offset + size > pool->size)
		goto error;

	new_item = (struct mempool_item *)(pool->data + offset);
	new_item->size = size;
	new_item->prev_item_offset = pool->last_offset;
	if (last_item)
		last_item->next_item_offset = offset;
	new_item->next_item_offset = -1;
	pool->last_offset = offset;

	return new_item + 1;

error:
	put_pool(pool);
	return NULL;
}

void mempool_free(struct mempool *pool, void *ptr)
{
	struct mempool_item *item;
	struct mempool_item *prev_item;
	struct mempool_item *next_item;
	ssize_t last_offset = -1;

	if (!ptr)
		return;

	item = (struct mempool_item *)((vaddr_t)ptr -
				       sizeof(struct mempool_item));
	if (item->prev_item_offset >= 0) {
		prev_item = (struct mempool_item *)(pool->data +
						    item->prev_item_offset);
		prev_item->next_item_offset = item->next_item_offset;
		last_offset = item->prev_item_offset;
	}

	if (item->next_item_offset >= 0) {
		next_item = (struct mempool_item *)(pool->data +
						    item->next_item_offset);
		next_item->prev_item_offset = item->prev_item_offset;
		last_offset = pool->last_offset;
	}

	pool->last_offset = last_offset;
	put_pool(pool);
}
