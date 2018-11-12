/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __MEMPOOL_H
#define __MEMPOOL_H

#include <types_ext.h>

/*
 * struct mempool_item - internal struct to keep track of an item
 */
struct mempool_item {
	size_t size;
	ssize_t prev_item_offset;
	ssize_t next_item_offset;
};

struct mempool;

/*
 * mempool_alloc_pool() - Allocate a new memory pool
 * @data:		a block of memory to carve out items from
 * @size:		size fo the block of memory
 * @release_mem:	function to call when the pool has been emptied,
 *			ignored if NULL.
 * returns a pointer to a valid pool on success or NULL on failure.
 */
struct mempool *mempool_alloc_pool(void *data, size_t size,
				   void (*release_mem)(void *ptr, size_t size));

/*
 * mempool_alloc() - Allocate an item from a memory pool
 * @pool:		A memory pool created with mempool_alloc_pool()
 * @size:		Size in bytes of the item to allocate
 * return a valid pointer on success or NULL on failure.
 */
void *mempool_alloc(struct mempool *pool, size_t size);

/*
 * mempool_calloc() - Allocate and zero initialize an array of elements from a
 *		      memory pool
 * @pool:		A memory pool created with mempool_alloc_pool()
 * @nmemb:		Number of elements in the array
 * @size:		Size in bytes of each element in the array
 * return a valid pointer on success or NULL on failure.
 */
void *mempool_calloc(struct mempool *pool, size_t nmemb, size_t size);

/*
 * mempool_free() - Frees a previously allocated item
 * @pool:		A memory pool create with mempool_alloc_pool()
 * @ptr:		A pointer to a previously allocated item
 */
void mempool_free(struct mempool *pool, void *ptr);

#endif /*__MEMPOOL_H*/
