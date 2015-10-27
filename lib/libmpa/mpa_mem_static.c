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
#include "mpa.h"
#include <util.h>
#include <trace.h>

/*
 *  mpa_init_scratch_mem_sync
 */
void mpa_init_scratch_mem_sync(mpa_scratch_mem pool, size_t size,
			uint32_t bn_bits, mpa_scratch_mem_sync_fn get,
			mpa_scratch_mem_sync_fn put,
			struct mpa_scratch_mem_sync *sync)
{
	pool->size = size;
	pool->last_offset = 0;	/* nothing is allocated yet in the pool */
	pool->bn_bits = bn_bits * 2;
	pool->get = get;
	pool->put = put;
	pool->sync = sync;
}

void mpa_init_scratch_mem(mpa_scratch_mem pool, size_t size, uint32_t bn_bits)
{
	mpa_init_scratch_mem_sync(pool, size, bn_bits, NULL, NULL, NULL);
}

/*
 * The allocation of the temporary Big Number is called when a temporary
 * variable is used in Big Number computation: Big Number operations (add,...),
 * crypto algorithms (rsa, ecc,,...)
 * The allocation algorithm takes Big Numbers from a pool, characterized by
 * (cf. struct mpa_scratch_mem_struct):
 * - the total size (in bytes) of the pool
 * - the default size (bits) of a big number that will be required
 *   it equals the max size of the computation (for example 4096 bits),
 *   multiplied by 2 to allow overflow in computation
 * - the offset of the last Big Number item allocated in the pool
 *   (struct  mpa_scratch_item). This offset is 0 is nothing is allocated yet.
 *
 * Each item consists of (struct mpa_scratch_item)
 * - the size of the item
 * - the offsets, in the pool, of the previous and next items
 *
 * The allocation allocates an item for a given size of Big Number.
 * The allocation is performed in the pool after the last
 * allocated items. This means:
 * - the heap is never used.
 * - there is no assumption on the size of the allocated Big Number. Only
 *   the size of the pool will limit the allocation. This allow to
 *   allocate "small" Big Numbers, such in ECC where we know they are
 *   less than 521 bits.
 * - a constant time allocation and free as there is no list scan
 * - but a potentially fragmented memory as the allocation does not take into
 *   account "holes" in the pool (allocation is performed after the last
 *   allocated variable). Indeed, this it does not happen to be an issue
 *   as the variables are used as temporary variables, that is
 *   - have a short life cycle
 *   - if a variable A is allocated before a variable B, then A should be
 *     released after B.
 *   So the potential fragmentation is mitigated.
 */
mpanum mpa_alloc_static_temp_var_size(int size_bits, mpanum *var,
				      mpa_scratch_mem pool)
{
	uint32_t offset;
	size_t size;
	struct mpa_scratch_item *new_item;
	struct mpa_scratch_item *last_item = NULL;

	if (pool->get)
		pool->get(pool->sync);

	if (!pool->last_offset)
		offset = sizeof(struct mpa_scratch_mem_struct);
	else {
		offset = pool->last_offset;
		last_item = (struct mpa_scratch_item *)
				((vaddr_t)pool + offset);
		offset += last_item->size;
	}

	offset = ROUNDUP(offset, sizeof(uint32_t));
	if (offset > pool->size)
		goto error;

	size = sizeof(struct mpa_scratch_item) +
	       mpa_StaticVarSizeInU32(size_bits) * sizeof(uint32_t);
	size = ROUNDUP(size, sizeof(uint32_t));
	if (offset + size > pool->size)
		goto error;

	new_item = (struct mpa_scratch_item *)((vaddr_t)pool + offset);
	new_item->size = size;
	new_item->prev_item_offset = pool->last_offset;
	if (last_item)
		last_item->next_item_offset = offset;
	new_item->next_item_offset = 0;
	pool->last_offset = offset;

	*var = (mpanum)(new_item + 1);
	mpa_init_static(*var, mpa_StaticVarSizeInU32(size_bits));
	return *var;

error:
	*var = 0;
	if (pool->put)
		pool->put(pool->sync);
	return 0;
}


mpanum mpa_alloc_static_temp_var(mpanum *var, mpa_scratch_mem pool)
{
	return mpa_alloc_static_temp_var_size(pool->bn_bits, var, pool);
}

/*------------------------------------------------------------
 *
 *  mpa_free_static_temp_var
 *
 */
void mpa_free_static_temp_var(mpanum *var, mpa_scratch_mem pool)
{
	struct mpa_scratch_item *item;
	struct mpa_scratch_item *prev_item;
	struct mpa_scratch_item *next_item;
	uint32_t last_offset = 0;

	if (!var || !(*var))
		return;

	item = (struct mpa_scratch_item *)((vaddr_t)(*var) -
	       sizeof(struct mpa_scratch_item));
	if (item->prev_item_offset) {
		prev_item = (struct mpa_scratch_item *)((vaddr_t)pool +
							item->prev_item_offset);
		prev_item->next_item_offset = item->next_item_offset;
		last_offset = item->prev_item_offset;
	}

	if (item->next_item_offset) {
		next_item = (struct mpa_scratch_item *)((vaddr_t)pool +
							item->next_item_offset);
		next_item->prev_item_offset = item->prev_item_offset;
		last_offset = pool->last_offset;
	}

	pool->last_offset = last_offset;
	if (pool->put)
		pool->put(pool->sync);
}

