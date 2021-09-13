// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 */
#include <assert.h>
#include <bitstring.h>
#include <ffa.h>
#include <kernel/spinlock.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <mm/sp_mem.h>

#define NUM_SHARES	64

static bitstr_t bit_decl(share_bits, NUM_SHARES);
static unsigned int sp_mem_lock = SPINLOCK_UNLOCK;

/* mem_shares stores all active FF-A shares. */
SLIST_HEAD(sp_mem_head, sp_mem);
static struct sp_mem_head mem_shares = SLIST_HEAD_INITIALIZER(sp_mem_head);

struct sp_mem *sp_mem_new(void)
{
	struct sp_mem *smem = NULL;
	uint32_t exceptions = 0;
	int i = 0;

	smem = calloc(sizeof(*smem), 1);
	if (!smem)
		return NULL;

	exceptions = cpu_spin_lock_xsave(&sp_mem_lock);

	bit_ffc(share_bits, NUM_SHARES, &i);
	if (i == -1) {
		cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
		free(smem);
		return NULL;
	}

	bit_set(share_bits, i);
	/*
	 * OP-TEE SHAREs use bit 44 use bit 45 instead.
	 */
	smem->global_handle = i | FFA_MEMORY_HANDLE_SECURE_BIT;
	SLIST_INIT(&smem->regions);
	SLIST_INIT(&smem->receivers);

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);

	return smem;
}

void sp_mem_add(struct sp_mem *smem)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&sp_mem_lock);

	SLIST_INSERT_HEAD(&mem_shares, smem, link);

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
}

bool sp_mem_is_shared(struct sp_mem_map_region *new_reg)
{
	struct sp_mem *smem = NULL;
	uint32_t exceptions = cpu_spin_lock_xsave(&sp_mem_lock);
	uint64_t new_reg_end = new_reg->page_offset +
			       (new_reg->page_count * SMALL_PAGE_SIZE);

	SLIST_FOREACH(smem, &mem_shares, link) {
		struct sp_mem_map_region *reg = NULL;

		SLIST_FOREACH(reg, &smem->regions, link) {
			if (new_reg->mobj == reg->mobj) {
				uint64_t reg_end = 0;

				reg_end = reg->page_offset +
					  (reg->page_count * SMALL_PAGE_SIZE);

				if (new_reg->page_offset < reg_end &&
				    new_reg_end > reg->page_offset) {
					cpu_spin_unlock_xrestore(&sp_mem_lock,
								 exceptions);
					return true;
				}
			}
		}
	}

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
	return false;
}

void sp_mem_remove(struct sp_mem *smem)
{
	uint32_t exceptions = 0;
	int i = 0;
	struct sp_mem *tsmem = NULL;

	if (!smem)
		return;

	/* Remove all receivers */
	while (!SLIST_EMPTY(&smem->receivers)) {
		struct sp_mem_receiver *receiver = NULL;

		receiver = SLIST_FIRST(&smem->receivers);
		SLIST_REMOVE_HEAD(&smem->receivers, link);
		free(receiver);
	}
	/* Remove all regions */
	while (!SLIST_EMPTY(&smem->regions)) {
		struct sp_mem_map_region *region = SLIST_FIRST(&smem->regions);

		mobj_put(region->mobj);

		SLIST_REMOVE_HEAD(&smem->regions, link);
		free(region);
	}

	exceptions = cpu_spin_lock_xsave(&sp_mem_lock);

	i = smem->global_handle & ~FFA_MEMORY_HANDLE_SECURE_BIT;
	assert(i < NUM_SHARES);

	bit_clear(share_bits, i);

	SLIST_FOREACH(tsmem, &mem_shares, link) {
		if (tsmem == smem) {
			SLIST_REMOVE(&mem_shares, smem, sp_mem, link);
			break;
		}
	}

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);

	free(smem);
}
