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

struct sp_mem_receiver *sp_mem_get_receiver(uint32_t s_id, struct sp_mem *smem)
{
	struct sp_mem_receiver *r = NULL;

	SLIST_FOREACH(r, &smem->receivers, link) {
		if (r->perm.endpoint_id == s_id)
			return r;
	}
	return NULL;
}

struct sp_mem *sp_mem_get(uint64_t handle)
{
	struct sp_mem *smem = NULL;

	SLIST_FOREACH(smem, &mem_shares, link) {
		if (smem->transaction.global_handle == handle)
			return smem;
	}
	return NULL;
}

void *sp_mem_get_va(const struct user_mode_ctx *uctx, size_t offset,
		    struct mobj *mobj)
{
	struct vm_region *region = NULL;

	TAILQ_FOREACH(region, &uctx->vm_info.regions, link) {
		if (region->mobj == mobj) {
			if (region->offset == offset)
				return (void *)region->va;
		}
	}
	return 0;
}

struct sp_mem *sp_mem_new(void)
{
	struct sp_mem *smem = NULL;
	uint32_t exceptions = 0;
	int i = 0;

	smem = malloc(sizeof(*smem));
	if (!smem)
		return NULL;

	exceptions = cpu_spin_lock_xsave(&sp_mem_lock);
	bit_ffc(share_bits, NUM_SHARES, &i);
	if (i != -1) {
		bit_set(share_bits, i);
		/*
		 * OP-TEE SHAREs use bit 44 use bit 45 instead.
		 */
		smem->global_handle = i | FFA_MEMORY_HANDLE_SECURE_BIT;
	}

	if (i == -1) {
		cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
		free(smem);
		return NULL;
	}
	SLIST_INIT(&smem->regions);
	SLIST_INSERT_HEAD(&mem_shares, smem, link);
	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);

	return smem;
}

bool sp_mem_is_shared(struct sp_mem_map_region *new_reg)
{
	struct sp_mem *smem = NULL;

	SLIST_FOREACH(smem, &mem_shares, link) {
		struct sp_mem_map_region *reg = NULL;

		SLIST_FOREACH(reg, &smem->regions, link) {
			uint64_t reg_end = reg->page_offset +
					   (reg->page_count * SMALL_PAGE_SIZE);
			uint64_t new_reg_end = 0;

			new_reg_end = new_reg->page_offset +
				      (new_reg->page_count * SMALL_PAGE_SIZE);

			if (new_reg->mobj == reg->mobj) {
				if (new_reg->page_offset < reg_end &&
				    reg->page_offset < new_reg_end) {
					return true;
				}
			}
		}
	}

	return false;
}

void sp_mem_remove(struct sp_mem *smem)
{
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&sp_mem_lock);
	if (smem) {
		SLIST_REMOVE(&mem_shares, smem, sp_mem, link);
		free(smem);
	}
	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
}
