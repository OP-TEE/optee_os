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

/* mem_shares stores all active FF-A shares. */
SLIST_HEAD(sp_mem_head, sp_mem);
static struct sp_mem_head mem_shares = SLIST_HEAD_INITIALIZER(sp_mem_head);

static unsigned int sp_mem_lock = SPINLOCK_UNLOCK;

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
		 * OP_TEE SHAREs use bit 44 use bit 45 instead.
		 */
		smem->transaction.global_handle = i | BIT64(45);
	}
	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);

	SLIST_INIT(&smem->regions);
	SLIST_INSERT_HEAD(&mem_shares, smem, link);

	return smem;
}

bool sp_mem_remove(struct sp_mem *smem)
{
	if (smem) {
		SLIST_REMOVE(&mem_shares, smem, sp_mem, link);
		free(smem);
	}
	return false;
}
