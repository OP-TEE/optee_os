// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <assert.h>
#include <kernel/mutex.h>
#include <kernel/spinlock.h>
#include <kernel/tee_misc.h>
#include <kernel/user_mode_ctx.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>
#include <mm/tee_pager.h>
#include <stdlib.h>
#include <trace.h>
#include <util.h>

void pgt_init(void)
{
}

void pgt_flush(struct user_mode_ctx *uctx __unused)
{
}

bool pgt_check_avail(struct user_mode_ctx *uctx __unused)
{
	return false;
}

void pgt_clear_range(struct user_mode_ctx *uctx __unused,
		     vaddr_t begin __unused, vaddr_t end __unused)
{
}

void pgt_flush_range(struct user_mode_ctx *uctx __unused,
		     vaddr_t begin __unused, vaddr_t last __unused)
{
}

struct pgt *pgt_pop_from_cache_list(vaddr_t vabase __unused,
				    struct ts_ctx *ctx __unused)
{
	return NULL;
}

void pgt_push_to_cache_list(struct pgt *pgt __unused)
{
}

void pgt_get_all(struct user_mode_ctx *uctx __unused)
{
}
