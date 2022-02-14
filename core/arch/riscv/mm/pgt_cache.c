// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <mm/pgt_cache.h>

void pgt_init(void)
{
}

void pgt_free(struct pgt_cache *pgt_cache __unused, bool save_ctx __unused)
{
}

void pgt_clear_ctx_range(struct pgt_cache *pgt_cache __unused,
		struct ts_ctx *ctx __unused, vaddr_t begin __unused,
		vaddr_t end __unused)
{				 
}
