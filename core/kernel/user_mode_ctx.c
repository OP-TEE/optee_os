// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <kernel/user_mode_ctx.h>
#include <trace.h>
#include <mm/mobj.h>

void user_mode_ctx_print_mappings(struct user_mode_ctx *uctx)
{
	struct vm_region *r = NULL;
	char flags[7] = { '\0', };
	size_t n = 0;

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link) {
		paddr_t pa = 0;

		if (r->mobj)
			mobj_get_pa(r->mobj, r->offset, 0, &pa);

		mattr_perm_to_str(flags, sizeof(flags), r->attr);
		EMSG_RAW(" region %2zu: va 0x%0*" PRIxVA " pa 0x%0*" PRIxPA
			 " size 0x%06zx flags %s",
			 n, PRIxVA_WIDTH, r->va, PRIxPA_WIDTH, pa, r->size,
			 flags);
		n++;
	}
}
