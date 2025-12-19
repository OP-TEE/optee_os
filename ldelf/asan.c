// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Linutronix GmbH
 */

#include <compiler.h>
#include <ldelf.h>
#include <ldelf_syscalls.h>

#include "asan.h"
#include "sys.h"

static void init_run_constructors(void)
{
	const vaddr_t *ctor = NULL;

	for (ctor = &__init_array_start; ctor < &__init_array_end; ctor++)
		((void (*)(void))(*ctor))();
}

static int asan_ldelf_map_stack(size_t size)
{
	vaddr_t stack_top = (vaddr_t)&stack_top;
	vaddr_t stack_base = 0;

	size = ROUNDUP(size, SMALL_PAGE_SIZE);
	stack_top = ROUNDUP(stack_top, SMALL_PAGE_SIZE);
	stack_base = stack_top - size;

	return asan_user_map_shadow((void *)stack_base, (void *)stack_top);
}

TEE_Result asan_init_ldelf(void)
{
	vaddr_t req = (vaddr_t)GET_ASAN_INFO();
	TEE_Result rc = TEE_SUCCESS;
	vaddr_t tmp = req;

	/* Map global ASan info */
	rc = _ldelf_map_zi(&tmp, sizeof(struct asan_global_info), 0, 0, 0);
	if (rc == TEE_SUCCESS && req == tmp) {
		/* Map shadow stack for ldelf */
		rc = asan_ldelf_map_stack(LDELF_STACK_SIZE);
		if (rc) {
			EMSG("%s: failed to map ldelf shadow stack",
			     __func__);
			panic();
		}
		/* Map shadow memory for ldelf binary sections */
		rc = asan_user_map_shadow((void *)__text_start,
					  (void *)ROUNDUP((vaddr_t)__end,
					  SMALL_PAGE_SIZE));
		if (rc) {
			EMSG("%s: failed to map ldelf shadow elf sections",
			     __func__);
			panic();
		}
		/* Register global ASan constructors */
		init_run_constructors();
	} else {
		rc = TEE_ERROR_GENERIC;
	}

	return rc;
}
