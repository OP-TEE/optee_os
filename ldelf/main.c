// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <ldelf.h>
#include <malloc.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>

#include "ta_elf.h"
#include "sys.h"

static size_t mpool_size = 2 * SMALL_PAGE_SIZE;
static vaddr_t mpool_base;

/*
 * ldelf()- Loads ELF into memory
 * @arg:	Argument passing to/from TEE Core
 *
 * Only called from assembly
 */
void __noreturn ldelf(struct ldelf_arg *arg);
void ldelf(struct ldelf_arg *arg)
{
	TEE_Result res = TEE_SUCCESS;
	struct ta_elf *elf = NULL;

	DMSG("Loading TA %pUl", (void *)&arg->uuid);
	res = sys_map_zi(mpool_size, 0, &mpool_base, 0, 0);
	if (res) {
		EMSG("sys_map_zi(%zu): result %"PRIx32, mpool_size, res);
		panic();
	}
	malloc_add_pool((void *)mpool_base, mpool_size);

	/* Load the main binary and get a list of dependencies, if any. */
	ta_elf_load_main(&arg->uuid, &arg->is_32bit, &arg->entry_func,
			 &arg->stack_ptr, &arg->flags);

	/*
	 * Load binaries, ta_elf_load() may add external libraries to the
	 * list, so the loop will end when all the dependencies are
	 * satisfied.
	 */
	TAILQ_FOREACH(elf, &main_elf_queue, link)
		ta_elf_load_dependency(elf, arg->is_32bit);

	TAILQ_FOREACH(elf, &main_elf_queue, link) {
		ta_elf_relocate(elf);
		ta_elf_finalize_mappings(elf);
	}

	TAILQ_FOREACH(elf, &main_elf_queue, link)
		DMSG("ELF (%pUl) at %#"PRIxVA,
		     (void *)&elf->uuid, elf->load_addr);

	res = sys_unmap(mpool_base, mpool_size);
	if (res) {
		EMSG("sys_unmap(%p, %zu): result %"PRIx32,
		     (void *)mpool_base, mpool_size, res);
		panic();
	}
	sys_return_cleanup();
}
