// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <assert.h>
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

static void __noreturn __maybe_unused dump_ta_state(struct dump_entry_arg *arg)
{
	struct ta_elf *elf = TAILQ_FIRST(&main_elf_queue);

	assert(elf && elf->is_main);
	EMSG_RAW("Status of TA %pUl", (void *)&elf->uuid);
	EMSG_RAW(" arch: %s", elf->is_32bit ? "arm" : "aarch64");


	ta_elf_print_mappings(&main_elf_queue, arg->num_maps, arg->maps,
			      mpool_base);

	if (arg->is_arm32)
		ta_elf_stack_trace_a32(arg->arm32.regs);
	else
		ta_elf_stack_trace_a64(arg->arm64.fp, arg->arm64.sp,
				       arg->arm64.pc);

	sys_return_cleanup();
}

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

#if TRACE_LEVEL >= TRACE_ERROR
	arg->dump_entry = (vaddr_t)(void *)dump_ta_state;
#else
	arg->dump_entry = 0;
#endif

	sys_return_cleanup();
}
