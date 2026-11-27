// SPDX-License-Identifier: BSD-2-Clause
/*-
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright (c) 2015 Linaro Limited
 * Copyright (c) 2015 The FreeBSD Foundation
 */

#include <kernel/linker.h>
#include <kernel/thread.h>
#include <kernel/unwind.h>
#include <kernel/unwind_private.h>
#include <riscv.h>
#include <unw/unwind.h>

vaddr_t *unw_get_kernel_stack(void)
{
	size_t n = 0;
	size_t size = 0;
	vaddr_t *tmp = NULL;
	vaddr_t *addr = NULL;
	vaddr_t stack = thread_stack_start();
	size_t stack_size = thread_stack_size();
	struct unwind_state_riscv state = {
		.pc = read_pc(),
		.fp = read_fp()
	};

	while (unwind_stack_riscv(&state, stack, stack_size)) {
		tmp = unw_grow(addr, &size, (n + 1) * sizeof(vaddr_t));
		if (!tmp)
			goto err;
		addr = tmp;
		addr[n] = state.pc;
		n++;
	}

	if (addr) {
		tmp = unw_grow(addr, &size, (n + 1) * sizeof(vaddr_t));
		if (!tmp)
			goto err;
		addr = tmp;
		addr[n] = 0;
	}

	return addr;
err:
	EMSG("Out of memory");
	free(addr);
	return NULL;
}

#if defined(CFG_UNWIND) && (TRACE_LEVEL > 0)
void print_kernel_stack(void)
{
	struct unwind_state_riscv state = { };
	vaddr_t stack_start = 0;
	vaddr_t stack_end = 0;

	state.pc = read_pc();
	state.fp = read_fp();

	trace_printf_helper_raw(TRACE_ERROR, true,
				"TEE load address @ %#"PRIxVA, VCORE_START_VA);
	get_stack_hard_limits(&stack_start, &stack_end);
	print_stack_riscv(&state, stack_start, stack_end - stack_start);
}
#endif
