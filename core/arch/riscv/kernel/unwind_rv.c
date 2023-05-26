// SPDX-License-Identifier: BSD-2-Clause
/*-
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright (c) 2015 Linaro Limited
 * Copyright (c) 2015 The FreeBSD Foundation
 */

#include <kernel/linker.h>
#include <kernel/thread.h>
#include <kernel/unwind.h>
#include <riscv.h>
#include <unw/unwind.h>

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
