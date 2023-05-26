// SPDX-License-Identifier: BSD-2-Clause
/*-
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright (c) 2015-2019 Linaro Limited
 * Copyright (c) 2015 The FreeBSD Foundation
 */

#include <compiler.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <unw/unwind.h>
#include <util.h>

void __weak ftrace_map_lr(uint64_t *lr __unused)
{
}

bool unwind_stack_riscv(struct unwind_state_riscv *frame,
			vaddr_t stack, size_t stack_size)
{
	vaddr_t fp = frame->fp;
	struct unwind_state_riscv *caller_state = NULL;

	if (fp < stack)
		return false;
	if (fp > stack + stack_size)
		return false;

	/*
	 *  |    .....    |       ^  unwind upwards
	 *  |    .....    |       |
	 *  +=============+  <--+ |  +======= caller FP ==========+
	 *  |     RA      |     | |
	 *  +-------------+     | |
	 *  |  caller FP  |  ---|-+               ^
	 *  +-------------+     |          caller stack frame
	 *  |    .....    |     |                 v
	 *  |    .....    |     |
	 *  |    .....    |     |
	 *  +=============+     |    +== caller SP / trapped FP ==+
	 *  |     RA      |     |
	 *  +-------------+     |
	 *  |  caller FP  |  ---+                 ^
	 *  +-------------+               trapped stack frame
	 *  |    .....    |                       v
	 *  |    .....    |
	 *  |    .....    |
	 *  +=============+          +======== trapped SP ========+
	 *         |
	 *         |  grow downwards
	 *         V
	 */

	/* Get caller FP and RA */
	caller_state = (struct unwind_state_riscv *)fp - 1;
	frame->fp = caller_state->fp;
	frame->pc = caller_state->pc;

	ftrace_map_lr(&frame->pc);

	frame->pc -= 4;

	return true;
}

void print_stack_riscv(struct unwind_state_riscv *state,
		       vaddr_t stack, size_t stack_size)
{
	int width = sizeof(unsigned long);

	trace_printf_helper_raw(TRACE_ERROR, true, "Call stack:");

	ftrace_map_lr(&state->pc);
	do {
		trace_printf_helper_raw(TRACE_ERROR, true, " 0x%0*"PRIxVA,
					width, state->pc);
	} while (unwind_stack_riscv(state, stack, stack_size));
}
