// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2015 Linaro Limited
 * Copyright 2013-2014 Andrew Turner.
 * Copyright 2013-2014 Ian Lepore.
 * Copyright 2013-2014 Rui Paulo.
 * Copyright 2013 Eitan Adler.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <arm.h>
#include <kernel/linker.h>
#include <kernel/thread.h>
#include <kernel/unwind.h>
#include <trace.h>
#include <unw/unwind.h>

#include "unwind_private.h"

/* The register names */
#define	FP	11
#define	SP	13
#define	LR	14
#define	PC	15

bool find_exidx(vaddr_t addr __unused, vaddr_t *idx_start, vaddr_t *idx_end)
{
	*idx_start = (vaddr_t)__exidx_start;
	*idx_end = (vaddr_t)__exidx_end;
	return true;
}

vaddr_t *unw_get_kernel_stack(void)
{
	size_t n = 0;
	size_t size = 0;
	size_t exidx_sz = 0;
	vaddr_t *tmp = NULL;
	vaddr_t *addr = NULL;
	struct unwind_state_arm32 state = { };
	vaddr_t stack = thread_stack_start();
	size_t stack_size = thread_stack_size();

	if (SUB_OVERFLOW((vaddr_t)__exidx_end, (vaddr_t)__exidx_start,
			 &exidx_sz))
		return NULL;

	/* r7: Thumb-style frame pointer */
	state.registers[7] = read_r7();
	/* r11: ARM-style frame pointer */
	state.registers[FP] = read_fp();
	state.registers[SP] = read_sp();
	state.registers[LR] = read_lr();

	/*
	 * Add 4 to make sure that we have an address well inside this function.
	 * This is needed because we're subtracting 2 from PC when calling
	 * find_index() above. See a comment there for more details.
	 */
	state.registers[PC] = (uint32_t)unw_get_kernel_stack + 4;

	while (unwind_stack_arm32(&state, stack, stack_size)) {
		tmp = unw_grow(addr, &size, (n + 1) * sizeof(vaddr_t));
		if (!tmp)
			goto err;
		addr = tmp;
		addr[n] = state.registers[PC];
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
	return NULL;
}

#if (TRACE_LEVEL > 0)
void print_kernel_stack(void)
{
	struct unwind_state_arm32 state = { };
	vaddr_t stack_start = 0;
	vaddr_t stack_end = 0;

	/* r7: Thumb-style frame pointer */
	state.registers[7] = read_r7();
	/* r11: ARM-style frame pointer */
	state.registers[FP] = read_fp();
	state.registers[SP] = read_sp();
	state.registers[LR] = read_lr();

	/*
	 * Add 4 to make sure that we have an address well inside this function.
	 * This is needed because we're subtracting 2 from PC when calling
	 * find_index() above. See a comment there for more details.
	 */
	state.registers[PC] = (uint32_t)print_kernel_stack + 4;

	trace_printf_helper_raw(TRACE_ERROR, true,
				"TEE load address @ %#"PRIxVA, VCORE_START_VA);
	get_stack_hard_limits(&stack_start, &stack_end);
	print_stack_arm32(&state, stack_start, stack_end - stack_start);
}
#endif
