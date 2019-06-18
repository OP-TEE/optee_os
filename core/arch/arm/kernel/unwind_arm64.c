// SPDX-License-Identifier: BSD-2-Clause
/*-
 * Copyright (c) 2015 Linaro Limited
 * Copyright (c) 2015 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Semihalf under
 * the sponsorship of the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <arm.h>
#include <kernel/thread.h>
#include <kernel/unwind.h>
#include <kernel/tee_misc.h>
#include <string.h>
#include <tee/tee_svc.h>
#include <trace.h>
#include <util.h>

#include "unwind_private.h"

static void copy_in_reg(uint64_t *reg, vaddr_t addr)
{
	memcpy(reg, (void *)addr, sizeof(*reg));
}

bool unwind_stack_arm64(struct unwind_state_arm64 *frame,
			vaddr_t stack, size_t stack_size)
{
	vaddr_t fp = frame->fp;

	if (!core_is_buffer_inside(fp, sizeof(uint64_t) * 3,
				   stack, stack_size))
		return false;

	frame->sp = fp + 0x10;
	/* FP to previous frame (X29) */
	copy_in_reg(&frame->fp, fp);
	/* LR (X30) */
	copy_in_reg(&frame->pc, fp + 8);
	frame->pc -= 4;

	return true;
}

#if (TRACE_LEVEL > 0)

void print_stack_arm64(int level, struct unwind_state_arm64 *state,
		       vaddr_t stack, size_t stack_size)
{
	trace_printf_helper_raw(level, true, "Call stack:");

	do {
		trace_printf_helper_raw(level, true, " 0x%016" PRIx64,
					state->pc);
	} while (unwind_stack_arm64(state, stack, stack_size));
}

void print_kernel_stack(int level)
{
	struct unwind_state_arm64 state;
	uaddr_t stack = thread_stack_start();
	size_t stack_size = thread_stack_size();

	memset(&state, 0, sizeof(state));
	state.pc = read_pc();
	state.fp = read_fp();

	print_stack_arm64(level, &state, stack, stack_size);
}

#endif

vaddr_t *unw_get_kernel_stack(void)
{
	size_t n = 0;
	size_t size = 0;
	vaddr_t *tmp = NULL;
	vaddr_t *addr = NULL;
	struct unwind_state_arm64 state = { 0 };
	uaddr_t stack = thread_stack_start();
	size_t stack_size = thread_stack_size();

	state.pc = read_pc();
	state.fp = read_fp();

	while (unwind_stack_arm64(&state, stack, stack_size)) {
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
