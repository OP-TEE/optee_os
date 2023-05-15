// SPDX-License-Identifier: BSD-2-Clause
/*-
 * Copyright (c) 2015-2019 Linaro Limited
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

#include <compiler.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <unw/unwind.h>
#include <util.h>

void __weak ftrace_map_lr(uint64_t *lr __unused)
{}

void __weak pauth_strip_pac(uint64_t *lr __unused)
{}

static bool copy_in_reg(uint64_t *reg, vaddr_t addr)
{
	memcpy(reg, (void *)addr, sizeof(*reg));
	return true;
}

bool unwind_stack_arm64(struct unwind_state_arm64 *frame,
			vaddr_t stack, size_t stack_size)
{
	vaddr_t fp = frame->fp;

	if (fp < stack)
		return false;
	if (fp + sizeof(uint64_t) * 3 > stack + stack_size)
		return false;

	frame->sp = fp + 0x10;
	/* FP to previous frame (X29) */
	if (!copy_in_reg(&frame->fp, fp))
		return false;
	if (!frame->fp)
		return false;
	/* LR (X30) */
	if (!copy_in_reg(&frame->pc, fp + 8))
		return false;

	pauth_strip_pac(&frame->pc);

	ftrace_map_lr(&frame->pc);

	frame->pc -= 4;

	return true;
}

void print_stack_arm64(struct unwind_state_arm64 *state,
		       vaddr_t stack, size_t stack_size)
{
	int width = 8;

	trace_printf_helper_raw(TRACE_ERROR, true, "Call stack:");

	ftrace_map_lr(&state->pc);
	do {
		trace_printf_helper_raw(TRACE_ERROR, true, " 0x%0*"PRIx64,
					width, state->pc);
	} while (unwind_stack_arm64(state, stack, stack_size));
}
