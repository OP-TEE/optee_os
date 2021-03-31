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
#include <kernel/linker.h>
#include <kernel/thread.h>
#include <kernel/unwind.h>
#include <unw/unwind.h>

#include "unwind_private.h"

vaddr_t *unw_get_kernel_stack(void)
{
	size_t n = 0;
	size_t size = 0;
	vaddr_t *tmp = NULL;
	vaddr_t *addr = NULL;
	uaddr_t stack = thread_stack_start();
	size_t stack_size = thread_stack_size();
	struct unwind_state_arm64 state = {
		.pc = read_pc(),
		.fp = read_fp()
	};

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

#if defined(CFG_UNWIND) && (TRACE_LEVEL > 0)
void print_kernel_stack(void)
{
	struct unwind_state_arm64 state = { };
	vaddr_t stack_start = 0;
	vaddr_t stack_end = 0;

	state.pc = read_pc();
	state.fp = read_fp();

	trace_printf_helper_raw(TRACE_ERROR, true,
				"TEE load address @ %#"PRIxVA, VCORE_START_VA);
	get_stack_hard_limits(&stack_start, &stack_end);
	print_stack_arm64(&state, stack_start, stack_end - stack_start);
}
#endif
