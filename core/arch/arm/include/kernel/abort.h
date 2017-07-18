/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef KERNEL_ABORT_H
#define KERNEL_ABORT_H

#define ABORT_TYPE_UNDEF	0
#define ABORT_TYPE_PREFETCH	1
#define ABORT_TYPE_DATA		2

#ifndef ASM

#include <compiler.h>
#include <types_ext.h>

struct abort_info {
	uint32_t abort_type;
	uint32_t fault_descr;	/* only valid for data of prefetch abort */
	vaddr_t va;
	uint32_t pc;
	struct thread_abort_regs *regs;
};

/* Print abort info to the console */
void abort_print(struct abort_info *ai);
/* Print abort info + stack dump to the console */
void abort_print_error(struct abort_info *ai);

void abort_handler(uint32_t abort_type, struct thread_abort_regs *regs);

bool abort_is_user_exception(struct abort_info *ai);

#endif /*ASM*/
#endif /*KERNEL_ABORT_H*/

