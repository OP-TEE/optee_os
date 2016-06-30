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
#include "tee_syscall_numbers.h"
#include "trace_levels.h"
#include <asm.S>
#include <arm64_macros.S>
#include <arm64.h>
#include <tee_api_defines.h>
#include <kernel/thread.h>
#include <asm-defines.h>

	.section .text.arch_svc_asm

#if 0
struct sc_rec {
	uint64_t x0;
	uint64_t x1;
	uint64_t x19;
	uint64_t x30;
}
#endif
#define SC_REC_X0		(8 * 0)
#define SC_REC_X1		(8 * 1)
#define SC_REC_X19		(8 * 2)
#define SC_REC_X30		(8 * 3)
#define SC_REC_SIZE		(SC_REC_X30 + 8)

/*
 * uint32_t tee_svc_do_call(struct thread_svc_regs *regs, tee_svc_func func);
 *
 * Called from tee_svc_handler()
 */
FUNC tee_svc_do_call , :
	sub	sp, sp, #SC_REC_SIZE
	stp	x0, x1, [sp, #SC_REC_X0]
	stp	x19, x30, [sp, #SC_REC_X19]
	mov	x19, sp

	ldr	x2, [x0, #THREAD_SVC_REG_SPSR]
	tst	x2, #(SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT)
	b.eq	.Lcall_a64

	ldp	x5, x6, [x0, #THREAD_SVC_REG_X5]
	cmp	x6, #0
	b.eq	.Lno_args_a32

	/*
	 * Calculate required space on stack to copy Aarch32 arguments
	 * and to transform them into Aarch64 arguments.
	 * x6 = nargs_on_stack
         * n64 = (nargs_on_stack - 4) * 8
         * n32 = nargs_on_stack * 4
         * sp -= ROUNDUP(MAX(n32, n64), 16)
	 *
	 */
	/* n64 = (nargs_on_stack - 4) * 8 */
	sub	x1, x6, #0x4
	lsl	x1, x1, #3
	/* n32 = nargs_on_stack * 4 */
	lsl	x0, x6, #2
	/* sp -= ROUNDUP(MAX(n32, n64), 16) */
	cmp	x1, x0
	csel	x0, x1, x0, ge
	add	x0, x0, #0xf
	and	x0, x0, #0xfffffffffffffff0
	sub	sp, sp, x0

	/*
	 * Find location on stack where to copy the Aarch32 arguments
	 * and do the copy.
	 * tee_svc_copy_from_user(sp, x5, nargs_on_stack * 4)
	 */
	mov	x0, sp
	mov	x1, x5
	add	x2, xzr, x6, lsl #2
	bl	tee_svc_copy_from_user
	/* If copy failed return the error */
	cmp	x0, #0
	bne	.Lret

	/*
	 * Load arguments into w4..w7, we're loading junk into unused
	 * registers, but it's quicker than trying to figure out how
	 * many registers to load into.
	 */
	/* x0 = nargs_on_stack */
	ldr	x0, [x19, #SC_REC_X0]
	ldr	x0, [x0, #THREAD_SVC_REG_X6]
	load_wregs sp, 0, 4, 7

	/*
	 * Convert remaining Aarch32 parameters passed on stack as Aarch64
	 * parameters on stack.
	 *
	 * nargs_on_stack is initialized in x0 above
	 * n64 = (nargs_on_stack - 4) * 8
	 * if n64 < 0 goro .Lno_args
	 * x0 = x2 = x19 - n64
	 * x1 points to next argument
	 * while (x2 != x19) {
	 *	w3 = *x1
	 *	x1 += 4
	 *	*x2 = x3
	 *	x2 += 8
	 * }
	 * sp = x0
	 */
	/* n64 = (nargs_on_stack - 4) * 8 */
	subs	x2, x0, #0x4
	b.le	.Lno_args_a32
	lsl	x2, x2, #3
	mov	x0, x2

.Lcpy_to_stack:
	ldr	w3, [x1], #4
	str	x3, [x2], #8
	cmp	x2, x19
	b.ne	.Lcpy_to_stack
	mov	sp, x0


.Lno_args_a32: /* Load the first 4 arguments to function */
	ldr	x9, [x19, #SC_REC_X0]
	load_xregs x9, THREAD_SVC_REG_X0, 0, 3
	mov	w0, w0
	mov	w1, w1
	mov	w2, w2
	mov	w3, w3

	/* Call the svc function */
	ldr	x16, [x19, #SC_REC_X1]
	blr	x16
	b	.Lret

.Lcall_a64: /* Load the first 8 arguments to function */
	ldr	x9, [x19, #SC_REC_X0]
	load_xregs x9, THREAD_SVC_REG_X0, 0, 8

	/* Call the svc function */
	ldr	x16, [x19, #SC_REC_X1]
	blr	x16

.Lret:
	mov	sp, x19
	ldp	x19, x30, [sp, #SC_REC_X19]
	add	sp, sp, #SC_REC_SIZE
	ret
END_FUNC tee_svc_do_call

/*
 * User space sees this function as:
 * void syscall_sys_return(uint32_t ret) __noreturn;
 *
 * But internally the function depends on being called from
 * tee_svc_do_call() with pointer to the struct thread_svc_regs saved by
 * thread_svc_handler() in r8. The argument ret is already in r0 so we
 * don't touch that and let it propagate as return value of the called
 * tee_svc_unwind_enter_user_mode().
 */
FUNC syscall_sys_return , :
	mov	x1, #0  /* panic = false */
	mov	x2, #0  /* panic_code = 0 */
	ldr	x3, [x19, #SC_REC_X0]
	b	tee_svc_sys_return_helper
END_FUNC syscall_sys_return

/*
 * User space sees this function as:
 * void syscall_panic(uint32_t code) __noreturn;
 *
 * But internally the function depends on being called from
 * tee_svc_do_call() with pointer to the struct thread_svc_regs saved by
 * thread_svc_handler() in r8.
 */
FUNC syscall_panic , :
	mov	x1, #1  /* panic = true */
	mov	x2, x0  /* code */
	ldr	w0, =TEE_ERROR_TARGET_DEAD
	ldr	x3, [x19, #SC_REC_X0]
	b	tee_svc_sys_return_helper
END_FUNC syscall_panic
