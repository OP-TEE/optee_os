/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <arm.h>
#include <tee_api_defines.h>
#include <kernel/thread.h>
#include <kernel/unwind.h>
#include <asm-defines.h>

	.section .text.arch_svc_asm

/*
 * uint32_t tee_svc_do_call(struct thread_svc_regs *regs, tee_svc_func func);
 *
 * Called from tee_svc_handler()
 */
FUNC tee_svc_do_call , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	push	{r5-r9, lr}
	mov	r7, sp
	mov	r8, r0
	mov	r9, r1
	ldr	r5, [r8, #THREAD_SVC_REG_R5]
	ldr	r6, [r8, #THREAD_SVC_REG_R6]

	/*
	 * Copy eventual arguments passed on the user stack.
	 *
	 * r5 holds the address of the first word
	 * r6 holds the number of words
	 *
	 * tee_svc_handler() who calls this function has already checked
	 * that we don't copy too much data.
	 */
	cmp     r6, #0
	beq     .Lno_args
	sub     sp, sp, r6, lsl #2
	bic	sp, sp, #7	/* make sure it's a multiple of 8 */
	mov     r0, sp
	mov     r1, r5
	mov     r2, r6, lsl #2
	ldr     lr, =tee_svc_copy_from_user
	blx     lr

	/* If copy failed return the error */
	cmp     r0, #0
	bne     .Lret

.Lno_args:
	/* Load arguments to function */
	add	lr, r8, #THREAD_SVC_REG_R0
	ldm	lr, {r0-r3}
	blx	r9
.Lret:
	mov	sp, r7
	pop	{r5-r9, pc}
UNWIND(	.fnend)
END_FUNC tee_svc_do_call

/*
 * User space sees this function as:
 * void syscall_sys_return(uint32_t ret) __noreturn;
 *
 * But internally the function depends on being called from
 * tee_svc_do_call() with pointer to the struct thread_svc_regs saved by
 * thread_svc_handler() in r8. The argument ret is already in r0 so we
 * don't touch that and let it propagate as return value of the called
 * thread_unwind_user_mode().
 */
FUNC syscall_sys_return , :
UNWIND(	.fnstart)
	mov	r1, #0	/* panic = false */
	mov	r2, #0	/* panic_code = 0 */
	mov	r3, r8
	b	tee_svc_sys_return_helper
UNWIND(	.fnend)
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
UNWIND(	.fnstart)
	mov	r1, #1	/* panic = true */
	mov	r2, r0	/* panic_code = 0 */
	mov	r3, r8
	ldr	r0, =TEE_ERROR_TARGET_DEAD
	b	tee_svc_sys_return_helper
UNWIND(	.fnend)
END_FUNC syscall_panic
