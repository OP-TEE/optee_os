/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "tee_syscall_numbers.h"
#include "trace_levels.h"
#include <arm.h>
#include <asm.S>
#include <generated/asm-defines.h>
#include <kernel/thread.h>
#include <tee_api_defines.h>

/*
 * uint32_t scall_do_call(struct thread_scall_regs *regs, syscall_t func);
 *
 * Called from scall_handle_user_ta()
 */
FUNC scall_do_call , :
UNWIND(	.cantunwind)
	push	{r5-r9, lr}
	mov	r7, sp
	mov	r8, r0
	mov	r9, r1
	ldr	r5, [r8, #THREAD_SCALL_REG_R5]
	ldr	r6, [r8, #THREAD_SCALL_REG_R6]

	/*
	 * Copy eventual arguments passed on the user stack.
	 *
	 * r5 holds the address of the first word
	 * r6 holds the number of words
	 *
	 * scall_handle_user_ta() who calls this function has already checked
	 * that we don't copy too much data.
	 */
	cmp     r6, #0
	beq     .Lno_args
	sub     sp, sp, r6, lsl #2
	bic	sp, sp, #7	/* make sure it's a multiple of 8 */
	mov     r0, sp
	mov     r1, r5
	mov     r2, r6, lsl #2
	ldr     lr, =copy_from_user
	blx     lr

	/* If copy failed return the error */
	cmp     r0, #0
	bne     .Lret

.Lno_args:
	/* Load arguments to function */
	add	lr, r8, #THREAD_SCALL_REG_R0
	ldm	lr, {r0-r3}
	blx	r9
.Lret:
	mov	sp, r7
	pop	{r5-r9, pc}
END_FUNC scall_do_call

/*
 * syscall_sys_return() and syscall_panic() are two special cases for syscalls
 * in the way that they do not return to the TA, instead execution is resumed
 * as if __thread_enter_user_mode() had returned to thread_enter_user_mode().
 *
 * In order to do this the functions need a way to get hold of a pointer to
 * the struct thread_scall_regs provided by storing relevant registers on the
 * stack in thread_scall_handler() and later load them into registers again
 * when thread_scall_handler() is returning.
 *
 * scall_do_call() is supplied the pointer to struct thread_scall_regs in
 * r0. This pointer can later be retrieved from r8.
 */

/*
 * User space sees this function as:
 * void syscall_sys_return(uint32_t ret) __noreturn;
 *
 * But internally the function depends on being called from
 * scall_do_call() with pointer to the struct thread_scall_regs saved by
 * thread_scall_handler() in r8.
 *
 * The argument ret is already in r0 so we don't touch that and let it
 * propagate as return value of the called scall_sys_return_helper().
 */
FUNC syscall_sys_return , :
	mov	r1, #0	/* panic = false */
	mov	r2, #0	/* panic_code = 0 */
	mov	r3, r8	/* pointer to struct thread_scall_regs */
	b	scall_sys_return_helper
END_FUNC syscall_sys_return

/*
 * User space sees this function as:
 * void syscall_panic(uint32_t code) __noreturn;
 *
 * But internally the function depends on being called from
 * scall_do_call() with pointer to the struct thread_scall_regs saved by
 * thread_scall_handler() in r8.
 */
FUNC syscall_panic , :
	mov	r1, #1	/* panic = true */
	mov	r2, r0	/* panic_code = 0 */
	mov	r3, r8	/* pointer to struct thread_scall_regs */
	ldr	r0, =TEE_ERROR_TARGET_DEAD
	b	scall_sys_return_helper
END_FUNC syscall_panic
