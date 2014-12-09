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
#include <arm32.h>
#include <tee_api_defines.h>
#include <kernel/thread.h>

	.section .text.arch_svc_asm

/*
 * Below are low level routines handling entry and return from user mode.
 *
 * tee_svc_enter_user_mode() saves all that registers user mode can change
 * so kernel mode can restore needed registers when resuming execution
 * after the call to tee_svc_enter_user_mode() has returned.
 * tee_svc_enter_user_mode() doesn't return directly since it enters user
 * mode instead, it's tee_svc_unwind_enter_user_mode() that does the
 * returning by restoring the registers saved by tee_svc_enter_user_mode().
 *
 * There's three ways for tee_svc_enter_user_mode() to return to caller,
 * user TA calls utee_return, user TA calls utee_panic or through an abort.
 *
 * Calls to utee_return or utee_panic are handled as:
 * thread_svc_handler() -> tee_svc_handler() ->	tee_svc_do_call() which
 * calls tee_svc_sys_return() or tee_svc_sys_panic().
 *
 * These function calls returns normally except thread_svc_handler() which
 * which is an exception handling routine so it reads return address and
 * SPSR to restore from the stack. tee_svc_sys_return() and tee_svc_sys_panic()
 * changes return address and SPSR used by thread_svc_handler() to instead of
 * returning into user mode as with other syscalls it returns into
 * tee_svc_unwind_enter_user_mode() in kernel mode instead.  When
 * thread_svc_handler() returns the stack pointer at the point where
 * tee_svc_enter_user_mode() left it so this is where
 * tee_svc_unwind_enter_user_mode() can operate.
 *
 * Aborts are handled in a similar way but by thread_abort_handler()
 * instead, when the pager sees that it's an abort from user mode that
 * can't be handled it updates SPSR and return address used by
 * thread_abort_handler() to return into tee_svc_unwind_enter_user_mode()
 * instead.
 */

/*
 * TEE_Result tee_svc_enter_user_mode(
 *              uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
 *              tee_uaddr_t sp, tee_uaddr_t user_func,
 *              uint32_t *panicked, uint32_t *panic_code);
 */
FUNC tee_svc_enter_user_mode , :
	/*
	 * Save all registers to allow tee_svc_sys_return() to
	 * resume execution as if this function would have returned.
	 * This is also used in tee_svc_sys_panic().
	 *
	 * If stack usage of this function is changed
	 * tee_svc_unwind_enter_user_mode() has to be updated.
	 */
	push    {r4-r12,lr}

	ldr     r4, [sp, #(10 * 0x4)]   /* user stack pointer */
	ldr     r5, [sp, #(11 * 0x4)]   /* user function */

	/*
	 * Save old user sp and set new user sp.
	 */
	cps	#CPSR_MODE_SYS
	mov	r6, sp
	mov     sp, r4
	cps	#CPSR_MODE_SVC
	push	{r6}

	/*
	 * Set the saved Processors Status Register to user mode to allow
	 * entry of user mode through movs below. Also update thumbstate
	 * since movs doesn't do that automatically.
	 */
	mrs     r6, cpsr
	bic     r6, #CPSR_MODE_MASK
	orr	r6, #CPSR_MODE_USR
	tst     r5, #1	/* If it's odd we should switch to thumb mode */
	orrne   r6, #CPSR_T		/* Enable thumb mode */
	biceq   r6, #CPSR_T		/* Disable thumb mode */
	bicne   r6, #CPSR_IT_MASK1	/* Clear IT state for thumb mode */
	bicne   r6, #CPSR_IT_MASK2	/* Clear IT state for thumb mode */
	msr     spsr_cxsf, r6

	/*
	* Don't allow return from this function, return is done through
	* tee_svc_unwind_enter_user_mode() below.
	*/
	mov     lr, #0
	/* Call the user function with its arguments */
	movs    pc, r5
END_FUNC tee_svc_enter_user_mode

/*
 * uint32_t tee_svc_unwind_enter_user_mode(uint32_t ret, bool panic,
 *			uint32_t panic_code);
 *
 * This is the function that exception handlers can return into
 * to resume execution in kernel mode instead of user mode.
 *
 * This function is closely coupled with tee_svc_enter_user_mode() since
 * it need to restore registers saved by tee_svc_enter_user_mode() and when
 * it returns make it look like tee_svc_enter_user_mode() just returned.
 * It is expected that the stack pointer is where tee_svc_enter_user_mode()
 * left it. The stack will be unwound and we'll return to where
 * tee_svc_enter_user_mode() was expected to return to.
 */
FUNC tee_svc_unwind_enter_user_mode , :
	ldr     ip, [sp, #(13 * 0x4)]   /* &ctx->panicked */
	str	r1, [ip]
	ldr     ip, [sp, #(14 * 0x4)]   /* &ctx->panic_code */
	str	r2, [ip]

	/* Restore old user sp */
	pop	{r4}
	cps	#CPSR_MODE_SYS
	mov	sp, r4
	cps	#CPSR_MODE_SVC

	pop     {r4-r12,pc}	/* Match the push in tee_svc_enter_user_mode()*/
END_FUNC tee_svc_unwind_enter_user_mode

/*
 * uint32_t tee_svc_do_call(struct thread_svc_regs *regs, tee_svc_func func);
 *
 * Called from tee_svc_handler()
 */
FUNC tee_svc_do_call , :
	push	{r7-r9, lr}
	mov	r7, sp
	mov	r8, r0
	mov	r9, r1
	ldr	r5, [r8, #THREAD_SVC_REG_R5_OFFS]
	ldr	r6, [r8, #THREAD_SVC_REG_R6_OFFS]

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
	mov     r0, #0	/* Let tee_svc_copy_from_user() lookup the session */
	mov     r1, sp
	mov     r2, r5
	mov     r3, r6, lsl #2
	ldr     lr, =tee_svc_copy_from_user
	blx     lr

	/* If copy failed return the error */
	cmp     r0, #0
	bne     .Lret

.Lno_args:
	/* Load arguments to function */
	add	lr, r8, #THREAD_SVC_REG_R0_OFFS
	ldm	lr, {r0-r3}
	blx	r9
.Lret:
	mov	sp, r7
	pop	{r7-r9, pc}
END_FUNC tee_svc_do_call

/*
 * User space sees this function as:
 * void tee_svc_sys_return(uint32_t ret) __noreturn;
 *
 * But internally the function depends on being called from
 * tee_svc_do_call() with pointer to the struct thread_svc_regs saved by
 * thread_svc_handler() in r8. The argument ret is already in r0 so we
 * don't touch that and let it propagate as return value of the called
 * tee_svc_unwind_enter_user_mode().
 */
FUNC tee_svc_sys_return , :
	mov	r1, #0	/* panic = false */
	mov	r2, #0	/* panic_code = 0 */
	mov	r3, r8
	b	tee_svc_sys_return_helper
END_FUNC tee_svc_sys_return

/*
 * User space sees this function as:
 * void tee_svc_sys_panic(uint32_t code) __noreturn;
 *
 * But internally the function depends on being called from
 * tee_svc_do_call() with pointer to the struct thread_svc_regs saved by
 * thread_svc_handler() in r8.
 */
FUNC tee_svc_sys_panic , :
	mov	r1, #1	/* panic = true */
	mov	r2, r0	/* panic_code = 0 */
	mov	r3, r8
	ldr	r0, =TEE_ERROR_TARGET_DEAD
	b	tee_svc_sys_return_helper
END_FUNC tee_svc_sys_panic
