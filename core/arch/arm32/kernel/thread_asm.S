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

#include <asm.S>
#include <arm32.h>
#include <arm32_macros.S>
#include <sm/teesmc.h>
#include <kernel/thread_defs.h>

FUNC thread_set_abt_sp , :
	mrs	r1, cpsr
	cps	#CPSR_MODE_ABT
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
END_FUNC thread_set_abt_sp

FUNC thread_set_irq_sp , :
	mrs	r1, cpsr
	cps	#CPSR_MODE_IRQ
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
END_FUNC thread_set_irq_sp


FUNC thread_set_fiq_sp , :
	mrs	r1, cpsr
	cps	#CPSR_MODE_FIQ
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
END_FUNC thread_set_irq_sp

FUNC thread_recv_smc_call , :
	ldr	r9, =TEESMC32_CALL_HANDLE_FIQ
	cmp	r0, r9
	bne	.recv_smc
	/*
	 * FIQ raised while in non-secure world, unmask FIQ temporarily to
	 * receive the FIQ in as it's normally recieved when secure world
	 * is active when FIQ is raised.
	 */
	cpsie	f
	nop
	nop
	nop
	nop		/* We should have received IT by now... */
	cpsid	f
	mov	r0, r1
	mov	r1, r2
	mov	r2, r3
	mov	r3, r4
	b	thread_issue_smc
.recv_smc:
	push	{r0-r7}
	mov	r0, sp
	bl	thread_handle_smc_call
	/*
	 * Normally thread_handle_smc_call() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_smc_call()
	 * hasn't switched stack (fast call, FIQ, error detected) it will
	 * do a normal "C" return.
	 */
	pop	{r0-r7}
thread_issue_smc:
	smc	#0
	b	thread_recv_smc_call	/* Next entry to secure world is here */
END_FUNC thread_recv_smc_call

/* void thread_resume(struct thread_ctx_regs *regs) */
FUNC thread_resume , :
	add	r12, r0, #(13 * 4)	/* Restore registers r0-r12 later */

	cps	#CPSR_MODE_SYS
	ldm	r12!, {r1, sp, lr}
	msr	spsr, r1

#ifdef THREAD_LOCAL_EXCEPTION_SPS
	cps	#CPSR_MODE_IRQ
	ldm	r12!, {r1, sp, lr}
	msr	spsr, r1
#endif /*THREAD_LOCAL_EXCEPTION_SPS*/

	cps	#CPSR_MODE_SVC
	ldm	r12!, {r1, sp, lr}
	msr	spsr, r1

#ifdef THREAD_LOCAL_EXCEPTION_SPS
	cps	#CPSR_MODE_ABT
	ldm	r12!, {r1, sp, lr}
	msr	spsr, r1

	cps	#CPSR_MODE_UND
	ldm	r12!, {r1, sp, lr}
	msr	spsr, r1
#endif /*THREAD_LOCAL_EXCEPTION_SPS*/

	cps	#CPSR_MODE_SVC
	ldm	r12, {r1, r2}
	push	{r1, r2}

	ldm	r0, {r0-r12}


	/* Restore CPSR and jump to the instruction to resume at */
	rfefd	sp!
END_FUNC thread_resume

/*
 * Disables IRQ and FIQ and saves state of thread, returns original
 * CPSR.
 */
LOCAL_FUNC thread_save_state , :
	push	{r12, lr}
	/*
	 * Uses stack for temporary storage, while storing needed
	 * context in the thread context struct.
	 */

	mrs	r12, cpsr

	cpsid	if			/* Disable IRQ and FIQ */

	push	{r4-r7}
	push	{r0-r3}

	mov	r5, r12			/* Save CPSR in a preserved register */
	mrs	r6, cpsr		/* Save current CPSR */

	bl	thread_get_ctx_regs

	pop	{r1-r4}			/* r0-r3 pushed above */
	stm	r0!, {r1-r4}
	pop	{r1-r4}			/* r4-r7 pushed above */
	stm	r0!, {r1-r4}
	stm	r0!, {r8-r11}

	pop	{r12, lr}
	stm	r0!, {r12}

        cps     #CPSR_MODE_SYS
        mrs     r1, spsr
        stm     r0!, {r1, sp, lr}

#ifdef THREAD_LOCAL_EXCEPTION_SPS
        cps     #CPSR_MODE_IRQ
        mrs     r1, spsr
        stm     r0!, {r1, sp, lr}
#endif /*THREAD_LOCAL_EXCEPTION_SPS*/

        cps     #CPSR_MODE_SVC
        mrs     r1, spsr
        stm     r0!, {r1, sp, lr}

#ifdef THREAD_LOCAL_EXCEPTION_SPS
        cps     #CPSR_MODE_ABT
        mrs     r1, spsr
        stm     r0!, {r1, sp, lr}

        cps     #CPSR_MODE_UND
        mrs     r1, spsr
        stm     r0!, {r1, sp, lr}
#endif /*THREAD_LOCAL_EXCEPTION_SPS*/

	msr	cpsr, r6		/* Restore mode */

	mov	r0, r5			/* Return original CPSR */
	bx	lr
END_FUNC thread_save_state

FUNC thread_stdcall_entry , :
	/* Pass r0-r7 in a struct thread_smc_args */
	push	{r0-r7}
	mov	r0, sp
	ldr	lr, =thread_stdcall_handler_ptr
	ldr	lr, [lr]
	blx	lr
	/*
	 * Load the returned r0-r3 into preserved registers and skip the
	 * "returned" r4-r7 since they will not be returned to normal
	 * world.
	 */
	pop	{r4-r7}
	add	sp, #(4 * 4)

	/* Disable interrupts before switching to temporary stack */
	cpsid	if
	bl	thread_get_tmp_sp
	mov	sp, r0

	bl	thread_state_free

	mov	r0, r4
	mov	r1, r5
	mov	r2, r6
	mov	r3, r7
	b	thread_issue_smc
END_FUNC thread_stdcall_entry


/*
 * void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS])
 */
FUNC thread_rpc , :
	push	{lr}
	push	{r0}

	bl	thread_save_state
	mov	r4, r0			/* Save original CPSR */

	/*
 	 * Switch to temporary stack and SVC mode. Save CPSR to resume into.
	 */
	bl	thread_get_tmp_sp
	ldr	r5, [sp]		/* Get pointer to rv[] */
	cps	#CPSR_MODE_SVC		/* Change to SVC mode */
	mov	sp, r0			/* Switch to tmp stack */

	mov	r0, #THREAD_FLAGS_COPY_ARGS_ON_RETURN
	mov	r1, r4			/* CPSR to restore */
	ldr	r2, =.thread_rpc_return
	bl	thread_state_suspend
	mov	r3, r0			/* Supply thread index */
	ldm	r5, {r0-r2}		/* Load rv[] into r0-r2 */
	b	thread_issue_smc

.thread_rpc_return:
	/*
	 * At this point has the stack pointer been restored to the value
	 * it had when thread_save_state() was called above.
	 *
	 * Jumps here from thread_resume above when RPC has returned. The
	 * IRQ and FIQ bits are restored to what they where when this
	 * function was originally entered.
	 */
	pop	{r12}			/* Get pointer to rv[] */
	stm	r12, {r0-r2}		/* Store r0-r2 into rv[] */
	pop	{pc}
END_FUNC thread_rpc

LOCAL_FUNC thread_fiq_handler , :
	/* FIQ has a +4 offset for lr compared to preferred return address */
	sub     lr, lr, #4
	push	{r0-r12, lr}
	bl	check_canaries
	ldr	lr, =thread_fiq_handler_ptr
	ldr	lr, [lr]
	blx	lr
	pop	{r0-r12, lr}
	movs	pc, lr
END_FUNC thread_fiq_handler

LOCAL_FUNC thread_irq_handler , :
	/*
	 * IRQ mode is set up to use tmp stack so FIQ has to be
	 * disabled before touching the stack. We can also assign
	 * SVC sp from IRQ sp to get SVC mode into the state we
	 * need when doing the SMC below.
	 */
	cpsid	f			/* Disable FIQ also */
	sub	lr, lr, #4
	push	{lr}
	push	{r12}

	bl	thread_save_state

	mov	r0, #THREAD_FLAGS_EXIT_ON_IRQ
	mrs	r1, spsr
	pop	{r12}
	pop	{r2}
	blx	thread_state_suspend
	mov	r3, r0		/* Supply thread index */

	/*
	 * Switch to SVC mode and copy current stack pointer as it already
	 * is the tmp stack.
	 */
	mov	r0, sp
	cps	#CPSR_MODE_SVC
	mov	sp, r0

	ldr	r0, =TEESMC_RETURN_RPC_IRQ
	mov	r1, #0
	mov	r2, #0
	/* r3 is already filled in above */
	b	thread_issue_smc
END_FUNC thread_irq_handler

FUNC thread_init_vbar , :
	/* Set vector (VBAR) */
	ldr	r0, =thread_vect_table
	write_vbar r0
	bx	lr
END_FUNC thread_init_vbar

LOCAL_FUNC thread_abort_handler , :
thread_abort_handler:
thread_und_handler:
	/*
	 * Switch to abort mode to use that stack instead.
	 */
	cps	#CPSR_MODE_ABT
	sub	lr, lr, #4
	push	{r0-r3, ip, lr}
	cps	#CPSR_MODE_UND
	mrs	r0, spsr
	cps	#CPSR_MODE_ABT
	push	{r0, r1}
	msr	spsr, r0	/* In case some code reads spsr directly */
	mov	r0, #THREAD_ABORT_UNDEF
	b	.thread_abort_generic

thread_dabort_handler:
	sub	lr, lr, #8
	push	{r0-r3, ip, lr}
	mrs	r0, spsr
	push	{r0, r1}
	mov	r0, #THREAD_ABORT_DATA
	b	.thread_abort_generic

thread_pabort_handler:
	sub	lr, lr, #4
	push	{r0-r3, ip, lr}
	mrs	r0, spsr
	push	{r0, r1}
	mov	r0, #THREAD_ABORT_PREFETCH
	b	.thread_abort_generic

.thread_abort_generic:
	mov	r1, sp
	ldr	lr, =thread_abort_handler_ptr;
	ldr	lr, [lr]
	blx	lr
	pop	{r0, r1}
	msr	spsr, r0
	pop	{r0-r3, ip, lr}
	movs	pc, lr
END_FUNC thread_abort_handler

LOCAL_FUNC thread_svc_handler , :
/*
 * TODO figure out an efficient way of redesigning tee_svc_syscall to allow
 * usage of this code instead.
 */
#if 0
	push	{r0-r5, lr}
	mrs	r0, spsr
	push	{r0}
	mov	r0, sp
	ldr	lr, =thread_svc_handler_ptr;
	ldr	lr, [lr]
	blx	lr
	pop	{r0}
	msr	spsr, r0
	pop	{r0-r5, lr}
	movs	pc, lr
#else
	ldr	pc, =tee_svc_syscall
#endif
END_FUNC thread_svc_handler

        .align	5
LOCAL_FUNC thread_vect_table , :
	b	.			/* Reset			*/
	b	thread_und_handler	/* Undefined instruction	*/
	b	thread_svc_handler	/* System call			*/
	b	thread_pabort_handler	/* Prefetch abort		*/
	b	thread_dabort_handler	/* Data abort			*/
	b	.			/* Reserved			*/
	b	thread_irq_handler	/* IRQ				*/
	b	thread_fiq_handler	/* FIQ				*/
END_FUNC thread_vect_table
