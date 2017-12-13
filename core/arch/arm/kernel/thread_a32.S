/*
 * Copyright (c) 2016-2017, Linaro Limited
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

#include <arm32_macros.S>
#include <arm.h>
#include <asm-defines.h>
#include <asm.S>
#include <keep.h>
#include <kernel/abort.h>
#include <kernel/thread_defs.h>
#include <kernel/unwind.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

#include "thread_private.h"

LOCAL_FUNC vector_std_smc_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	push	{r0-r7}
	mov	r0, sp
	bl	thread_handle_std_smc
	/*
	 * Normally thread_handle_std_smc() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_smc()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
	pop	{r1-r8}
	ldr	r0, =TEESMC_OPTEED_RETURN_CALL_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_std_smc_entry

LOCAL_FUNC vector_fast_smc_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	push	{r0-r7}
	mov	r0, sp
	bl	thread_handle_fast_smc
	pop	{r1-r8}
	ldr	r0, =TEESMC_OPTEED_RETURN_CALL_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_fast_smc_entry

LOCAL_FUNC vector_fiq_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
 	/* Secure Monitor received a FIQ and passed control to us. */
	bl	thread_check_canaries
	ldr	lr, =thread_nintr_handler_ptr
 	ldr	lr, [lr]
 	blx	lr
	mov	r1, r0
	ldr	r0, =TEESMC_OPTEED_RETURN_FIQ_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_fiq_entry

LOCAL_FUNC vector_cpu_on_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	ldr	lr, =thread_cpu_on_handler_ptr
	ldr	lr, [lr]
	blx	lr
	mov	r1, r0
	ldr	r0, =TEESMC_OPTEED_RETURN_ON_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_cpu_on_entry

LOCAL_FUNC vector_cpu_off_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	ldr	lr, =thread_cpu_off_handler_ptr
	ldr	lr, [lr]
	blx	lr
	mov	r1, r0
	ldr	r0, =TEESMC_OPTEED_RETURN_OFF_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_cpu_off_entry

LOCAL_FUNC vector_cpu_suspend_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	ldr	lr, =thread_cpu_suspend_handler_ptr
	ldr	lr, [lr]
	blx	lr
	mov	r1, r0
	ldr	r0, =TEESMC_OPTEED_RETURN_SUSPEND_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_cpu_suspend_entry

LOCAL_FUNC vector_cpu_resume_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	ldr	lr, =thread_cpu_resume_handler_ptr
	ldr	lr, [lr]
	blx	lr
	mov	r1, r0
	ldr	r0, =TEESMC_OPTEED_RETURN_RESUME_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_cpu_resume_entry

LOCAL_FUNC vector_system_off_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	ldr	lr, =thread_system_off_handler_ptr
	ldr	lr, [lr]
	blx	lr
	mov	r1, r0
	ldr	r0, =TEESMC_OPTEED_RETURN_SYSTEM_OFF_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_system_off_entry

LOCAL_FUNC vector_system_reset_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	ldr	lr, =thread_system_reset_handler_ptr
	ldr	lr, [lr]
	blx	lr
	mov	r1, r0
	ldr	r0, =TEESMC_OPTEED_RETURN_SYSTEM_RESET_DONE
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC vector_system_reset_entry

/*
 * Vector table supplied to ARM Trusted Firmware (ARM-TF) at
 * initialization.  Also used when compiled with the internal monitor, but
 * the cpu_*_entry and system_*_entry are not used then.
 *
 * Note that ARM-TF depends on the layout of this vector table, any change
 * in layout has to be synced with ARM-TF.
 */
FUNC thread_vector_table , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	b	vector_std_smc_entry
	b	vector_fast_smc_entry
	b	vector_cpu_on_entry
	b	vector_cpu_off_entry
	b	vector_cpu_resume_entry
	b	vector_cpu_suspend_entry
	b	vector_fiq_entry
	b	vector_system_off_entry
	b	vector_system_reset_entry
UNWIND(	.fnend)
END_FUNC thread_vector_table
KEEP_PAGER thread_vector_table

FUNC thread_set_abt_sp , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	mrs	r1, cpsr
	cps	#CPSR_MODE_ABT
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
UNWIND(	.fnend)
END_FUNC thread_set_abt_sp

FUNC thread_set_und_sp , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	mrs	r1, cpsr
	cps	#CPSR_MODE_UND
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
UNWIND(	.fnend)
END_FUNC thread_set_und_sp

FUNC thread_set_irq_sp , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	mrs	r1, cpsr
	cps	#CPSR_MODE_IRQ
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
UNWIND(	.fnend)
END_FUNC thread_set_irq_sp

FUNC thread_set_fiq_sp , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	mrs	r1, cpsr
	cps	#CPSR_MODE_FIQ
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
UNWIND(	.fnend)
END_FUNC thread_set_fiq_sp

/* void thread_resume(struct thread_ctx_regs *regs) */
FUNC thread_resume , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	add	r12, r0, #(13 * 4)	/* Restore registers r0-r12 later */

	cps	#CPSR_MODE_SYS
	ldm	r12!, {sp, lr}

	cps	#CPSR_MODE_SVC
	ldm	r12!, {r1, sp, lr}
	msr	spsr_fsxc, r1

	cps	#CPSR_MODE_SVC
	ldm	r12, {r1, r2}
	push	{r1, r2}

	ldm	r0, {r0-r12}

	/* Restore CPSR and jump to the instruction to resume at */
	rfefd	sp!
UNWIND(	.fnend)
END_FUNC thread_resume

/*
 * Disables IRQ and FIQ and saves state of thread in fiq mode which has
 * the banked r8-r12 registers, returns original CPSR.
 */
LOCAL_FUNC thread_save_state_fiq , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	mov	r9, lr

	/*
	 * Uses stack for temporary storage, while storing needed
	 * context in the thread context struct.
	 */

	mrs	r8, cpsr

	cpsid	aif			/* Disable Async abort, IRQ and FIQ */

	push	{r4-r7}
	push	{r0-r3}

	mrs	r6, cpsr		/* Save current CPSR */

	bl	thread_get_ctx_regs

	pop	{r1-r4}			/* r0-r3 pushed above */
	stm	r0!, {r1-r4}
	pop	{r1-r4}			/* r4-r7 pushed above */
	stm	r0!, {r1-r4}

	cps     #CPSR_MODE_SYS
	stm	r0!, {r8-r12}
	stm     r0!, {sp, lr}

	cps     #CPSR_MODE_SVC
	mrs     r1, spsr
	stm     r0!, {r1, sp, lr}

	/* back to fiq mode */
	orr	r6, r6, #ARM32_CPSR_FIA	/* Disable Async abort, IRQ and FIQ */
	msr	cpsr, r6		/* Restore mode */

	mov	r0, r8			/* Return original CPSR */
	bx	r9
UNWIND(	.fnend)
END_FUNC thread_save_state_fiq

/*
 * Disables IRQ and FIQ and saves state of thread, returns original
 * CPSR.
 */
LOCAL_FUNC thread_save_state , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	push	{r12, lr}
	/*
	 * Uses stack for temporary storage, while storing needed
	 * context in the thread context struct.
	 */

	mrs	r12, cpsr

	cpsid	aif			/* Disable Async abort, IRQ and FIQ */

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
        stm     r0!, {sp, lr}

        cps     #CPSR_MODE_SVC
        mrs     r1, spsr
        stm     r0!, {r1, sp, lr}

	orr	r6, r6, #ARM32_CPSR_FIA	/* Disable Async abort, IRQ and FIQ */
	msr	cpsr, r6		/* Restore mode */

	mov	r0, r5			/* Return original CPSR */
	bx	lr
UNWIND(	.fnend)
END_FUNC thread_save_state

FUNC thread_std_smc_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	/* Pass r0-r7 in a struct thread_smc_args */
	push	{r0-r7}
	mov	r0, sp
	bl	__thread_std_smc_entry
	/*
	 * Load the returned r0-r3 into preserved registers and skip the
	 * "returned" r4-r7 since they will not be returned to normal
	 * world.
	 */
	pop	{r4-r7}
	add	sp, #(4 * 4)

	/* Disable interrupts before switching to temporary stack */
	cpsid	aif
	bl	thread_get_tmp_sp
	mov	sp, r0

	bl	thread_state_free

	ldr	r0, =TEESMC_OPTEED_RETURN_CALL_DONE
	mov	r1, r4
	mov	r2, r5
	mov	r3, r6
	mov	r4, r7
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC thread_std_smc_entry


/* void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]) */
FUNC thread_rpc , :
/*
 * r0-r2 are used to pass parameters to normal world
 * r0-r5 are used to pass return vaule back from normal world
 *
 * note that r3 is used to pass "resume information", that is, which
 * thread it is that should resume.
 *
 * Since the this function is following AAPCS we need to preserve r4-r5
 * which are otherwise modified when returning back from normal world.
 */
UNWIND(	.fnstart)
	push	{r4-r5, lr}
UNWIND(	.save	{r4-r5, lr})
	push	{r0}
UNWIND(	.save	{r0})

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
	mov	r4, r0			/* Supply thread index */
	ldr	r0, =TEESMC_OPTEED_RETURN_CALL_DONE
	ldm	r5, {r1-r3}		/* Load rv[] into r0-r2 */
	smc	#0
	b	.	/* SMC should not return */

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
	stm	r12, {r0-r5}		/* Store r0-r5 into rv[] */
	pop	{r4-r5, pc}
UNWIND(	.fnend)
END_FUNC thread_rpc
KEEP_PAGER thread_rpc

FUNC thread_init_vbar , :
UNWIND(	.fnstart)
	/* Set vector (VBAR) */
	ldr	r0, =thread_vect_table
	write_vbar r0
	bx	lr
UNWIND(	.fnend)
END_FUNC thread_init_vbar
KEEP_PAGER thread_init_vbar

/*
 * Below are low level routines handling entry and return from user mode.
 *
 * thread_enter_user_mode() saves all that registers user mode can change
 * so kernel mode can restore needed registers when resuming execution
 * after the call to thread_enter_user_mode() has returned.
 * thread_enter_user_mode() doesn't return directly since it enters user
 * mode instead, it's thread_unwind_user_mode() that does the
 * returning by restoring the registers saved by thread_enter_user_mode().
 *
 * There's three ways for thread_enter_user_mode() to return to caller,
 * user TA calls utee_return, user TA calls utee_panic or through an abort.
 *
 * Calls to utee_return or utee_panic are handled as:
 * thread_svc_handler() -> tee_svc_handler() ->	tee_svc_do_call() which
 * calls syscall_return() or syscall_panic().
 *
 * These function calls returns normally except thread_svc_handler() which
 * which is an exception handling routine so it reads return address and
 * SPSR to restore from the stack. syscall_return() and syscall_panic()
 * changes return address and SPSR used by thread_svc_handler() to instead of
 * returning into user mode as with other syscalls it returns into
 * thread_unwind_user_mode() in kernel mode instead.  When
 * thread_svc_handler() returns the stack pointer at the point where
 * thread_enter_user_mode() left it so this is where
 * thread_unwind_user_mode() can operate.
 *
 * Aborts are handled in a similar way but by thread_abort_handler()
 * instead, when the pager sees that it's an abort from user mode that
 * can't be handled it updates SPSR and return address used by
 * thread_abort_handler() to return into thread_unwind_user_mode()
 * instead.
 */

/*
 * uint32_t __thread_enter_user_mode(unsigned long a0, unsigned long a1,
 *               unsigned long a2, unsigned long a3, unsigned long user_sp,
 *               unsigned long user_func, unsigned long spsr,
 *               uint32_t *exit_status0, uint32_t *exit_status1)
 *
 */
FUNC __thread_enter_user_mode , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	/*
	 * Save all registers to allow syscall_return() to resume execution
	 * as if this function would have returned. This is also used in
	 * syscall_panic().
	 *
	 * If stack usage of this function is changed
	 * thread_unwind_user_mode() has to be updated.
	 */
	push    {r4-r12,lr}

	ldr     r4, [sp, #(10 * 0x4)]   /* user stack pointer */
	ldr     r5, [sp, #(11 * 0x4)]   /* user function */
	ldr     r6, [sp, #(12 * 0x4)]   /* spsr */

	/*
	 * Set the saved Processors Status Register to user mode to allow
	 * entry of user mode through movs below.
	 */
	msr     spsr_cxsf, r6
	
	/*
	 * Save old user sp and set new user sp.
	 */
	cps	#CPSR_MODE_SYS
	mov	r6, sp
	mov     sp, r4
	cps	#CPSR_MODE_SVC
	push	{r6,r7}

	/*
	* Don't allow return from this function, return is done through
	* thread_unwind_user_mode() below.
	*/
	mov     lr, #0
	/* Call the user function with its arguments */
	movs    pc, r5
UNWIND(	.fnend)
END_FUNC __thread_enter_user_mode

/*
 * void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
 *              uint32_t exit_status1);
 * See description in thread.h
 */
FUNC thread_unwind_user_mode , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	ldr     ip, [sp, #(15 * 0x4)]   /* &ctx->panicked */
	str	r1, [ip]
	ldr     ip, [sp, #(16 * 0x4)]   /* &ctx->panic_code */
	str	r2, [ip]

	/* Restore old user sp */
	pop	{r4,r7}
	cps	#CPSR_MODE_SYS
	mov	sp, r4
	cps	#CPSR_MODE_SVC

	pop     {r4-r12,pc}	/* Match the push in thread_enter_user_mode()*/
UNWIND(	.fnend)
END_FUNC thread_unwind_user_mode

/* The handler of native interrupt. */
.macro	native_intr_handler mode:req
	.ifc	\mode\(),irq
	/*
	 * Foreign interrupts should be masked.
	 * For GICv2, IRQ is for foreign interrupt and already masked by
	 * hardware in FIQ mode which is used for native interrupt.
	 * For GICv3, FIQ is for foreign interrupt. It's not masked by hardware
	 * in IRQ mode which is used for natvie interrupt.
	 */
	cpsid	f
	.endif
	/*
	 * FIQ and IRQ have a +4 offset for lr compared to preferred return
	 * address
	 */
	sub     lr, lr, #4

	/*
	 * We're always saving {r0-r3}. In IRQ mode we're saving r12 also.
	 * In FIQ mode we're saving the banked fiq registers {r8-r12} FIQ
	 * because the secure monitor doesn't save those. The treatment of
	 * the banked fiq registers is somewhat analogous to the lazy save
	 * of VFP registers.
	 */
	.ifc	\mode\(),fiq
	push	{r0-r3, r8-r12, lr}
	.else
	push	{r0-r3, r12, lr}
	.endif
	bl	thread_check_canaries
	ldr	lr, =thread_nintr_handler_ptr
	ldr	lr, [lr]
	blx	lr
	.ifc	\mode\(),fiq
	pop	{r0-r3, r8-r12, lr}
	.else
	pop	{r0-r3, r12, lr}
	.endif
	movs	pc, lr
.endm

/* The handler of foreign interrupt. */
.macro foreign_intr_handler mode:req
	.ifc	\mode\(),irq
	/*
	 * Disable FIQ if the foreign interrupt is sent as IRQ.
	 * IRQ mode is set up to use tmp stack so FIQ has to be
	 * disabled before touching the stack. We can also assign
	 * SVC sp from IRQ sp to get SVC mode into the state we
	 * need when doing the SMC below.
	 * If it is sent as FIQ, the IRQ has already been masked by hardware
	 */
	cpsid	f
	.endif
	sub	lr, lr, #4
	push	{lr}
	push	{r12}

	.ifc	\mode\(),fiq
	bl	thread_save_state_fiq
	.else
	bl	thread_save_state
	.endif

	mov	r0, #THREAD_FLAGS_EXIT_ON_FOREIGN_INTR
	mrs	r1, spsr
	pop	{r12}
	pop	{r2}
	blx	thread_state_suspend
	mov	r4, r0		/* Supply thread index */

	/*
	 * Switch to SVC mode and copy current stack pointer as it already
	 * is the tmp stack.
	 */
	mov	r0, sp
	cps	#CPSR_MODE_SVC
	mov	sp, r0

	ldr	r0, =TEESMC_OPTEED_RETURN_CALL_DONE
	ldr	r1, =OPTEE_SMC_RETURN_RPC_FOREIGN_INTR
	mov	r2, #0
	mov	r3, #0
	/* r4 is already filled in above */
	smc	#0
	b	.	/* SMC should not return */
.endm

	.section .text.thread_vect_table
        .align	5
FUNC thread_vect_table , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	b	.			/* Reset			*/
	b	thread_und_handler	/* Undefined instruction	*/
	b	thread_svc_handler	/* System call			*/
	b	thread_pabort_handler	/* Prefetch abort		*/
	b	thread_dabort_handler	/* Data abort			*/
	b	.			/* Reserved			*/
	b	thread_irq_handler	/* IRQ				*/
	b	thread_fiq_handler	/* FIQ				*/

thread_und_handler:
	/*
	 * Disable both foreign and native interrupts in the thread handlers.
	 * The tee handlers can decide when the native interrupts should
	 * be enabled.
	 */
	cpsid	f	/* IRQ is already masked by the hardware */
	strd	r0, r1, [sp, #THREAD_CORE_LOCAL_R0]
	mrs	r1, spsr
	tst	r1, #CPSR_T
	subne	lr, lr, #2
	subeq	lr, lr, #4
	mov	r0, #ABORT_TYPE_UNDEF
	b	thread_abort_common

thread_dabort_handler:
	/*
	 * Disable both foreign and native interrupts in the thread handlers.
	 * The tee handlers can decide when the native interrupts should
	 * be enabled.
	 */
	cpsid	f	/* IRQ is already masked by the hardware */
	strd	r0, r1, [sp, #THREAD_CORE_LOCAL_R0]
	sub	lr, lr, #8
	mov	r0, #ABORT_TYPE_DATA
	b	thread_abort_common

thread_pabort_handler:
	/*
	 * Disable both foreign and native interrupts in the thread handlers.
	 * The tee handlers can decide when the native interrupts should
	 * be enabled.
	 */
	cpsid	f	/* IRQ is already masked by the hardware */
	strd	r0, r1, [sp, #THREAD_CORE_LOCAL_R0]
	sub	lr, lr, #4
	mov	r0, #ABORT_TYPE_PREFETCH

thread_abort_common:
	/*
	 * At this label:
	 * cpsr is in mode undef or abort
	 * sp is still pointing to struct thread_core_local belonging to
	 * this core.
	 * {r0, r1} are saved in struct thread_core_local pointed to by sp
	 * {r2-r11, ip} are untouched.
	 * r0 holds the first argument for abort_handler()
	 */

	/*
	 * Update core local flags.
	 * flags = (flags << THREAD_CLF_SAVED_SHIFT) | THREAD_CLF_ABORT;
	 */
	ldr	r1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsl	r1, r1, #THREAD_CLF_SAVED_SHIFT
	orr	r1, r1, #THREAD_CLF_ABORT

	/*
	 * Select stack and update flags accordingly
	 *
	 * Normal case:
	 * If the abort stack is unused select that.
	 *
	 * Fatal error handling:
	 * If we're already using the abort stack as noted by bit
	 * (THREAD_CLF_SAVED_SHIFT + THREAD_CLF_ABORT_SHIFT) in the flags
	 * field we're selecting the temporary stack instead to be able to
	 * make a stack trace of the abort in abort mode.
	 *
	 * r1 is initialized as a temporary stack pointer until we've
	 * switched to system mode.
	 */
	tst	r1, #(THREAD_CLF_ABORT << THREAD_CLF_SAVED_SHIFT)
	orrne	r1, r1, #THREAD_CLF_TMP /* flags |= THREAD_CLF_TMP; */
	str	r1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	ldrne	r1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	ldreq	r1, [sp, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]

	/*
	 * Store registers on stack fitting struct thread_abort_regs
	 * start from the end of the struct
	 * {r2-r11, ip}
	 * Load content of previously saved {r0-r1} and stores
	 * it up to the pad field.
	 * After this is only {usr_sp, usr_lr} missing in the struct
	 */
	stmdb	r1!, {r2-r11, ip}	/* Push on the selected stack */
	ldrd	r2, r3, [sp, #THREAD_CORE_LOCAL_R0]
	/* Push the original {r0-r1} on the selected stack */
	stmdb	r1!, {r2-r3}
	mrs	r3, spsr
	/* Push {pad, spsr, elr} on the selected stack */
	stmdb	r1!, {r2, r3, lr}

	cps	#CPSR_MODE_SYS
	str	lr, [r1, #-4]!
	str	sp, [r1, #-4]!
	mov	sp, r1

	bl	abort_handler

	mov	ip, sp
	ldr	sp, [ip], #4
	ldr	lr, [ip], #4

	/*
	 * Even if we entered via CPSR_MODE_UND, we are returning via
	 * CPSR_MODE_ABT. It doesn't matter as lr and spsr are assigned
	 * here.
	 */
	cps	#CPSR_MODE_ABT
	ldm	ip!, {r0, r1, lr}	/* r0 is pad */
	msr	spsr_fsxc, r1

	/* Update core local flags */
	ldr	r0, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsr	r0, r0, #THREAD_CLF_SAVED_SHIFT
	str	r0, [sp, #THREAD_CORE_LOCAL_FLAGS]

	ldm	ip, {r0-r11, ip}

	movs	pc, lr
	/* end thread_abort_common */

thread_svc_handler:
	/*
	 * Disable both foreign and native interrupts in the thread handlers.
	 * The tee handlers can decide when the native interrupts should
	 * be enabled.
	 */
	cpsid	f	/* IRQ is already masked by the hardware */
	push	{r0-r7, lr}
	mrs	r0, spsr
	push	{r0}
	mov	r0, sp
	bl	tee_svc_handler
	pop	{r0}
	msr	spsr_fsxc, r0
	pop	{r0-r7, lr}
	movs	pc, lr
	/* end thread_svc_handler */

thread_fiq_handler:
#if defined(CFG_ARM_GICV3)
	foreign_intr_handler	fiq
#else
	native_intr_handler	fiq
#endif
	/* end thread_fiq_handler */

thread_irq_handler:
#if defined(CFG_ARM_GICV3)
	native_intr_handler	irq
#else
	foreign_intr_handler	irq
#endif
	/* end thread_irq_handler */
UNWIND(	.fnend)
END_FUNC thread_vect_table
