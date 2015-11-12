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

#include <asm.S>
#include <arm64_macros.S>
#include <arm64.h>
#include <sm/teesmc.h>
#include <sm/teesmc_opteed_macros.h>
#include <sm/teesmc_opteed.h>
#include <kernel/thread_defs.h>
#include <kernel/thread.h>
#include "thread_private.h"

	.macro get_thread_ctx core_local, res, tmp0, tmp1
		ldr	w\tmp0, [\core_local, \
				#THREAD_CORE_LOCAL_CURR_THREAD_OFFSET]
		adr	x\res, threads
		mov	x\tmp1, #THREAD_CTX_SIZE
		madd	x\res, x\tmp0, x\tmp1, x\res
	.endm

	.section .text.thread_asm
LOCAL_FUNC vector_std_smc_entry , :
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X_OFFS(0), 0, 7
	mov	x0, sp
	bl	thread_handle_std_smc
	/*
	 * Normally thread_handle_std_smc() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_smc()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
	load_xregs sp, THREAD_SMC_ARGS_X_OFFS(0), 1, 8
	add	sp, sp, #THREAD_SMC_ARGS_SIZE
	ldr	x0, =TEESMC_OPTEED_RETURN_CALL_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_std_smc_entry

LOCAL_FUNC vector_fast_smc_entry , :
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X_OFFS(0), 0, 7
	mov	x0, sp
	bl	thread_handle_fast_smc
	load_xregs sp, THREAD_SMC_ARGS_X_OFFS(0), 1, 8
	add	sp, sp, #THREAD_SMC_ARGS_SIZE
	ldr	x0, =TEESMC_OPTEED_RETURN_CALL_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_fast_smc_entry

LOCAL_FUNC vector_fiq_entry , :
	/* Secure Monitor received a FIQ and passed control to us. */
	bl	thread_check_canaries
	adr	x16, thread_fiq_handler_ptr
	ldr	x16, [x16]
	blr	x16
	ldr	x0, =TEESMC_OPTEED_RETURN_FIQ_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_fiq_entry

LOCAL_FUNC vector_cpu_on_entry , :
	adr	x16, thread_cpu_on_handler_ptr
	ldr	x16, [x16]
	blr	x16
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_ON_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_cpu_on_entry

LOCAL_FUNC vector_cpu_off_entry , :
	adr	x16, thread_cpu_off_handler_ptr
	ldr	x16, [x16]
	blr	x16
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_OFF_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_cpu_off_entry

LOCAL_FUNC vector_cpu_suspend_entry , :
	adr	x16, thread_cpu_suspend_handler_ptr
	ldr	x16, [x16]
	blr	x16
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_SUSPEND_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_cpu_suspend_entry

LOCAL_FUNC vector_cpu_resume_entry , :
	adr	x16, thread_cpu_resume_handler_ptr
	ldr	x16, [x16]
	blr	x16
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_RESUME_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_cpu_resume_entry

LOCAL_FUNC vector_system_off_entry , :
	adr	x16, thread_system_off_handler_ptr
	ldr	x16, [x16]
	blr	x16
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_SYSTEM_OFF_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_system_off_entry

LOCAL_FUNC vector_system_reset_entry , :
	adr	x16, thread_system_reset_handler_ptr
	ldr	x16, [x16]
	blr	x16
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_SYSTEM_RESET_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_system_reset_entry

/*
 * Vector table supplied to ARM Trusted Firmware (ARM-TF) at
 * initialization.
 *
 * Note that ARM-TF depends on the layout of this vector table, any change
 * in layout has to be synced with ARM-TF.
 */
FUNC thread_vector_table , :
	b	vector_std_smc_entry
	b	vector_fast_smc_entry
	b	vector_cpu_on_entry
	b	vector_cpu_off_entry
	b	vector_cpu_resume_entry
	b	vector_cpu_suspend_entry
	b	vector_fiq_entry
	b	vector_system_off_entry
	b	vector_system_reset_entry
END_FUNC thread_vector_table


/* void thread_resume(struct thread_ctx_regs *regs) */
FUNC thread_resume , :
	load_xregs x0, THREAD_CTX_REGS_SP_OFFSET, 1, 3
	mov	sp, x1
	msr	elr_el1, x2
	msr	spsr_el1, x3
	load_xregs x0, THREAD_CTX_REGS_X_OFFSET(1), 1, 30
	ldr	x0, [x0, THREAD_CTX_REGS_X_OFFSET(0)]
	eret
END_FUNC thread_resume

FUNC thread_std_smc_entry , :
	/* pass x0-x7 in a struct thread_smc_args */
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X_OFFS(0), 0, 7
	mov	x0, sp

	/* Call the registered handler */
	bl	__thread_std_smc_entry

	/*
	 * Load the returned x0-x3 into preserved registers and skip the
	 * "returned" x4-x7 since they will not be returned to normal
	 * world.
	 */
	load_xregs sp, THREAD_SMC_ARGS_X_OFFS(0), 20, 23
	add	sp, sp, #THREAD_SMC_ARGS_SIZE

	/* Disable interrupts before switching to temporary stack */
	msr	daifset, #(DAIFBIT_FIQ | DAIFBIT_IRQ)
	bl	thread_get_tmp_sp
	mov	sp, x0

	bl	thread_state_free

	ldr	x0, =TEESMC_OPTEED_RETURN_CALL_DONE
	mov	x1, x20
	mov	x2, x21
	mov	x3, x22
	mov	x4, x23
	smc	#0
	b	.	/* SMC should not return */
END_FUNC thread_std_smc_entry

/* void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]) */
FUNC thread_rpc , :
	/* Read daif and create an SPSR */
	mrs	x1, daif
	orr	x1, x1, #(SPSR_64_MODE_EL1 << SPSR_64_MODE_EL_SHIFT)

	msr	daifset, #DAIFBIT_ALL
	push	x0, xzr
	push	x1, x30
	bl	thread_get_ctx_regs
	ldr	x30, [sp, #8]
	store_xregs x0, THREAD_CTX_REGS_X_OFFSET(19), 19, 30
	mov	x19, x0

	bl	thread_get_tmp_sp
	pop	x1, xzr		/* Match "push x1, x30" above */
	mov	x2, sp
	str	x2, [x19, #THREAD_CTX_REGS_SP_OFFSET]
	ldr	x20, [sp]	/* Get pointer to rv[] */
	mov	sp, x0		/* Switch to tmp stack */

	adr	x2, .thread_rpc_return
	mov	w0, #THREAD_FLAGS_COPY_ARGS_ON_RETURN
	bl	thread_state_suspend
	mov	x4, x0		/* Supply thread index */
	ldr	w0, =TEESMC_OPTEED_RETURN_CALL_DONE
	load_wregs x20, 0, 1, 3	/* Load rv[] into x0-x2 */
	smc	#0
	b	.		/* SMC should not return */

.thread_rpc_return:
	/*
	 * At this point has the stack pointer been restored to the value
	 * stored in THREAD_CTX above.
	 *
	 * Jumps here from thread_resume above when RPC has returned. The
	 * IRQ and FIQ bits are restored to what they where when this
	 * function was originally entered.
	 */
	pop	x4, xzr		/* Get pointer to rv[] */
	store_wregs x4, 0, 0, 2	/* Store x0-x2 into rv[] */
	ret
END_FUNC thread_rpc

FUNC thread_init_vbar , :
	adr	x0, thread_vect_table
	msr	vbar_el1, x0
	ret
END_FUNC thread_init_vbar

/*
 * uint32_t __thread_enter_user_mode(unsigned long a0, unsigned long a1,
 *               unsigned long a2, unsigned long a3, unsigned long user_sp,
 *               unsigned long user_func, unsigned long spsr,
 *               uint32_t *exit_status0, uint32_t *exit_status1)
 *
 */
FUNC __thread_enter_user_mode , :
	ldr	x8, [sp]
	/*
	 * Create the and fill in the struct thread_user_mode_rec
	 */
	sub	sp, sp, #THREAD_USER_MODE_REC_SIZE
	store_xregs sp, THREAD_USER_MODE_REC_EXIT_STATUS0_PTR_OFFSET, 7, 8
	store_xregs sp, THREAD_USER_MODE_REC_X_OFFSET(19), 19, 30

	/*
	 * Switch to SP_EL1
	 * Disable exceptions
	 * Save kern sp in x19
	 */
	msr	daifset, #DAIFBIT_ALL
	mov	x19, sp
	msr	spsel, #1

	/*
	 * Save the kernel stack pointer in the thread context
	 */
	/* get pointer to current thread context */
	get_thread_ctx sp, 21, 20, 22
	/* save kernel stack pointer */
	str	x19, [x21, #THREAD_CTX_KERN_SP_OFFSET]

	/*
	 * Initialize SPSR, ELR_EL1, and SP_EL0 to enter user mode
	 */
	msr	spsr_el1, x6
	/* Set user sp */
	mov	x13, x4		/* Used when running TA in Aarch32 */
	msr	sp_el0, x4	/* Used when running TA in Aarch64 */
	/* Set user function */
	msr	elr_el1, x5

	/* Jump into user mode */
	eret
END_FUNC __thread_enter_user_mode

/*
 * void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
 * 		uint32_t exit_status1);
 * See description in thread.h
 */
FUNC thread_unwind_user_mode , :
	/* Store the exit status */
	ldp	x3, x4, [sp, #THREAD_USER_MODE_REC_EXIT_STATUS0_PTR_OFFSET]
	str	w1, [x3]
	str	w2, [x4]
	/* Restore x19..x30 */
	load_xregs sp, THREAD_USER_MODE_REC_X_OFFSET(19), 19, 30
	add	sp, sp, #THREAD_USER_MODE_REC_SIZE
	/* Return from the call of thread_enter_user_mode() */
	ret
END_FUNC thread_unwind_user_mode

	/*
	 * This macro verifies that the a given vector doesn't exceed the
	 * architectural limit of 32 instructions. This is meant to be placed
	 * immedately after the last instruction in the vector. It takes the
	 * vector entry as the parameter
	 */
	.macro check_vector_size since
	  .if (. - \since) > (32 * 4)
	    .error "Vector exceeds 32 instructions"
	  .endif
	.endm


	.align	11
LOCAL_FUNC thread_vect_table , :
	/* -----------------------------------------------------
	 * EL1 with SP0 : 0x0 - 0x180
	 * -----------------------------------------------------
	 */
	.align	7
sync_el1_sp0:
	store_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	b	el1_sync_abort
	check_vector_size sync_el1_sp0

	.align	7
irq_el1_sp0:
	store_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	b	elx_irq
	check_vector_size irq_el1_sp0

	.align	7
fiq_el1_sp0:
	store_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	b	elx_fiq
	check_vector_size fiq_el1_sp0

	.align	7
SErrorSP0:
	b	SErrorSP0
	check_vector_size SErrorSP0

	/* -----------------------------------------------------
	 * Current EL with SPx: 0x200 - 0x380
	 * -----------------------------------------------------
	 */
	.align	7
SynchronousExceptionSPx:
	b	SynchronousExceptionSPx
	check_vector_size SynchronousExceptionSPx

	.align	7
IrqSPx:
	b	IrqSPx
	check_vector_size IrqSPx

	.align	7
FiqSPx:
	b	FiqSPx
	check_vector_size FiqSPx

	.align	7
SErrorSPx:
	b	SErrorSPx
	check_vector_size SErrorSPx

	/* -----------------------------------------------------
	 * Lower EL using AArch64 : 0x400 - 0x580
	 * -----------------------------------------------------
	 */
	.align	7
el0_sync_a64:
	b	el0_sync_a64
	check_vector_size el0_sync_a64

	.align	7
IrqA64:
	b	IrqA64
	check_vector_size IrqA64

	.align	7
FiqA64:
	b	FiqA64
	check_vector_size FiqA64

	.align	7
SErrorA64:
	b   	SErrorA64
	check_vector_size SErrorA64

	/* -----------------------------------------------------
	 * Lower EL using AArch32 : 0x0 - 0x180
	 * -----------------------------------------------------
	 */
	.align	7
el0_sync_a32:
	store_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	mrs	x2, esr_el1
	mrs	x3, sp_el0
	lsr	x2, x2, #ESR_EC_SHIFT
	cmp	x2, #ESR_EC_AARCH32_SVC
	b.eq	el0_sync_a32_svc
	b	el0_sync_abort
	check_vector_size el0_sync_a32

	.align	7
el0_irq_a32:
	store_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	b	elx_irq
	check_vector_size el0_irq_a32

	.align	7
el0_fiq_a32:
	store_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	b	elx_fiq
	check_vector_size el0_fiq_a32

	.align	7
SErrorA32:
	b	SErrorA32
	check_vector_size SErrorA32

END_FUNC thread_vect_table

LOCAL_FUNC el0_sync_a32_svc , :
	/* get pointer to current thread context in x0 */
	get_thread_ctx sp, 0, 1, 2
	/* load saved kernel sp */
	ldr	x0, [x0, #THREAD_CTX_KERN_SP_OFFSET]
	/* Keep pointer to initial recod in x1 */
	mov	x1, sp
	/* Switch to SP_EL0 and restore kernel sp */
	msr	spsel, #0
	mov	sp, x0
	/* Restore x0-x3 */
	ldp	x2, x3, [x1, #THREAD_CORE_LOCAL_X_OFFSET(2)]
	ldp	x0, x1, [x1, #THREAD_CORE_LOCAL_X_OFFSET(0)]

	/* Prepare the argument for the handler */
	sub	sp, sp, #THREAD_SVC_REG_SIZE
	store_xregs sp, THREAD_SVC_REG_X_OFFS(0), 0, 14
	mrs	x0, elr_el1
	mrs	x1, spsr_el1
	store_xregs sp, THREAD_SVC_REG_ELR_OFFS, 0, 1
	mov	x0, sp

	/*
	 * Unmask FIQ, Serror, and debug exceptions since we have nothing
	 * left in sp_el1. Note that the SVC handler is excepted to
	 * re-enable IRQs by itself.
	 */
	msr	daifclr, #(DAIFBIT_FIQ | DAIFBIT_ABT | DAIFBIT_DBG)

	/* Call the registered handler */
	adr	x16, thread_svc_handler_ptr
	ldr	x16, [x16]
	blr	x16

	/* Mask all maskable exceptions since we're switching back to sp_el1 */
	msr	daifset, #DAIFBIT_ALL

	/* Save kernel sp we'll have after the add below */
	msr	spsel, #1
	get_thread_ctx sp, 0, 1, 2
	msr	spsel, #0
	add	x1, sp, #THREAD_SVC_REG_SIZE
	str	x1, [x0, #THREAD_CTX_KERN_SP_OFFSET]

	/* Restore registers to the required state and return*/
	load_xregs sp, THREAD_SVC_REG_ELR_OFFS, 0, 1
	msr	elr_el1, x0
	msr	spsr_el1, x1
	load_xregs sp, THREAD_SVC_REG_X_OFFS(0), 0, 14
	add	sp, sp, #THREAD_SVC_REG_SIZE

	eret
END_FUNC el0_sync_a32_svc

LOCAL_FUNC el1_sync_abort , :
	mov	x0, sp
	msr	spsel, #0

	/* Update core local flags */
	ldr	w1, [x0, #THREAD_CORE_LOCAL_FLAGS_OFFSET]
	lsl	w1, w1, #THREAD_CLF_SAVED_SHIFT
	orr	w1, w1, #THREAD_CLF_ABORT
	str	w1, [x0, #THREAD_CORE_LOCAL_FLAGS_OFFSET]

	/*
	 * Check if we should initialize SP_EL0 or use it as is (recursive
	 * aborts).
	 */
	tst	w1, #(THREAD_CLF_ABORT << THREAD_CLF_SAVED_SHIFT)
	mov	x3, sp		/* Save original sp unconditionally */
	beq	.keep_sp
	ldr	x2, [x0, #THREAD_CORE_LOCAL_ABT_STACK_VA_END_OFFSET]
	mov	sp, x2
.keep_sp:

	/*
	 * Save state on stack
	 */
	sub	sp, sp, #THREAD_ABT_REGS_SIZE
	mrs	x2, spsr_el1
	/* Store spsr, sp_el0 */
	stp	x2, x3, [sp, #THREAD_ABT_REG_SPSR_OFFS]
	/* Store original x0, x1 */
	ldp	x2, x3, [x0, #THREAD_CORE_LOCAL_X_OFFSET(0)]
	stp	x2, x3, [sp, #THREAD_ABT_REG_X_OFFS(0)]
	/* Store original x2, x3 and x4 to x29 */
	ldp	x2, x3, [x0, #THREAD_CORE_LOCAL_X_OFFSET(2)]
	store_xregs sp, THREAD_ABT_REG_X_OFFS(2), 2, 29
	/* Store x30, elr_el1 */
	mrs	x0, elr_el1
	stp	x30, x0, [sp, #THREAD_ABT_REG_X_OFFS(30)]

	/*
	 * Call handler
	 */
	mov	x0, #0
	mov	x1, sp
	bl	thread_handle_abort

	/*
	 * Restore state from stack
	 */
	/* Load x30, elr_el1 */
	ldp	x30, x0, [sp, #THREAD_ABT_REG_X_OFFS(30)]
	msr	elr_el1, x0
	/* Load x0 to x29 */
	load_xregs sp, THREAD_ABT_REG_X_OFFS(0), 0, 29
	/* Switch to SP_EL1 */
	msr	spsel, #1
	/* Save x0 to x3 in CORE_LOCAL */
	store_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	/* Restore spsr_el1 and sp_el0 */
	mrs	x3, sp_el0
	ldp	x0, x1, [x3, #THREAD_ABT_REG_SPSR_OFFS]
	msr	spsr_el1, x0
	msr	sp_el0, x1

	/* Update core local flags */
	ldr	w0, [sp, #THREAD_CORE_LOCAL_FLAGS_OFFSET]
	lsr	w0, w0, #THREAD_CLF_SAVED_SHIFT
	str	w0, [sp, #THREAD_CORE_LOCAL_FLAGS_OFFSET]

	/* Restore x0 to x3 */
	load_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3

	/* Return from exception */
	eret
END_FUNC el1_sync_abort

	/* sp_el0 in x3 */
LOCAL_FUNC el0_sync_abort , :
	/* load abt_stack_va_end */
	ldr	x1, [sp, #THREAD_CORE_LOCAL_ABT_STACK_VA_END_OFFSET]
	/* Keep pointer to initial record in x0 */
	mov	x0, sp
	/* Switch to SP_EL0 */
	msr	spsel, #0
	mov	sp, x1
	sub	sp, sp, #THREAD_ABT_REGS_SIZE
	mrs	x2, spsr_el1
	/* Store spsr, sp_el0 */
	stp	x2, x3, [sp, #THREAD_ABT_REG_SPSR_OFFS]
	/* Store original x0, x1 */
	ldp	x2, x3, [x0, #THREAD_CORE_LOCAL_X_OFFSET(0)]
	stp	x2, x3, [sp, #THREAD_ABT_REG_X_OFFS(0)]
	/* Store original x2, x3 and x4 to x29 */
	ldp	x2, x3, [x0, #THREAD_CORE_LOCAL_X_OFFSET(2)]
	store_xregs sp, THREAD_ABT_REG_X_OFFS(2), 2, 29
	/* Store x30, elr_el1 */
	mrs	x0, elr_el1
	stp	x30, x0, [sp, #THREAD_ABT_REG_X_OFFS(30)]
	/* Call handler */
	mov	x0, #0
	mov	x1, sp
	bl	thread_handle_abort
	/* Load x30, elr_el1 */
	ldp	x30, x0, [sp, #THREAD_ABT_REG_X_OFFS(30)]
	msr	elr_el1, x0
	/* Load x0 to x29 */
	load_xregs sp, THREAD_ABT_REG_X_OFFS(0), 0, 29
	/* Switch to SP_EL1 */
	msr	spsel, #1
	/* Save x0 to x3 in EL1_REC */
	store_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	/* Restore spsr_el1 and sp_el0 */
	mrs	x3, sp_el0
	ldp	x0, x1, [x3, #THREAD_ABT_REG_SPSR_OFFS]
	msr	spsr_el1, x0
	msr	sp_el0, x1
	/* Restore x0 to x3 */
	load_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3
	/* Return from exception */
	eret
END_FUNC el0_sync_abort

/*
 * struct elx_itr_rec {
 * 	uint64_t x[19 - 4]; x4..x18
 * 	uint64_t init_rec;
 * 	uint64_t pad;
 * 	uint64_t lr;
 * 	uint64_t sp_el0;
 * };
 */
#define ELX_ITR_REC_X_OFFSET(x)		(8 * ((x) - 4))
#define ELX_ITR_REC_INIT_REC_OFFSET	(8 + ELX_ITR_REC_X_OFFSET(19))
#define ELX_ITR_REC_PAD_OFFSET		(8 + ELX_ITR_REC_INIT_REC_OFFSET)
#define ELX_ITR_REC_LR_OFFSET		(8 + ELX_ITR_REC_PAD_OFFSET)
#define ELX_ITR_REC_SP_EL0_OFFSET	(8 + ELX_ITR_REC_LR_OFFSET)
#define ELX_ITR_REC_SIZE		(8 + ELX_ITR_REC_SP_EL0_OFFSET)

LOCAL_FUNC elx_irq , :
	/* load tmp_stack_va_end */
	ldr	x1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END_OFFSET]
	/* Keep pointer to initial record in x0 */
	mov	x0, sp
	/* Keep original SP_EL0 */
	mrs	x2, sp_el0
	/* Switch to SP_EL0 */
	msr	spsel, #0
	mov	sp, x1

	/*
	 * Save registers on stack that can be corrupted by a call to
	 * thread_get_ctx_regs().
	 */
	/* Make room for struct elx_itr_rec */
	sub	sp, sp, #ELX_ITR_REC_SIZE
	/* Store x4..x18 */
	store_xregs sp, ELX_ITR_REC_X_OFFSET(4), 4, 18
	/* Store pointer to initial record */
	str	x0, [sp, #ELX_ITR_REC_INIT_REC_OFFSET]
	/* Store lr and original sp_el0 */
	stp	x30, x2, [sp, #ELX_ITR_REC_LR_OFFSET]

	/*
	 * Get pointer to struct thread_ctx_regs and store context
	 */
	bl	thread_get_ctx_regs
	/* Restore lr and original sp_el0 */
	ldp	x30, x1, [sp, #ELX_ITR_REC_LR_OFFSET]
	/* Store original sp_el0 */
	str	x1, [x0, #THREAD_CTX_REGS_SP_OFFSET]
	/* Restore x4..x18 */
	load_xregs sp, ELX_ITR_REC_X_OFFSET(4), 4, 18
	/* store x4..x30 */
	store_xregs x0, THREAD_CTX_REGS_X_OFFSET(4), 4, 30
	/* get pointer to initial record */
	ldr	x4, [sp, #ELX_ITR_REC_INIT_REC_OFFSET]
	/* Load original x0..x3 into x10..x13 */
	load_xregs x4, THREAD_CORE_LOCAL_X_OFFSET(0), 10, 13
	/* Save original x0..x3 */
	store_xregs x0, THREAD_CTX_REGS_X_OFFSET(0), 10, 13

	/* Remove struct elx_itr_rec from stack */
	add	sp, sp, #ELX_ITR_REC_SIZE

	/*
	 * Mark current thread as suspended
	 */
	mov	w0, #THREAD_FLAGS_EXIT_ON_IRQ
	mrs	x1, spsr_el1
	mrs	x2, elr_el1
	bl	thread_state_suspend
	mov	w4, w0		/* Supply thread index */

	ldr	w0, =TEESMC_OPTEED_RETURN_CALL_DONE
	ldr	w1, =TEESMC_RETURN_RPC_IRQ
	mov	w2, #0
	mov	w3, #0
	/* w4 is already filled in above */
	smc	#0
	b	.	/* SMC should not return */
END_FUNC elx_irq

LOCAL_FUNC elx_fiq , :
	/* load tmp_stack_va_end */
	ldr	x1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END_OFFSET]
	/* Keep pointer to initial record in x0 */
	mov	x0, sp
	/* Keep original SP_EL0 */
	mrs	x2, sp_el0
	/* Switch to SP_EL0 */
	msr	spsel, #0
	mov	sp, x1

	/*
	 * Save registers on stack that can be corrupted by a call to
	 * a C function
	 */
	/* Make room for struct elx_itr_rec */
	sub	sp, sp, #ELX_ITR_REC_SIZE
	/* Store x4..x18 */
	store_xregs sp, ELX_ITR_REC_X_OFFSET(4), 4, 18
	/* Store lr and original sp_el0 */
	stp	x30, x2, [sp, #ELX_ITR_REC_LR_OFFSET]

	bl	thread_check_canaries
	adr	x16, thread_fiq_handler_ptr
	ldr	x16, [x16]
	blr	x16

	/*
	 * Restore registers
	 */
	/* Restore x4..x18 */
	load_xregs sp, ELX_ITR_REC_X_OFFSET(4), 4, 18
	/* Load  lr and original sp_el0 */
	ldp	x30, x2, [sp, #ELX_ITR_REC_LR_OFFSET]
	/* Restore sp_el0 */
	mov	sp, x2
	/* Switch back to sp_el1 */
	msr	spsel, #1
	/* Restore x0..x3 */
	load_xregs sp, THREAD_CORE_LOCAL_X_OFFSET(0), 0, 3

	/* Return from exception */
	eret
END_FUNC elx_fiq
