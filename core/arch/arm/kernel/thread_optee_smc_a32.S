/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <arm.h>
#include <asm.S>
#include <keep.h>
#include <kernel/thread_defs.h>
#include <kernel/unwind.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

.arch_extension sec

LOCAL_FUNC vector_std_smc_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	push	{r4-r7}
	bl	thread_handle_std_smc
	add	sp, sp, #(4 * 4)
	/*
	 * Normally thread_handle_std_smc() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_smc()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
	mov	r1, r0
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
	bl	itr_core_handler
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

FUNC thread_std_smc_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	bl	__thread_std_smc_entry
	mov	r4, r0	/* Save return value for later */

	/* Disable interrupts before switching to temporary stack */
	cpsid	aif
	bl	thread_get_tmp_sp
	mov	sp, r0

	bl	thread_state_free

	ldr	r0, =TEESMC_OPTEED_RETURN_CALL_DONE
	mov	r1, r4
	mov	r2, #0
	mov	r3, #0
	mov	r4, #0
	smc	#0
	b	.	/* SMC should not return */
UNWIND(	.fnend)
END_FUNC thread_std_smc_entry

/* void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]) */
FUNC thread_rpc , :
UNWIND(	.fnstart)
	push	{r0, lr}
UNWIND(	.save	{r0, lr})

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
	pop	{r12, lr}		/* Get pointer to rv[] */
	stm	r12, {r0-r3}		/* Store r0-r3 into rv[] */
	bx	lr
UNWIND(	.fnend)
END_FUNC thread_rpc
KEEP_PAGER thread_rpc

/*
 * void thread_foreign_intr_exit(uint32_t thread_index)
 *
 * This function is jumped to at the end of macro foreign_intr_handler().
 * The current thread as indicated by @thread_index has just been
 * suspended.  The job here is just to inform normal world the thread id to
 * resume when returning.
 */
FUNC thread_foreign_intr_exit , :
	mov	r4, r0
	ldr	r0, =TEESMC_OPTEED_RETURN_CALL_DONE
	ldr	r1, =OPTEE_SMC_RETURN_RPC_FOREIGN_INTR
	mov	r2, #0
	mov	r3, #0
	smc	#0
	b	.	/* SMC should not return */
END_FUNC thread_foreign_intr_exit
