/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <platform_config.h>

#include <arm32_macros.S>
#include <arm.h>
#include <asm.S>
#include <ffa.h>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread_defs.h>
#include <optee_ffa.h>

FUNC thread_ffa_msg_wait , :
	mov_imm	r0, FFA_MSG_WAIT		/* FID */
	mov	r1, #FFA_TARGET_INFO_MBZ	/* Target info MBZ */
	mov	r2, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	r3, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	r4, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	r5, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	r6, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	r7, #FFA_PARAM_MBZ		/* Param MBZ */
	b	.ffa_msg_loop
END_FUNC thread_ffa_msg_wait

	/* Caller provides r1, r3-r7 params */
LOCAL_FUNC ffa_msg_send_direct_resp , :
	ldr	r0, =FFA_MSG_SEND_DIRECT_RESP_32	/* FID */
	mov	r2, #FFA_PARAM_MBZ			/* RES MBZ */

.ffa_msg_loop:
	/* Invoke SMC with caller provided parameters */
	smc	#0

	/* Store the parameters as struct thread_smc_args on stack */
	push	{r0-r7}
	mov	r0, sp

	/* parse and handle message */
	bl	thread_spmc_msg_recv

	/* Load struct thread_smc_args into registers */
	pop	{r0-r7}
	b	.ffa_msg_loop
END_FUNC ffa_msg_send_direct_resp

FUNC thread_std_smc_entry , :
UNWIND(	.cantunwind)

	push	{r4, r5} /* Pass these following the arm32 calling convention */
	ror	r4, r0, #16 /* Save target info with src and dst swapped */
	bl	__thread_std_smc_entry
	add	sp, sp, #8 /* There's nothing return, just restore the sp */
	mov	r5, r0	/* Save return value */

	/* Mask all maskable exceptions before switching to temporary stack */
	cpsid	aif
	bl	thread_get_tmp_sp
	mov	sp, r0

	bl	thread_state_free

	mov	r1, r4				/* Target info */
	mov	r3, r5				/* Return value */
	mov	r4, #FFA_PARAM_MBZ		/* Unused parameter */
	mov	r5, #FFA_PARAM_MBZ		/* Unused parameter */
	mov	r6, #FFA_PARAM_MBZ		/* Unused parameter */
	mov	r7, #FFA_PARAM_MBZ		/* Unused parameter */
	b	ffa_msg_send_direct_resp
END_FUNC thread_std_smc_entry

/* void thread_rpc(struct thread_rpc_arg *rpc_arg) */
FUNC thread_rpc , :
	push	{r0, lr}
UNWIND(	.save	{r0, lr})

	bl	thread_save_state
	mov	r4, r0			/* Save original CPSR */

	/*
	 * Switch to temporary stack and SVC mode. Save CPSR to resume into.
	 */
	bl	thread_get_tmp_sp
	ldr	r8, [sp]		/* Get pointer to rv[] */
	cps	#CPSR_MODE_SVC		/* Change to SVC mode */
	mov	sp, r0			/* Switch to tmp stack */

	mov	r0, #THREAD_FLAGS_COPY_ARGS_ON_RETURN
	mov	r1, r4			/* CPSR to restore */
	ldr	r2, =.thread_rpc_return
	bl	thread_state_suspend
	mov	r7, r0			/* Supply thread index */
	ldr	r0, =FFA_MSG_SEND_DIRECT_RESP_32
	mov	r2, #FFA_PARAM_MBZ
	mov	r3, #0			/* Error code = 0 */
	ldm	r8, {r1, r4-r6}		/* Load rv[] into r1,r4-r6 */
	b	ffa_msg_send_direct_resp

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
END_FUNC thread_rpc
DECLARE_KEEP_PAGER thread_rpc

/*
 * void thread_foreign_intr_exit(uint32_t thread_index)
 *
 * This function is jumped to at the end of macro foreign_intr_handler().
 * The current thread as indicated by @thread_index has just been
 * suspended.  The job here is just to inform normal world the thread id to
 * resume when returning.
 */
FUNC thread_foreign_intr_exit , :
	/* load threads[r0].tsd.rpc_target_info into r1 */
	mov	r1, #THREAD_CTX_SIZE
	ldr	r2, =threads
	mla	r1, r1, r0, r2
	ldr	r1, [r1, #THREAD_CTX_TSD_RPC_TARGET_INFO]
	mov	r2, #FFA_PARAM_MBZ
	mov	r3, #FFA_PARAM_MBZ
	mov	r4, #OPTEE_FFA_YIELDING_CALL_RETURN_INTERRUPT
	mov	r5, #FFA_PARAM_MBZ
	mov	r6, #FFA_PARAM_MBZ
	mov	r7, r0
	b	ffa_msg_send_direct_resp
END_FUNC thread_foreign_intr_exit
