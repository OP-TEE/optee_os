/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2019-2021, Arm Limited
 */

#include <platform_config.h>

#include <arm64_macros.S>
#include <arm.h>
#include <asm.S>
#include <ffa.h>
#include <generated/asm-defines.h>
#include <kernel/thread.h>
#include <optee_ffa.h>

#ifdef CFG_SECURE_PARTITION
LOCAL_FUNC thread_ffa_interrupt , :
	mov_imm	x0, FFA_INTERRUPT		/* FID */
	/* X1: Endpoint/vCPU IDs is set by caller */
	mov	x2, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x3, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x4, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x5, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x6, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x7, #FFA_PARAM_MBZ		/* Param MBZ */
	b	.ffa_msg_loop
END_FUNC thread_ffa_interrupt
#endif /* CFG_SECURE_PARTITION */

FUNC thread_ffa_msg_wait , :
	mov_imm	x0, FFA_MSG_WAIT		/* FID */
	mov	x1, #FFA_TARGET_INFO_MBZ	/* Target info MBZ */
	mov	x2, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x3, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x4, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x5, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x6, #FFA_PARAM_MBZ		/* Param MBZ */
	mov	x7, #FFA_PARAM_MBZ		/* Param MBZ */
	b	.ffa_msg_loop
END_FUNC thread_ffa_msg_wait

	/* Caller provides x1, x3-x7 params */
LOCAL_FUNC ffa_msg_send_direct_resp , :
	msr	spsel, #1
	ldr	w0, [sp, #THREAD_CORE_LOCAL_DIRECT_RESP_FID]
	msr	spsel, #0
	mov	x2, #FFA_PARAM_MBZ			/* RES MBZ */

.ffa_msg_loop:
	/*
	 * Native interrupts unmasked while invoking SMC with caller
	 * provided parameters.
	 */
	msr	daifclr, #DAIFBIT_NATIVE_INTR
	smc	#0
	msr	daifset, #DAIFBIT_NATIVE_INTR

	/* Store the parameters as struct thread_smc_args on stack */
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	mov	x0, sp

	/* parse and handle message */
	bl	thread_spmc_msg_recv

	/* Load struct thread_smc_args into registers */
	load_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	add	sp, sp, #THREAD_SMC_ARGS_SIZE
	b	.ffa_msg_loop
END_FUNC ffa_msg_send_direct_resp

FUNC thread_std_smc_entry , :
	ror	w19, w0, #16 /* Save target info with src and dst swapped */
	bl	__thread_std_smc_entry
	mov	w20, w0	/* Save return value */

	/* Mask all maskable exceptions before switching to temporary stack */
	msr	daifset, #DAIFBIT_ALL
	bl	thread_get_tmp_sp
	mov	sp, x0

	bl	thread_state_free

	mov	w1, w19				/* Target info */
	mov	w3, w20				/* Return value */
	mov	x4, #FFA_PARAM_MBZ		/* Unused parameter */
	mov	x5, #FFA_PARAM_MBZ		/* Unused parameter */
	mov	x6, #FFA_PARAM_MBZ		/* Unused parameter */
	mov	x7, #FFA_PARAM_MBZ		/* Unused parameter */
	b	ffa_msg_send_direct_resp
END_FUNC thread_std_smc_entry

#ifdef CFG_SECURE_PARTITION
/* void spmc_sp_thread_entry(args) */
FUNC spmc_sp_thread_entry , :
	/* Store the parameters as struct thread_smc_args on stack */
	sub     sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	mov     x0, sp
	mov     x1, #0 /* Pass NULL pointer for caller_sp, coming from NW */
	bl      spmc_sp_msg_handler
	load_xregs sp, THREAD_SMC_ARGS_X0, 20, 27

	/* Mask all maskable exceptions before switching to temporary stack */
	msr     daifset, #DAIFBIT_ALL
	bl      thread_get_tmp_sp
	mov     sp, x0

	bl      thread_state_free

	/* Restore the FF-A arguments before the SMC instruction. */
	mov     w0, w20
	mov     w1, w21
	mov     w2, w22
	mov     w3, w23
	mov     w4, w24
	mov     w5, w25
	mov     w6, w26
	mov     w7, w27
	b .ffa_msg_loop
END_FUNC spmc_sp_thread_entry
#endif

/* void thread_rpc_spsr(uint32_t rv[THREAD_RPC_NUM_ARGS], uint64_t spsr) */
FUNC thread_rpc_spsr , :
	/* Mask all maskable exceptions before switching to temporary stack */
	msr	daifset, #DAIFBIT_ALL
	push	x0, xzr
	push	x1, x30
	bl	thread_get_ctx_regs
	ldr	x30, [sp, #8]
	store_xregs x0, THREAD_CTX_REGS_X19, 19, 30
	mov	x19, x0

#if defined(CFG_CORE_PAUTH)
	/* Save APIAKEY */
	read_apiakeyhi  x1
	read_apiakeylo  x2
	store_xregs x0, THREAD_CTX_REGS_APIAKEY_HI, 1, 2
#endif

	bl	thread_get_tmp_sp
	pop	x1, xzr		/* Match "push x1, x30" above */
	mov	x2, sp
	str	x2, [x19, #THREAD_CTX_REGS_SP]
	ldr	x20, [sp]	/* Get pointer to rpc_arg[] */
	mov	sp, x0		/* Switch to tmp stack */
	/*
	 * We need to read rpc_arg[] early, because thread_state_suspend
	 * can invoke virt_unset_guest() which will unmap pages,
	 * where rpc_arg[] resides
	 */
	load_wregs x20, 0, 21, 24	/* Load rpc_arg[] into w21-w24 */

	adr	x2, .thread_rpc_return
	mov	w0, #THREAD_FLAGS_COPY_ARGS_ON_RETURN
	bl	thread_state_suspend
	mov	w1, w21
	mov	w3, #0		/* Error code = 0 */
	mov	w4, w22
	mov	w5, w23
	mov	w6, w24
	mov	w7, w0		/* Supply thread index */
	b	ffa_msg_send_direct_resp

.thread_rpc_return:
	/*
	 * At this point has the stack pointer been restored to the value
	 * stored in THREAD_CTX above.
	 *
	 * Jumps here from thread_resume above when RPC has returned. The
	 * IRQ and FIQ bits are restored to what they where when this
	 * function was originally entered. w0-w3 holds the values supplied
	 * to thread_resume_from_rpc() in a0-a3.
	 */
	pop	x16, xzr	/* Get pointer to rv[] */
	store_wregs x16, 0, 0, 3	/* Store w0-w3 into rv[] */
	ret
END_FUNC thread_rpc_spsr

/*
 * void thread_foreign_intr_exit(uint32_t thread_index)
 *
 * This function is jumped to at the end of macro foreign_intr_handler().
 * The current thread as indicated by @thread_index has just been
 * suspended.  The job here is just to inform normal world the thread id to
 * resume when returning.
 * If the active FF-A endpoint is OP-TEE (or a TA) then an this function send an
 * OPTEE_FFA_YIELDING_CALL_RETURN_INTERRUPT message to the normal world via the
 * FFA_MSG_SEND_DIRECT_RESP interface. This is handled by the OP-TEE
 * driver in Linux so it can schedule task to the thread.
 * If the active endpoint is an SP the function sends an FFA_INTERRUPT. This is
 * handled by the FF-A driver and after taking care of the NWd interrupts it
 * returns via an FFA_RUN call.
 * The active endpoint is determined by checking the THREAD_FLAGS_FFA_ONLY flag
 * in threads[w0].flags. This is only set for the thread which handles SPs.
 */
FUNC thread_foreign_intr_exit , :
	/* load threads[w0].tsd.rpc_target_info into w1 */
	mov	x1, #THREAD_CTX_SIZE
	adr_l	x2, threads
	madd	x2, x1, x0, x2
	ldr	w1, [x2, #THREAD_CTX_TSD_RPC_TARGET_INFO]
#ifdef CFG_SECURE_PARTITION
	/* load threads[w0].flags into w2 */
	ldr	w2, [x2, #THREAD_CTX_FLAGS]
	and     w2, w2, #THREAD_FLAGS_FFA_ONLY
	cbnz	w2, thread_ffa_interrupt
#endif /* CFG_SECURE_PARTITION */
	mov	w3, #FFA_PARAM_MBZ
	mov	w4, #OPTEE_FFA_YIELDING_CALL_RETURN_INTERRUPT
	mov	x5, #FFA_PARAM_MBZ
	mov	w6, #FFA_PARAM_MBZ
	mov	w7, w0
	b	ffa_msg_send_direct_resp
END_FUNC thread_foreign_intr_exit

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
