/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <arm64_macros.S>
#include <arm.h>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread_defs.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

/*
 * If ASLR is configured the identity mapped code may be mapped at two
 * locations, the identity location where virtual and physical address is
 * the same and at the runtime selected location to which OP-TEE has been
 * relocated.  Code executing at a location different compared to the
 * runtime selected location works OK as long as it doesn't do relative
 * addressing outside the identity mapped range. To allow relative
 * addressing this macro jumps to the runtime selected location.
 *
 * Note that the identity mapped range and the runtime selected range can
 * only differ if ASLR is configured.
 */
	.macro readjust_pc
#ifdef CFG_CORE_ASLR
	ldr	x16, =1111f
	br	x16
1111:
BTI(	bti	j)
#endif
	.endm

LOCAL_FUNC vector_std_smc_entry , : , .identity_map
	readjust_pc
	bl	thread_handle_std_smc
	/*
	 * Normally thread_handle_std_smc() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_smc()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
	mov	w1, w0
	ldr	x0, =TEESMC_OPTEED_RETURN_CALL_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_std_smc_entry

LOCAL_FUNC vector_fast_smc_entry , : , .identity_map
	readjust_pc
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	mov	x0, sp
	bl	thread_handle_fast_smc
	load_xregs sp, THREAD_SMC_ARGS_X0, 1, 8
	add	sp, sp, #THREAD_SMC_ARGS_SIZE
	ldr	x0, =TEESMC_OPTEED_RETURN_CALL_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_fast_smc_entry

LOCAL_FUNC vector_fiq_entry , : , .identity_map
	readjust_pc
	/* Secure Monitor received a FIQ and passed control to us. */
	bl	thread_check_canaries
	bl	itr_core_handler
	ldr	x0, =TEESMC_OPTEED_RETURN_FIQ_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_fiq_entry

LOCAL_FUNC vector_cpu_on_entry , : , .identity_map
	bl	cpu_on_handler
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_ON_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_cpu_on_entry

LOCAL_FUNC vector_cpu_off_entry , : , .identity_map
	readjust_pc
	bl	thread_cpu_off_handler
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_OFF_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_cpu_off_entry

LOCAL_FUNC vector_cpu_suspend_entry , : , .identity_map
	readjust_pc
	bl	thread_cpu_suspend_handler
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_SUSPEND_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_cpu_suspend_entry

LOCAL_FUNC vector_cpu_resume_entry , : , .identity_map
	readjust_pc
	bl	thread_cpu_resume_handler
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_RESUME_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_cpu_resume_entry

LOCAL_FUNC vector_system_off_entry , : , .identity_map
	readjust_pc
	bl	thread_system_off_handler
	mov	x1, x0
	ldr	x0, =TEESMC_OPTEED_RETURN_SYSTEM_OFF_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_system_off_entry

LOCAL_FUNC vector_system_reset_entry , : , .identity_map
	readjust_pc
	bl	thread_system_reset_handler
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
FUNC thread_vector_table , : , .identity_map, , nobti
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
DECLARE_KEEP_PAGER thread_vector_table

FUNC thread_std_smc_entry , :
	bl	__thread_std_smc_entry
	mov	w20, w0	/* Save return value for later */

	/* Mask all maskable exceptions before switching to temporary stack */
	msr	daifset, #DAIFBIT_ALL
	bl	thread_get_tmp_sp
	mov	sp, x0

	bl	thread_state_free

	ldr	x0, =TEESMC_OPTEED_RETURN_CALL_DONE
	mov	w1, w20
	mov	x2, #0
	mov	x3, #0
	mov	x4, #0
	smc	#0
	b	.	/* SMC should not return */
END_FUNC thread_std_smc_entry

/* void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]) */
FUNC thread_rpc , :
	/* Read daif and create an SPSR */
	mrs	x1, daif
	orr	x1, x1, #(SPSR_64_MODE_EL1 << SPSR_64_MODE_EL_SHIFT)

	/* Mask all maskable exceptions before switching to temporary stack */
	msr	daifset, #DAIFBIT_ALL
	push	x0, xzr
	push	x1, x30
	bl	thread_get_ctx_regs
	ldr	x30, [sp, #8]
	store_xregs x0, THREAD_CTX_REGS_X19, 19, 30
	mov	x19, x0

	bl	thread_get_tmp_sp
	pop	x1, xzr		/* Match "push x1, x30" above */
	mov	x2, sp
	str	x2, [x19, #THREAD_CTX_REGS_SP]
	ldr	x20, [sp]	/* Get pointer to rv[] */
	mov	sp, x0		/* Switch to tmp stack */
	/*
	 * We need to read rv[] early, because thread_state_suspend
	 * can invoke virt_unset_guest() which will unmap pages,
	 * where rv[] resides
	 */
	load_wregs x20, 0, 21, 23	/* Load rv[] into w20-w22 */

	adr	x2, .thread_rpc_return
	mov	w0, #THREAD_FLAGS_COPY_ARGS_ON_RETURN
	bl	thread_state_suspend
	mov	x4, x0		/* Supply thread index */
	ldr	w0, =TEESMC_OPTEED_RETURN_CALL_DONE
	mov	x1, x21
	mov	x2, x22
	mov	x3, x23
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
	pop	x16, xzr	/* Get pointer to rv[] */
	store_wregs x16, 0, 0, 3	/* Store w0-w3 into rv[] */
	ret
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
	mov	w4, w0
	ldr	w0, =TEESMC_OPTEED_RETURN_CALL_DONE
	ldr	w1, =OPTEE_SMC_RETURN_RPC_FOREIGN_INTR
	mov	w2, #0
	mov	w3, #0
	smc	#0
	b	.	/* SMC should not return */
END_FUNC thread_foreign_intr_exit

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
