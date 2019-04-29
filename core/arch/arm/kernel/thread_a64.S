/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2017, Linaro Limited
 */

#include <arm.h>
#include <arm64_macros.S>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread_defs.h>
#include <mm/core_mmu.h>
#include <smccc.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

#include "thread_private.h"

	.macro get_thread_ctx core_local, res, tmp0, tmp1
		ldr	w\tmp0, [\core_local, \
				#THREAD_CORE_LOCAL_CURR_THREAD]
		ldr	x\res, =threads
		mov	x\tmp1, #THREAD_CTX_SIZE
		madd	x\res, x\tmp0, x\tmp1, x\res
	.endm

	.macro b_if_spsr_is_el0 reg, label
		tbnz	\reg, #(SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT), \label
		tst	\reg, #(SPSR_64_MODE_EL_MASK << SPSR_64_MODE_EL_SHIFT)
		b.eq	\label
	.endm

LOCAL_FUNC vector_std_smc_entry , :
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	mov	x0, sp
	bl	thread_handle_std_smc
	/*
	 * Normally thread_handle_std_smc() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_smc()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
	load_xregs sp, THREAD_SMC_ARGS_X0, 1, 8
	add	sp, sp, #THREAD_SMC_ARGS_SIZE
	ldr	x0, =TEESMC_OPTEED_RETURN_CALL_DONE
	smc	#0
	b	.	/* SMC should not return */
END_FUNC vector_std_smc_entry

LOCAL_FUNC vector_fast_smc_entry , :
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

LOCAL_FUNC vector_fiq_entry , :
	/* Secure Monitor received a FIQ and passed control to us. */
	bl	thread_check_canaries
	adr	x16, thread_nintr_handler_ptr
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
KEEP_PAGER thread_vector_table


/* void thread_resume(struct thread_ctx_regs *regs) */
FUNC thread_resume , :
	load_xregs x0, THREAD_CTX_REGS_SP, 1, 3
	load_xregs x0, THREAD_CTX_REGS_X4, 4, 30
	mov	sp, x1
	msr	elr_el1, x2
	msr	spsr_el1, x3

	b_if_spsr_is_el0 w3, 1f

	load_xregs x0, THREAD_CTX_REGS_X1, 1, 3
	ldr	x0, [x0, THREAD_CTX_REGS_X0]
	eret

1:	load_xregs x0, THREAD_CTX_REGS_X1, 1, 3
	ldr	x0, [x0, THREAD_CTX_REGS_X0]

	msr	spsel, #1
	store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 1
	b	eret_to_el0
END_FUNC thread_resume

FUNC thread_std_smc_entry , :
	/* pass x0-x7 in a struct thread_smc_args */
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	mov	x0, sp

	/* Call the registered handler */
	bl	__thread_std_smc_entry

	/*
	 * Load the returned x0-x3 into preserved registers and skip the
	 * "returned" x4-x7 since they will not be returned to normal
	 * world.
	 */
	load_xregs sp, THREAD_SMC_ARGS_X0, 20, 23
	add	sp, sp, #THREAD_SMC_ARGS_SIZE

	/* Mask all maskable exceptions before switching to temporary stack */
	msr	daifset, #DAIFBIT_ALL
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
	store_wregs x16, 0, 0, 5	/* Store w0-w5 into rv[] */
	ret
END_FUNC thread_rpc
KEEP_PAGER thread_rpc

FUNC thread_smc , :
	smc	#0
	ret
END_FUNC thread_smc

FUNC thread_init_vbar , :
	msr	vbar_el1, x0
	ret
END_FUNC thread_init_vbar
KEEP_PAGER thread_init_vbar

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
	store_xregs sp, THREAD_USER_MODE_REC_EXIT_STATUS0_PTR, 7, 8
	store_xregs sp, THREAD_USER_MODE_REC_X19, 19, 30

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
	/*
	 * Save kernel stack pointer to ensure that el0_svc() uses
	 * correct stack pointer
	 */
	str	x19, [x21, #THREAD_CTX_KERN_SP]

	/*
	 * Initialize SPSR, ELR_EL1, and SP_EL0 to enter user mode
	 */
	msr	spsr_el1, x6
	/* Set user sp */
	mov	x13, x4		/* Used when running TA in Aarch32 */
	msr	sp_el0, x4	/* Used when running TA in Aarch64 */
	/* Set user function */
	msr	elr_el1, x5
	/* Set frame pointer (user stack can't be unwound past this point) */
	mov x29, #0

	/* Jump into user mode */
	store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 1
	b eret_to_el0
END_FUNC __thread_enter_user_mode
KEEP_PAGER __thread_enter_user_mode

/*
 * void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
 * 		uint32_t exit_status1);
 * See description in thread.h
 */
FUNC thread_unwind_user_mode , :
	/* Store the exit status */
	ldp	x3, x4, [sp, #THREAD_USER_MODE_REC_EXIT_STATUS0_PTR]
	str	w1, [x3]
	str	w2, [x4]
	/* Restore x19..x30 */
	load_xregs sp, THREAD_USER_MODE_REC_X19, 19, 30
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

	.macro restore_mapping
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
		/* Temporarily save x0, x1 */
		msr	tpidr_el1, x0
		msr	tpidrro_el0, x1

		/* Update the mapping to use the full kernel mapping */
		mrs	x0, ttbr0_el1
		sub	x0, x0, #CORE_MMU_L1_TBL_OFFSET
		/* switch to kernel mode ASID */
		bic	x0, x0, #BIT(TTBR_ASID_SHIFT)
		msr	ttbr0_el1, x0
		isb

		/* Jump into the full mapping and continue execution */
		ldr	x0, =1f
		br	x0
	1:

		/* Point to the vector into the full mapping */
		adr	x0, thread_user_kcode_offset
		ldr	x0, [x0]
		mrs	x1, vbar_el1
		add	x1, x1, x0
		msr	vbar_el1, x1
		isb

#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP_SEC
		/*
		 * Update the SP with thread_user_kdata_sp_offset as
		 * described in init_user_kcode().
		 */
		adr	x0, thread_user_kdata_sp_offset
		ldr	x0, [x0]
		add	sp, sp, x0
#endif

		/* Restore x0, x1 */
		mrs	x0, tpidr_el1
		mrs	x1, tpidrro_el0
		store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
#else
		store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
		mrs	x0, ttbr0_el1
		/* switch to kernel mode ASID */
		bic	x0, x0, #BIT(TTBR_ASID_SHIFT)
		msr	ttbr0_el1, x0
		isb
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/
	.endm

#define INV_INSN	0
	.section .text.thread_excp_vect
	.align	11, INV_INSN
FUNC thread_excp_vect , :
	/* -----------------------------------------------------
	 * EL1 with SP0 : 0x0 - 0x180
	 * -----------------------------------------------------
	 */
	.align	7, INV_INSN
el1_sync_sp0:
	store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
	b	el1_sync_abort
	check_vector_size el1_sync_sp0

	.align	7, INV_INSN
el1_irq_sp0:
	store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
	b	elx_irq
	check_vector_size el1_irq_sp0

	.align	7, INV_INSN
el1_fiq_sp0:
	store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
	b	elx_fiq
	check_vector_size el1_fiq_sp0

	.align	7, INV_INSN
el1_serror_sp0:
	b	el1_serror_sp0
	check_vector_size el1_serror_sp0

	/* -----------------------------------------------------
	 * Current EL with SP1: 0x200 - 0x380
	 * -----------------------------------------------------
	 */
	.align	7, INV_INSN
el1_sync_sp1:
	b	el1_sync_sp1
	check_vector_size el1_sync_sp1

	.align	7, INV_INSN
el1_irq_sp1:
	b	el1_irq_sp1
	check_vector_size el1_irq_sp1

	.align	7, INV_INSN
el1_fiq_sp1:
	b	el1_fiq_sp1
	check_vector_size el1_fiq_sp1

	.align	7, INV_INSN
el1_serror_sp1:
	b	el1_serror_sp1
	check_vector_size el1_serror_sp1

	/* -----------------------------------------------------
	 * Lower EL using AArch64 : 0x400 - 0x580
	 * -----------------------------------------------------
	 */
	.align	7, INV_INSN
el0_sync_a64:
	restore_mapping

	mrs	x2, esr_el1
	mrs	x3, sp_el0
	lsr	x2, x2, #ESR_EC_SHIFT
	cmp	x2, #ESR_EC_AARCH64_SVC
	b.eq	el0_svc
	b	el0_sync_abort
	check_vector_size el0_sync_a64

	.align	7, INV_INSN
el0_irq_a64:
	restore_mapping

	b	elx_irq
	check_vector_size el0_irq_a64

	.align	7, INV_INSN
el0_fiq_a64:
	restore_mapping

	b	elx_fiq
	check_vector_size el0_fiq_a64

	.align	7, INV_INSN
el0_serror_a64:
	b   	el0_serror_a64
	check_vector_size el0_serror_a64

	/* -----------------------------------------------------
	 * Lower EL using AArch32 : 0x0 - 0x180
	 * -----------------------------------------------------
	 */
	.align	7, INV_INSN
el0_sync_a32:
	restore_mapping

	mrs	x2, esr_el1
	mrs	x3, sp_el0
	lsr	x2, x2, #ESR_EC_SHIFT
	cmp	x2, #ESR_EC_AARCH32_SVC
	b.eq	el0_svc
	b	el0_sync_abort
	check_vector_size el0_sync_a32

	.align	7, INV_INSN
el0_irq_a32:
	restore_mapping

	b	elx_irq
	check_vector_size el0_irq_a32

	.align	7, INV_INSN
el0_fiq_a32:
	restore_mapping

	b	elx_fiq
	check_vector_size el0_fiq_a32

	.align	7, INV_INSN
el0_serror_a32:
	b	el0_serror_a32
	check_vector_size el0_serror_a32

#if defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC)
	.macro invalidate_branch_predictor
		store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
		mov_imm	x0, SMCCC_ARCH_WORKAROUND_1
		smc	#0
		load_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
	.endm

	.align	11, INV_INSN
	.global thread_excp_vect_workaround
thread_excp_vect_workaround:
	/* -----------------------------------------------------
	 * EL1 with SP0 : 0x0 - 0x180
	 * -----------------------------------------------------
	 */
	.align	7, INV_INSN
workaround_el1_sync_sp0:
	b	el1_sync_sp0
	check_vector_size workaround_el1_sync_sp0

	.align	7, INV_INSN
workaround_el1_irq_sp0:
	b	el1_irq_sp0
	check_vector_size workaround_el1_irq_sp0

	.align	7, INV_INSN
workaround_el1_fiq_sp0:
	b	el1_fiq_sp0
	check_vector_size workaround_el1_fiq_sp0

	.align	7, INV_INSN
workaround_el1_serror_sp0:
	b	el1_serror_sp0
	check_vector_size workaround_el1_serror_sp0

	/* -----------------------------------------------------
	 * Current EL with SP1: 0x200 - 0x380
	 * -----------------------------------------------------
	 */
	.align	7, INV_INSN
workaround_el1_sync_sp1:
	b	workaround_el1_sync_sp1
	check_vector_size workaround_el1_sync_sp1

	.align	7, INV_INSN
workaround_el1_irq_sp1:
	b	workaround_el1_irq_sp1
	check_vector_size workaround_el1_irq_sp1

	.align	7, INV_INSN
workaround_el1_fiq_sp1:
	b	workaround_el1_fiq_sp1
	check_vector_size workaround_el1_fiq_sp1

	.align	7, INV_INSN
workaround_el1_serror_sp1:
	b	workaround_el1_serror_sp1
	check_vector_size workaround_el1_serror_sp1

	/* -----------------------------------------------------
	 * Lower EL using AArch64 : 0x400 - 0x580
	 * -----------------------------------------------------
	 */
	.align	7, INV_INSN
workaround_el0_sync_a64:
	invalidate_branch_predictor
	b	el0_sync_a64
	check_vector_size workaround_el0_sync_a64

	.align	7, INV_INSN
workaround_el0_irq_a64:
	invalidate_branch_predictor
	b	el0_irq_a64
	check_vector_size workaround_el0_irq_a64

	.align	7, INV_INSN
workaround_el0_fiq_a64:
	invalidate_branch_predictor
	b	el0_fiq_a64
	check_vector_size workaround_el0_fiq_a64

	.align	7, INV_INSN
workaround_el0_serror_a64:
	b   	workaround_el0_serror_a64
	check_vector_size workaround_el0_serror_a64

	/* -----------------------------------------------------
	 * Lower EL using AArch32 : 0x0 - 0x180
	 * -----------------------------------------------------
	 */
	.align	7, INV_INSN
workaround_el0_sync_a32:
	invalidate_branch_predictor
	b	el0_sync_a32
	check_vector_size workaround_el0_sync_a32

	.align	7, INV_INSN
workaround_el0_irq_a32:
	invalidate_branch_predictor
	b	el0_irq_a32
	check_vector_size workaround_el0_irq_a32

	.align	7, INV_INSN
workaround_el0_fiq_a32:
	invalidate_branch_predictor
	b	el0_fiq_a32
	check_vector_size workaround_el0_fiq_a32

	.align	7, INV_INSN
workaround_el0_serror_a32:
	b	workaround_el0_serror_a32
	check_vector_size workaround_el0_serror_a32
#endif /*CFG_CORE_WORKAROUND_SPECTRE_BP_SEC*/

/*
 * We're keeping this code in the same section as the vector to make sure
 * that it's always available.
 */
eret_to_el0:

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	/* Point to the vector into the reduced mapping */
	adr	x0, thread_user_kcode_offset
	ldr	x0, [x0]
	mrs	x1, vbar_el1
	sub	x1, x1, x0
	msr	vbar_el1, x1
	isb

#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP_SEC
	/* Store the SP offset in tpidr_el1 to be used below to update SP */
	adr	x1, thread_user_kdata_sp_offset
	ldr	x1, [x1]
	msr	tpidr_el1, x1
#endif

	/* Jump into the reduced mapping and continue execution */
	ldr	x1, =1f
	sub	x1, x1, x0
	br	x1
1:

	load_xregs sp, THREAD_CORE_LOCAL_X0, 0, 1
	msr	tpidrro_el0, x0

	/* Update the mapping to exclude the full kernel mapping */
	mrs	x0, ttbr0_el1
	add	x0, x0, #CORE_MMU_L1_TBL_OFFSET
	orr	x0, x0, #BIT(TTBR_ASID_SHIFT) /* switch to user mode ASID */
	msr	ttbr0_el1, x0
	isb

#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP_SEC
	/*
	 * Update the SP with thread_user_kdata_sp_offset as described in
	 * init_user_kcode().
	 */
	mrs	x0, tpidr_el1
	sub	sp, sp, x0
#endif

	mrs	x0, tpidrro_el0
#else
	mrs	x0, ttbr0_el1
	orr	x0, x0, #BIT(TTBR_ASID_SHIFT) /* switch to user mode ASID */
	msr	ttbr0_el1, x0
	isb
	load_xregs sp, THREAD_CORE_LOCAL_X0, 0, 1
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/

	eret

	/*
	 * void icache_inv_user_range(void *addr, size_t size);
	 *
	 * This function has to execute with the user space ASID active,
	 * this means executing with reduced mapping and the code needs
	 * to be located here together with the vector.
	 */
	.global icache_inv_user_range
	.type icache_inv_user_range , %function
icache_inv_user_range:
	/* Mask all exceptions */
	mrs	x6, daif	/* this register must be preserved */
	msr	daifset, #DAIFBIT_ALL

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	/* Point to the vector into the reduced mapping */
	adr	x2, thread_user_kcode_offset
	ldr	x2, [x2]
	mrs	x4, vbar_el1	/* this register must be preserved */
	sub	x3, x4, x2
	msr	vbar_el1, x3
	isb

	/* Jump into the reduced mapping and continue execution */
	ldr	x3, =1f
	sub	x3, x3, x2
	br	x3
1:

	/* Update the mapping to exclude the full kernel mapping */
	mrs	x5, ttbr0_el1	/* this register must be preserved */
	add	x2, x5, #CORE_MMU_L1_TBL_OFFSET
	orr	x2, x2, #BIT(TTBR_ASID_SHIFT) /* switch to user mode ASID */
	msr	ttbr0_el1, x2
	isb

#else
	mrs	x5, ttbr0_el1	/* this register must be preserved */
	orr	x2, x2, #BIT(TTBR_ASID_SHIFT) /* switch to user mode ASID */
	msr	ttbr0_el1, x2
	isb
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/

	/*
	 * Do the actual icache invalidation
	 */

	/* Calculate minimum icache line size, result in x2 */
	mrs	x3, ctr_el0
	and	x3, x3, #CTR_IMINLINE_MASK
	mov	x2, #CTR_WORD_SIZE
	lsl	x2, x2, x3

	add	x1, x0, x1
	sub	x3, x2, #1
	bic	x0, x0, x3
1:
	ic	ivau, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo    1b
	dsb	ish

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	/* Update the mapping to use the full kernel mapping and ASID */
	msr	ttbr0_el1, x5
	isb

	/* Jump into the full mapping and continue execution */
	ldr	x0, =1f
	br	x0
1:

	/* Point to the vector into the full mapping */
	msr	vbar_el1, x4
	isb
#else
	/* switch to kernel mode ASID */
	msr	ttbr0_el1, x5
	isb
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/

	msr	daif, x6	/* restore exceptions */
	ret	/* End of icache_inv_user_range() */

	/*
	 * Make sure that literals are placed before the
	 * thread_excp_vect_end label.
	 */
	.pool
	.global thread_excp_vect_end
thread_excp_vect_end:
END_FUNC thread_excp_vect

LOCAL_FUNC el0_svc , :
	/* get pointer to current thread context in x0 */
	get_thread_ctx sp, 0, 1, 2
	/* load saved kernel sp */
	ldr	x0, [x0, #THREAD_CTX_KERN_SP]
	/* Keep pointer to initial recod in x1 */
	mov	x1, sp
	/* Switch to SP_EL0 and restore kernel sp */
	msr	spsel, #0
	mov	x2, sp	/* Save SP_EL0 */
	mov	sp, x0

	/* Make room for struct thread_svc_regs */
	sub	sp, sp, #THREAD_SVC_REG_SIZE
	stp	x30,x2, [sp, #THREAD_SVC_REG_X30]

	/* Restore x0-x3 */
	ldp	x2, x3, [x1, #THREAD_CORE_LOCAL_X2]
	ldp	x0, x1, [x1, #THREAD_CORE_LOCAL_X0]

	/* Prepare the argument for the handler */
	store_xregs sp, THREAD_SVC_REG_X0, 0, 14
	mrs	x0, elr_el1
	mrs	x1, spsr_el1
	store_xregs sp, THREAD_SVC_REG_ELR, 0, 1
	mov	x0, sp

	/*
	 * Unmask native interrupts, Serror, and debug exceptions since we have
	 * nothing left in sp_el1. Note that the SVC handler is excepted to
	 * re-enable foreign interrupts by itself.
	 */
#if defined(CFG_ARM_GICV3)
	msr	daifclr, #(DAIFBIT_IRQ | DAIFBIT_ABT | DAIFBIT_DBG)
#else
	msr	daifclr, #(DAIFBIT_FIQ | DAIFBIT_ABT | DAIFBIT_DBG)
#endif

	/* Call the handler */
	bl	tee_svc_handler

	/* Mask all maskable exceptions since we're switching back to sp_el1 */
	msr	daifset, #DAIFBIT_ALL

	/*
	 * Save kernel sp we'll had at the beginning of this function.
	 * This is when this TA has called another TA because
	 * __thread_enter_user_mode() also saves the stack pointer in this
	 * field.
	 */
	msr	spsel, #1
	get_thread_ctx sp, 0, 1, 2
	msr	spsel, #0
	add	x1, sp, #THREAD_SVC_REG_SIZE
	str	x1, [x0, #THREAD_CTX_KERN_SP]

	/* Restore registers to the required state and return*/
	load_xregs sp, THREAD_SVC_REG_ELR, 0, 1
	msr	elr_el1, x0
	msr	spsr_el1, x1
	load_xregs sp, THREAD_SVC_REG_X2, 2, 14
	mov	x30, sp
	ldr	x0, [x30, #THREAD_SVC_REG_SP_EL0]
	mov	sp, x0
	b_if_spsr_is_el0 w1, 1f
	ldp	x0, x1, [x30, THREAD_SVC_REG_X0]
	ldr	x30, [x30, #THREAD_SVC_REG_X30]

	eret

1:	ldp	x0, x1, [x30, THREAD_SVC_REG_X0]
	ldr	x30, [x30, #THREAD_SVC_REG_X30]

	msr	spsel, #1
	store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 1
	b	eret_to_el0
END_FUNC el0_svc

LOCAL_FUNC el1_sync_abort , :
	mov	x0, sp
	msr	spsel, #0
	mov	x3, sp		/* Save original sp */

	/*
	 * Update core local flags.
	 * flags = (flags << THREAD_CLF_SAVED_SHIFT) | THREAD_CLF_ABORT;
	 */
	ldr	w1, [x0, #THREAD_CORE_LOCAL_FLAGS]
	lsl	w1, w1, #THREAD_CLF_SAVED_SHIFT
	orr	w1, w1, #THREAD_CLF_ABORT
	tbnz	w1, #(THREAD_CLF_SAVED_SHIFT + THREAD_CLF_ABORT_SHIFT), \
			.Lsel_tmp_sp

	/* Select abort stack */
	ldr	x2, [x0, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	b	.Lset_sp

.Lsel_tmp_sp:
	/* Select tmp stack */
	ldr	x2, [x0, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	orr	w1, w1, #THREAD_CLF_TMP	/* flags |= THREAD_CLF_TMP; */

.Lset_sp:
	mov	sp, x2
	str	w1, [x0, #THREAD_CORE_LOCAL_FLAGS]

	/*
	 * Save state on stack
	 */
	sub	sp, sp, #THREAD_ABT_REGS_SIZE
	mrs	x2, spsr_el1
	/* Store spsr, sp_el0 */
	stp	x2, x3, [sp, #THREAD_ABT_REG_SPSR]
	/* Store original x0, x1 */
	ldp	x2, x3, [x0, #THREAD_CORE_LOCAL_X0]
	stp	x2, x3, [sp, #THREAD_ABT_REG_X0]
	/* Store original x2, x3 and x4 to x29 */
	ldp	x2, x3, [x0, #THREAD_CORE_LOCAL_X2]
	store_xregs sp, THREAD_ABT_REG_X2, 2, 29
	/* Store x30, elr_el1 */
	mrs	x0, elr_el1
	stp	x30, x0, [sp, #THREAD_ABT_REG_X30]

	/*
	 * Call handler
	 */
	mov	x0, #0
	mov	x1, sp
	bl	abort_handler

	/*
	 * Restore state from stack
	 */
	/* Load x30, elr_el1 */
	ldp	x30, x0, [sp, #THREAD_ABT_REG_X30]
	msr	elr_el1, x0
	/* Load x0 to x29 */
	load_xregs sp, THREAD_ABT_REG_X0, 0, 29
	/* Switch to SP_EL1 */
	msr	spsel, #1
	/* Save x0 to x3 in CORE_LOCAL */
	store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
	/* Restore spsr_el1 and sp_el0 */
	mrs	x3, sp_el0
	ldp	x0, x1, [x3, #THREAD_ABT_REG_SPSR]
	msr	spsr_el1, x0
	msr	sp_el0, x1

	/* Update core local flags */
	ldr	w0, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsr	w0, w0, #THREAD_CLF_SAVED_SHIFT
	str	w0, [sp, #THREAD_CORE_LOCAL_FLAGS]

	/* Restore x0 to x3 */
	load_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3

	/* Return from exception */
	eret
END_FUNC el1_sync_abort

	/* sp_el0 in x3 */
LOCAL_FUNC el0_sync_abort , :
	/*
	 * Update core local flags
	 */
	ldr	w1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsl	w1, w1, #THREAD_CLF_SAVED_SHIFT
	orr	w1, w1, #THREAD_CLF_ABORT
	str	w1, [sp, #THREAD_CORE_LOCAL_FLAGS]

	/*
	 * Save state on stack
	 */

	/* load abt_stack_va_end */
	ldr	x1, [sp, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]
	/* Keep pointer to initial record in x0 */
	mov	x0, sp
	/* Switch to SP_EL0 */
	msr	spsel, #0
	mov	sp, x1
	sub	sp, sp, #THREAD_ABT_REGS_SIZE
	mrs	x2, spsr_el1
	/* Store spsr, sp_el0 */
	stp	x2, x3, [sp, #THREAD_ABT_REG_SPSR]
	/* Store original x0, x1 */
	ldp	x2, x3, [x0, #THREAD_CORE_LOCAL_X0]
	stp	x2, x3, [sp, #THREAD_ABT_REG_X0]
	/* Store original x2, x3 and x4 to x29 */
	ldp	x2, x3, [x0, #THREAD_CORE_LOCAL_X2]
	store_xregs sp, THREAD_ABT_REG_X2, 2, 29
	/* Store x30, elr_el1 */
	mrs	x0, elr_el1
	stp	x30, x0, [sp, #THREAD_ABT_REG_X30]

	/*
	 * Call handler
	 */
	mov	x0, #0
	mov	x1, sp
	bl	abort_handler

	/*
	 * Restore state from stack
	 */

	/* Load x30, elr_el1 */
	ldp	x30, x0, [sp, #THREAD_ABT_REG_X30]
	msr	elr_el1, x0
	/* Load x0 to x29 */
	load_xregs sp, THREAD_ABT_REG_X0, 0, 29
	/* Switch to SP_EL1 */
	msr	spsel, #1
	/* Save x0 to x3 in EL1_REC */
	store_xregs sp, THREAD_CORE_LOCAL_X0, 0, 3
	/* Restore spsr_el1 and sp_el0 */
	mrs	x3, sp_el0
	ldp	x0, x1, [x3, #THREAD_ABT_REG_SPSR]
	msr	spsr_el1, x0
	msr	sp_el0, x1

	/* Update core local flags */
	ldr	w1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsr	w1, w1, #THREAD_CLF_SAVED_SHIFT
	str	w1, [sp, #THREAD_CORE_LOCAL_FLAGS]

	/* Restore x2 to x3 */
	load_xregs sp, THREAD_CORE_LOCAL_X2, 2, 3

	b_if_spsr_is_el0 w0, 1f

	/* Restore x0 to x1 */
	load_xregs sp, THREAD_CORE_LOCAL_X0, 0, 1

	/* Return from exception */
	eret
1:	b	eret_to_el0
END_FUNC el0_sync_abort

/* The handler of foreign interrupt. */
.macro foreign_intr_handler mode:req
	/*
	 * Update core local flags
	 */
	ldr	w1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsl	w1, w1, #THREAD_CLF_SAVED_SHIFT
	orr	w1, w1, #THREAD_CLF_TMP
	.ifc	\mode\(),fiq
	orr	w1, w1, #THREAD_CLF_FIQ
	.else
	orr	w1, w1, #THREAD_CLF_IRQ
	.endif
	str	w1, [sp, #THREAD_CORE_LOCAL_FLAGS]

	/* get pointer to current thread context in x0 */
	get_thread_ctx sp, 0, 1, 2
	/* Keep original SP_EL0 */
	mrs	x2, sp_el0

	/* Store original sp_el0 */
	str	x2, [x0, #THREAD_CTX_REGS_SP]
	/* store x4..x30 */
	store_xregs x0, THREAD_CTX_REGS_X4, 4, 30
	/* Load original x0..x3 into x10..x13 */
	load_xregs sp, THREAD_CORE_LOCAL_X0, 10, 13
	/* Save original x0..x3 */
	store_xregs x0, THREAD_CTX_REGS_X0, 10, 13

	/* load tmp_stack_va_end */
	ldr	x1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	/* Switch to SP_EL0 */
	msr	spsel, #0
	mov	sp, x1

	/*
	 * Mark current thread as suspended
	 */
	mov	w0, #THREAD_FLAGS_EXIT_ON_FOREIGN_INTR
	mrs	x1, spsr_el1
	mrs	x2, elr_el1
	bl	thread_state_suspend
	mov	w4, w0		/* Supply thread index */

	/* Update core local flags */
	/* Switch to SP_EL1 */
	msr	spsel, #1
	ldr	w0, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsr	w0, w0, #THREAD_CLF_SAVED_SHIFT
	str	w0, [sp, #THREAD_CORE_LOCAL_FLAGS]
	msr	spsel, #0

	/*
	 * Note that we're exiting with SP_EL0 selected since the entry
	 * functions expects to have SP_EL0 selected with the tmp stack
	 * set.
	 */

	ldr	w0, =TEESMC_OPTEED_RETURN_CALL_DONE
	ldr	w1, =OPTEE_SMC_RETURN_RPC_FOREIGN_INTR
	mov	w2, #0
	mov	w3, #0
	/* w4 is already filled in above */
	smc	#0
	b	.	/* SMC should not return */
.endm

/*
 * This struct is never used from C it's only here to visualize the
 * layout.
 *
 * struct elx_nintr_rec {
 * 	uint64_t x[19 - 4]; x4..x18
 * 	uint64_t lr;
 * 	uint64_t sp_el0;
 * };
 */
#define ELX_NINTR_REC_X(x)		(8 * ((x) - 4))
#define ELX_NINTR_REC_LR		(8 + ELX_NINTR_REC_X(19))
#define ELX_NINTR_REC_SP_EL0		(8 + ELX_NINTR_REC_LR)
#define ELX_NINTR_REC_SIZE		(8 + ELX_NINTR_REC_SP_EL0)

/* The handler of native interrupt. */
.macro native_intr_handler mode:req
	/*
	 * Update core local flags
	 */
	ldr	w1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsl	w1, w1, #THREAD_CLF_SAVED_SHIFT
	.ifc	\mode\(),fiq
	orr	w1, w1, #THREAD_CLF_FIQ
	.else
	orr	w1, w1, #THREAD_CLF_IRQ
	.endif
	orr	w1, w1, #THREAD_CLF_TMP
	str	w1, [sp, #THREAD_CORE_LOCAL_FLAGS]

	/* load tmp_stack_va_end */
	ldr	x1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	/* Keep original SP_EL0 */
	mrs	x2, sp_el0
	/* Switch to SP_EL0 */
	msr	spsel, #0
	mov	sp, x1

	/*
	 * Save registers on stack that can be corrupted by a call to
	 * a C function
	 */
	/* Make room for struct elx_nintr_rec */
	sub	sp, sp, #ELX_NINTR_REC_SIZE
	/* Store x4..x18 */
	store_xregs sp, ELX_NINTR_REC_X(4), 4, 18
	/* Store lr and original sp_el0 */
	stp	x30, x2, [sp, #ELX_NINTR_REC_LR]

	bl	thread_check_canaries
	adr	x16, thread_nintr_handler_ptr
	ldr	x16, [x16]
	blr	x16

	/*
	 * Restore registers
	 */
	/* Restore x4..x18 */
	load_xregs sp, ELX_NINTR_REC_X(4), 4, 18
	/* Load  lr and original sp_el0 */
	ldp	x30, x2, [sp, #ELX_NINTR_REC_LR]
	/* Restore SP_El0 */
	mov	sp, x2
	/* Switch back to SP_EL1 */
	msr	spsel, #1

	/* Update core local flags */
	ldr	w0, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsr	w0, w0, #THREAD_CLF_SAVED_SHIFT
	str	w0, [sp, #THREAD_CORE_LOCAL_FLAGS]

	mrs	x0, spsr_el1
	/* Restore x2..x3 */
	load_xregs sp, THREAD_CORE_LOCAL_X2, 2, 3
	b_if_spsr_is_el0 w0, 1f

	/* Restore x0..x1 */
	load_xregs sp, THREAD_CORE_LOCAL_X0, 0, 1

	/* Return from exception */
	eret
1:	b	eret_to_el0
.endm

LOCAL_FUNC elx_irq , :
#if defined(CFG_ARM_GICV3)
	native_intr_handler	irq
#else
	foreign_intr_handler	irq
#endif
END_FUNC elx_irq

LOCAL_FUNC elx_fiq , :
#if defined(CFG_ARM_GICV3)
	foreign_intr_handler	fiq
#else
	native_intr_handler	fiq
#endif
END_FUNC elx_fiq
