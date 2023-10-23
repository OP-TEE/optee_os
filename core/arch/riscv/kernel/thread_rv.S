/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <mm/core_mmu.h>
#include <riscv.h>
#include <riscv_macros.S>

.macro get_thread_ctx res, tmp0
	lw	\tmp0, THREAD_CORE_LOCAL_CURR_THREAD(tp)
	la	\res, threads
1:
	beqz	\tmp0, 2f
	addi	\res, \res, THREAD_CTX_SIZE
	addi	\tmp0, \tmp0, -1
	bnez	\tmp0, 1b
2:
.endm

.macro b_if_prev_priv_is_u reg, label
	andi	\reg, \reg, CSR_XSTATUS_SPP
	beqz	\reg, \label
.endm

.macro save_regs, mode
.if \mode == TRAP_MODE_USER
	/* Save user sp, a0, a1 into temporary spaces of thread_core_local */
	store_xregs tp, THREAD_CORE_LOCAL_X0, REG_SP
	store_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1
	/* Load and set kernel sp from thread context */
	get_thread_ctx a0, a1
	load_xregs a0, THREAD_CTX_KERN_SP, REG_SP
	/* Now sp is kernel sp, create stack frame to save user context */
	addi	sp, sp, -THREAD_TRAP_REGS_SIZE

	/* Save user sp */
	load_xregs tp, THREAD_CORE_LOCAL_X0, REG_A0
	store_xregs sp, THREAD_TRAP_REG_SP, REG_A0

	/* Restore user a0, a1 which can be saved later */
	load_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1

	/* Save user gp */
	store_xregs sp, THREAD_TRAP_REG_GP, REG_GP

	/*
	 * Set the scratch register to 0 such in case of a recursive
	 * exception thread_trap_vect() knows that it is emitted from kernel.
	 */
	csrrw	gp, CSR_XSCRATCH, zero
	/* Save user tp we previously swapped into CSR_XSCRATCH */
	store_xregs sp, THREAD_TRAP_REG_TP, REG_GP
.option push
.option norelax
	la	gp, __global_pointer$
.option pop
.else
	/* sp is kernel sp */
	addi	sp, sp, -THREAD_TRAP_REGS_SIZE
	store_xregs sp, THREAD_TRAP_REG_GP, REG_GP
	store_xregs sp, THREAD_TRAP_REG_SP, REG_SP
.endif
	store_xregs sp, THREAD_TRAP_REG_T3, REG_T3, REG_T6
	store_xregs sp, THREAD_TRAP_REG_T0, REG_T0, REG_T2
	store_xregs sp, THREAD_TRAP_REG_A0, REG_A0, REG_A7
	store_xregs sp, THREAD_TRAP_REG_RA, REG_RA
#if defined(CFG_UNWIND)
	/* To unwind stack we need s0, which is frame pointer. */
	store_xregs sp, THREAD_TRAP_REG_S0, REG_S0
#endif

	csrr	t0, CSR_XIE
	store_xregs sp, THREAD_TRAP_REG_IE, REG_T0

	/* Mask all interrupts */
	csrw	CSR_XIE, x0

	csrr	t0, CSR_XSTATUS
	store_xregs sp, THREAD_TRAP_REG_STATUS, REG_T0

	csrr	a0, CSR_XCAUSE
	csrr	a1, CSR_XEPC

	store_xregs sp, THREAD_TRAP_REG_EPC, REG_A1

	mv	a2, sp

	/* a0 = cause
	 * a1 = epc
	 * a2 = sp
	 * a3 = user
	 * thread_trap_handler(cause, epc, sp, user)
	 */
.endm

.macro restore_regs, mode
	load_xregs sp, THREAD_TRAP_REG_EPC, REG_T0
	csrw	CSR_XEPC, t0

	load_xregs sp, THREAD_TRAP_REG_IE, REG_T0
	csrw	CSR_XIE, t0

	load_xregs sp, THREAD_TRAP_REG_STATUS, REG_T0
	csrw	CSR_XSTATUS, t0

	load_xregs sp, THREAD_TRAP_REG_RA, REG_RA
	load_xregs sp, THREAD_TRAP_REG_A0, REG_A0, REG_A7
	load_xregs sp, THREAD_TRAP_REG_T0, REG_T0, REG_T2
	load_xregs sp, THREAD_TRAP_REG_T3, REG_T3, REG_T6
#if defined(CFG_UNWIND)
	/* To unwind stack we need s0, which is frame pointer. */
	load_xregs sp, THREAD_TRAP_REG_S0, REG_S0
#endif

.if \mode == TRAP_MODE_USER
	/* Set scratch as thread_core_local */
	csrw	CSR_XSCRATCH, tp

	load_xregs sp, THREAD_TRAP_REG_TP, REG_TP
	load_xregs sp, THREAD_TRAP_REG_GP, REG_GP
	load_xregs sp, THREAD_TRAP_REG_SP, REG_SP

.else
	load_xregs sp, THREAD_TRAP_REG_GP, REG_GP
	load_xregs sp, THREAD_TRAP_REG_SP, REG_SP
	addi	sp, sp, THREAD_TRAP_REGS_SIZE
.endif
.endm

/* size_t __get_core_pos(void); */
FUNC __get_core_pos , : , .identity_map
	lw	a0, THREAD_CORE_LOCAL_HART_ID(tp)
	ret
END_FUNC __get_core_pos

FUNC thread_trap_vect , :
	csrrw	tp, CSR_XSCRATCH, tp
	bnez	tp, 0f
	/* Read tp back */
	csrrw	tp, CSR_XSCRATCH, tp
	j	trap_from_kernel
0:
	/* Now tp is thread_core_local */
	j	trap_from_user
thread_trap_vect_end:
END_FUNC thread_trap_vect

LOCAL_FUNC trap_from_kernel, :
	save_regs TRAP_MODE_KERNEL
	li	a3, 0
	jal	thread_trap_handler
	restore_regs TRAP_MODE_KERNEL
	XRET
END_FUNC trap_from_kernel

LOCAL_FUNC trap_from_user, :
	save_regs TRAP_MODE_USER
	li	a3, 1
	jal	thread_trap_handler
	restore_regs TRAP_MODE_USER
	XRET
END_FUNC trap_from_user

/*
 * void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
 * 		uint32_t exit_status1);
 * See description in thread.h
 */
FUNC thread_unwind_user_mode , :

	/* Store the exit status */
	load_xregs sp, THREAD_USER_MODE_REC_CTX_REGS_PTR, REG_A3, REG_A5
	sw	a1, (a4)
	sw	a2, (a5)

	/* Save user callee regs */
	store_xregs a3, THREAD_CTX_REG_S0, REG_S0, REG_S1
	store_xregs a3, THREAD_CTX_REG_S2, REG_S2, REG_S11
	store_xregs a3, THREAD_CTX_REG_SP, REG_SP, REG_TP

	/* Restore kernel callee regs */
	mv	a1, sp

	load_xregs a1, THREAD_USER_MODE_REC_X1, REG_RA, REG_GP
	load_xregs a1, THREAD_USER_MODE_REC_X8, REG_S0, REG_S1
	load_xregs a1, THREAD_USER_MODE_REC_X18, REG_S2, REG_S11

	add	sp, sp, THREAD_USER_MODE_REC_SIZE

	/* Return from the call of thread_enter_user_mode() */
	ret
END_FUNC thread_unwind_user_mode

/*
 * void thread_exit_user_mode(unsigned long a0, unsigned long a1,
 *			       unsigned long a2, unsigned long a3,
 *			       unsigned long sp, unsigned long pc,
 *			       unsigned long status);
 */
FUNC thread_exit_user_mode , :
	/* Set kernel stack pointer */
	mv	sp, a4

	/* Set xSTATUS */
	csrw	CSR_XSTATUS, a6

	/*
	 * Zeroize xSCRATCH to indicate to thread_trap_vect()
	 * that we are executing in kernel.
	 */
	csrw	CSR_XSCRATCH, zero

	/*
	 * Mask all interrupts first. Interrupts will be unmasked after
	 * returning from __thread_enter_user_mode().
	 */
	csrw	CSR_XIE, zero

	/* Set epc as thread_unwind_user_mode() */
	csrw	CSR_XEPC, a5

	XRET
END_FUNC thread_exit_user_mode

/*
 * uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
 *				     uint32_t *exit_status0,
 *				     uint32_t *exit_status1);
 */
FUNC __thread_enter_user_mode , :
	/* Disable kernel mode exceptions first */
	csrc	CSR_XSTATUS, CSR_XSTATUS_IE

	/*
	 * Create and fill in the struct thread_user_mode_rec
	 */
	addi	sp, sp, -THREAD_USER_MODE_REC_SIZE
	store_xregs sp, THREAD_USER_MODE_REC_CTX_REGS_PTR, REG_A0, REG_A2
	store_xregs sp, THREAD_USER_MODE_REC_X1, REG_RA, REG_GP
	store_xregs sp, THREAD_USER_MODE_REC_X8, REG_S0, REG_S1
	store_xregs sp, THREAD_USER_MODE_REC_X18, REG_S2, REG_S11

	/*
	 * Save the kernel stack pointer in the thread context
	 */

	/* Get pointer to current thread context */
	get_thread_ctx s0, s1

	/*
	 * Save kernel stack pointer to ensure that
	 * thread_exit_user_mode() uses correct stack pointer.
	 */

	store_xregs s0, THREAD_CTX_KERN_SP, REG_SP
	/*
	 * Save thread_core_local in xSCRATCH to ensure that thread_trap_vect()
	 * uses correct core local structure.
	 */
	csrw	CSR_XSCRATCH, tp

	/* Set user ie */
	load_xregs a0, THREAD_CTX_REG_IE, REG_S0
	csrw	CSR_XIE, s0

	/* Set user status */
	load_xregs a0, THREAD_CTX_REG_STATUS, REG_S0
	csrw	CSR_XSTATUS, s0

	/* Load the rest of the general purpose registers */
	load_xregs a0, THREAD_CTX_REG_RA, REG_RA, REG_TP
	load_xregs a0, THREAD_CTX_REG_T0, REG_T0, REG_T2
	load_xregs a0, THREAD_CTX_REG_S0, REG_S0, REG_S1
	load_xregs a0, THREAD_CTX_REG_S2, REG_S2, REG_S11
	load_xregs a0, THREAD_CTX_REG_T3, REG_T3, REG_T6
	load_xregs a0, THREAD_CTX_REG_A0, REG_A0, REG_A7

	/* Set exception program counter */
	csrw		CSR_XEPC, ra

	/* Jump into user mode */
	XRET
END_FUNC __thread_enter_user_mode

/* void thread_resume(struct thread_ctx_regs *regs) */
FUNC thread_resume , :
	/* Disable global interrupts first */
	csrc	CSR_XSTATUS, CSR_XSTATUS_IE

	/* Restore epc */
	load_xregs a0, THREAD_CTX_REG_EPC, REG_T0
	csrw	CSR_XEPC, t0

	/* Restore ie */
	load_xregs a0, THREAD_CTX_REG_IE, REG_T0
	csrw	CSR_XIE, t0

	/* Restore status */
	load_xregs a0, THREAD_CTX_REG_STATUS, REG_T0
	csrw	CSR_XSTATUS, t0

	/* Check if previous privilege mode by status.SPP */
	b_if_prev_priv_is_u t0, 1f
	/* Set scratch as zero to indicate that we are in kernel mode */
	csrw	CSR_XSCRATCH, zero
	j	2f
1:
	/* Resume to U-mode, set scratch as tp to be used in the trap handler */
	csrw	CSR_XSCRATCH, tp
2:
	/* Restore all general-purpose registers */
	load_xregs a0, THREAD_CTX_REG_RA, REG_RA, REG_TP
	load_xregs a0, THREAD_CTX_REG_T0, REG_T0, REG_T2
	load_xregs a0, THREAD_CTX_REG_S0, REG_S0, REG_S1
	load_xregs a0, THREAD_CTX_REG_S2, REG_S2, REG_S11
	load_xregs a0, THREAD_CTX_REG_T3, REG_T3, REG_T6
	load_xregs a0, THREAD_CTX_REG_A0, REG_A0, REG_A7

	XRET
END_FUNC thread_resume
