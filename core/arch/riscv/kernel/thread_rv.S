/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 * Copyright 2024 Andes Technology Corporation
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <mm/core_mmu.h>
#include <riscv.h>
#include <riscv_macros.S>
#include <tee/optee_abi.h>
#include <tee/teeabi_opteed.h>
#include <tee/teeabi_opteed_macros.h>

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
	/* Save sp, a0, a1 into temporary spaces of thread_core_local */
	store_xregs tp, THREAD_CORE_LOCAL_X0, REG_SP
	store_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1

	csrr	a0, CSR_XCAUSE
	/* MSB of cause differentiates between interrupts and exceptions */
	bge	a0, zero, exception_from_kernel

interrupt_from_kernel:
	/* Get thread context as sp */
	get_thread_ctx sp, a0

	/* Load and save kernel sp */
	load_xregs tp, THREAD_CORE_LOCAL_X0, REG_A0
	store_xregs sp, THREAD_CTX_REG_SP, REG_A0

	/* Restore user a0, a1 which can be saved later */
	load_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1

	/* Save all other GPRs */
	store_xregs sp, THREAD_CTX_REG_RA, REG_RA
	store_xregs sp, THREAD_CTX_REG_GP, REG_GP
	store_xregs sp, THREAD_CTX_REG_T0, REG_T0, REG_T2
	store_xregs sp, THREAD_CTX_REG_S0, REG_S0, REG_S1
	store_xregs sp, THREAD_CTX_REG_A0, REG_A0, REG_A7
	store_xregs sp, THREAD_CTX_REG_S2, REG_S2, REG_S11
	store_xregs sp, THREAD_CTX_REG_T3, REG_T3, REG_T6
	/* Save XIE */
	csrr	t0, CSR_XIE
	store_xregs sp, THREAD_CTX_REG_IE, REG_T0
	/* Mask all interrupts */
	csrw	CSR_XIE, x0
	/* Save XSTATUS */
	csrr	t0, CSR_XSTATUS
	store_xregs sp, THREAD_CTX_REG_STATUS, REG_T0
	/* Save XEPC */
	csrr	t0, CSR_XEPC
	store_xregs sp, THREAD_CTX_REG_EPC, REG_T0

	/*
	 * a0 = struct thread_ctx_regs *regs
	 * a1 = cause
	 */
	mv	a0, sp
	csrr	a1, CSR_XCAUSE
	/* Load tmp_stack_va_end as current sp. */
	load_xregs tp, THREAD_CORE_LOCAL_TMP_STACK_VA_END, REG_SP

	/*
	 * Get interrupt code from XCAUSE and build XIP. For example, if the
	 * value of XCAUSE is 0x8000000000000005 (supervisor timer interrupt),
	 * we build 0x20, which is (1 << 5) and indicates the sip.STIP signal.
	 */
	li	a2, CSR_XCAUSE_INTR_FLAG
	sub	a2, a1, a2
	li	a3, 1
	sll	a3, a3, a2
	/*
	 * Compare built XIP with THREAD_EXCP_FOREIGN_INTR. If XIP is one of
	 * THREAD_EXCP_FOREIGN_INTR, we call thread_foreign_interrupt_handler().
	 */
	li	a2, THREAD_EXCP_FOREIGN_INTR
	and	a2, a3, a2
	beqz	a2, native_interrupt_from_kernel

foreign_interrupt_from_kernel:
	/*
	 * a0 = struct thread_ctx_regs *regs
	 * Tail call thread_foreign_interrupt_handler(regs) since we will not
	 * return to here.
	 */
	tail	thread_foreign_interrupt_handler

native_interrupt_from_kernel:
	/* Update 32-bit core local flags */
	lw	a2, THREAD_CORE_LOCAL_FLAGS(tp)
	slli	a2, a2, THREAD_CLF_SAVED_SHIFT
	ori	a2, a2, (THREAD_CLF_TMP | THREAD_CLF_IRQ)
	sw	a2, THREAD_CORE_LOCAL_FLAGS(tp)

	/*
	 * a0 = struct thread_ctx_regs *regs
	 * a1 = cause
	 * Call thread_native_interrupt_handler(regs, cause)
	 */
	call	thread_native_interrupt_handler

	/* Update 32-bit core local flags */
	lw	a2, THREAD_CORE_LOCAL_FLAGS(tp)
	srli	a2, a2, THREAD_CLF_SAVED_SHIFT
	sw	a2, THREAD_CORE_LOCAL_FLAGS(tp)

	/* Get thread context as sp */
	get_thread_ctx sp, t0
	/* Restore XEPC */
	load_xregs sp, THREAD_CTX_REG_EPC, REG_T0
	csrw	CSR_XEPC, t0
	/* Restore XSTATUS */
	load_xregs sp, THREAD_CTX_REG_STATUS, REG_T0
	csrw	CSR_XSTATUS, t0
	/* Restore XIE */
	load_xregs sp, THREAD_CTX_REG_IE, REG_T0
	csrw	CSR_XIE, t0
	/* We are going to XRET to kernel mode. Set XSCRATCH as 0 */
	csrw	CSR_XSCRATCH, 0
	/* Restore all GPRs */
	load_xregs sp, THREAD_CTX_REG_RA, REG_RA
	load_xregs sp, THREAD_CTX_REG_GP, REG_GP
	load_xregs sp, THREAD_CTX_REG_T0, REG_T0, REG_T2
	load_xregs sp, THREAD_CTX_REG_S0, REG_S0, REG_S1
	load_xregs sp, THREAD_CTX_REG_A0, REG_A0, REG_A7
	load_xregs sp, THREAD_CTX_REG_S2, REG_S2, REG_S11
	load_xregs sp, THREAD_CTX_REG_T3, REG_T3, REG_T6
	load_xregs sp, THREAD_CTX_REG_SP, REG_SP
	XRET

exception_from_kernel:
	/*
	 * Update core local flags.
	 * flags = (flags << THREAD_CLF_SAVED_SHIFT) | THREAD_CLF_ABORT;
	 */
	lw	a0, THREAD_CORE_LOCAL_FLAGS(tp)
	slli	a0, a0, THREAD_CLF_SAVED_SHIFT
	ori	a0, a0, THREAD_CLF_ABORT
	li	a1, (THREAD_CLF_ABORT << THREAD_CLF_SAVED_SHIFT)
	and	a1, a0, a1
	bnez	a1, sel_tmp_sp

	/* Select abort stack */
	load_xregs tp, THREAD_CORE_LOCAL_ABT_STACK_VA_END, REG_A1
	j	set_sp

sel_tmp_sp:
	/* We have an abort while using the abort stack, select tmp stack */
	load_xregs tp, THREAD_CORE_LOCAL_TMP_STACK_VA_END, REG_A1
	ori	a0, a0, THREAD_CLF_TMP	/* flags |= THREAD_CLF_TMP; */

set_sp:
	mv	sp, a1
	sw	a0, THREAD_CORE_LOCAL_FLAGS(tp)

	/*
	 * Save state on stack
	 */
	addi	sp, sp, -THREAD_ABT_REGS_SIZE

	/* Save kernel sp */
	load_xregs tp, THREAD_CORE_LOCAL_X0, REG_A0
	store_xregs sp, THREAD_ABT_REG_SP, REG_A0

	/* Restore kernel a0, a1 which can be saved later */
	load_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1

	/* Save all other GPRs */
	store_xregs sp, THREAD_ABT_REG_RA, REG_RA
	store_xregs sp, THREAD_ABT_REG_GP, REG_GP
	store_xregs sp, THREAD_ABT_REG_TP, REG_TP
	store_xregs sp, THREAD_ABT_REG_T0, REG_T0, REG_T2
	store_xregs sp, THREAD_ABT_REG_S0, REG_S0, REG_S1
	store_xregs sp, THREAD_ABT_REG_A0, REG_A0, REG_A7
	store_xregs sp, THREAD_ABT_REG_S2, REG_S2, REG_S11
	store_xregs sp, THREAD_ABT_REG_T3, REG_T3, REG_T6
	/* Save XIE */
	csrr	t0, CSR_XIE
	store_xregs sp, THREAD_ABT_REG_IE, REG_T0
	/* Mask all interrupts */
	csrw	CSR_XIE, x0
	/* Save XSTATUS */
	csrr	t0, CSR_XSTATUS
	store_xregs sp, THREAD_ABT_REG_STATUS, REG_T0
	/* Save XEPC */
	csrr	t0, CSR_XEPC
	store_xregs sp, THREAD_ABT_REG_EPC, REG_T0
	/* Save XTVAL */
	csrr	t0, CSR_XTVAL
	store_xregs sp, THREAD_ABT_REG_TVAL, REG_T0
	/* Save XCAUSE */
	csrr	a0, CSR_XCAUSE
	store_xregs sp, THREAD_ABT_REG_CAUSE, REG_A0

	/*
	 * a0 = cause
	 * a1 = sp (struct thread_abort_regs *regs)
	 * Call abort_handler(cause, regs)
	 */
	mv	a1, sp
	call	abort_handler

	/*
	 * Restore state from stack
	 */

	/* Restore XEPC */
	load_xregs sp, THREAD_ABT_REG_EPC, REG_T0
	csrw	CSR_XEPC, t0
	/* Restore XSTATUS */
	load_xregs sp, THREAD_ABT_REG_STATUS, REG_T0
	csrw	CSR_XSTATUS, t0
	/* Restore XIE */
	load_xregs sp, THREAD_ABT_REG_IE, REG_T0
	csrw	CSR_XIE, t0
	/* We are going to XRET to kernel mode. Set XSCRATCH as 0 */
	csrw	CSR_XSCRATCH, 0

	/* Update core local flags */
	lw	a0, THREAD_CORE_LOCAL_FLAGS(tp)
	srli	a0, a0, THREAD_CLF_SAVED_SHIFT
	sw	a0, THREAD_CORE_LOCAL_FLAGS(tp)

	/* Restore all GPRs */
	load_xregs sp, THREAD_ABT_REG_RA, REG_RA
	load_xregs sp, THREAD_ABT_REG_GP, REG_GP
	load_xregs sp, THREAD_ABT_REG_TP, REG_TP
	load_xregs sp, THREAD_ABT_REG_T0, REG_T0, REG_T2
	load_xregs sp, THREAD_ABT_REG_S0, REG_S0, REG_S1
	load_xregs sp, THREAD_ABT_REG_A0, REG_A0, REG_A7
	load_xregs sp, THREAD_ABT_REG_S2, REG_S2, REG_S11
	load_xregs sp, THREAD_ABT_REG_T3, REG_T3, REG_T6
	load_xregs sp, THREAD_ABT_REG_SP, REG_SP
	XRET
END_FUNC trap_from_kernel

LOCAL_FUNC trap_from_user, :
	/* Save user sp, a0, a1 into temporary spaces of thread_core_local */
	store_xregs tp, THREAD_CORE_LOCAL_X0, REG_SP
	store_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1

	csrr	a0, CSR_XCAUSE
	/* MSB of cause differentiates between interrupts and exceptions */
	bge	a0, zero, exception_from_user

interrupt_from_user:
	/* Get thread context as sp */
	get_thread_ctx sp, a0

	/* Save user sp */
	load_xregs tp, THREAD_CORE_LOCAL_X0, REG_A0
	store_xregs sp, THREAD_CTX_REG_SP, REG_A0

	/* Restore user a0, a1 which can be saved later */
	load_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1

	/* Save user gp */
	store_xregs sp, THREAD_CTX_REG_GP, REG_GP

	/*
	 * Set the scratch register to 0 such in case of a recursive
	 * exception thread_trap_vect() knows that it is emitted from kernel.
	 */
	csrrw	gp, CSR_XSCRATCH, zero
	/* Save user tp we previously swapped into CSR_XSCRATCH */
	store_xregs sp, THREAD_CTX_REG_TP, REG_GP
	/* Set kernel gp */
.option push
.option norelax
	la	gp, __global_pointer$
.option pop
	/* Save all other GPRs */
	store_xregs sp, THREAD_CTX_REG_RA, REG_RA
	store_xregs sp, THREAD_CTX_REG_T0, REG_T0, REG_T2
	store_xregs sp, THREAD_CTX_REG_S0, REG_S0, REG_S1
	store_xregs sp, THREAD_CTX_REG_A0, REG_A0, REG_A7
	store_xregs sp, THREAD_CTX_REG_S2, REG_S2, REG_S11
	store_xregs sp, THREAD_CTX_REG_T3, REG_T3, REG_T6
	/* Save XIE */
	csrr	t0, CSR_XIE
	store_xregs sp, THREAD_CTX_REG_IE, REG_T0
	/* Mask all interrupts */
	csrw	CSR_XIE, x0
	/* Save XSTATUS */
	csrr	t0, CSR_XSTATUS
	store_xregs sp, THREAD_CTX_REG_STATUS, REG_T0
	/* Save XEPC */
	csrr	t0, CSR_XEPC
	store_xregs sp, THREAD_CTX_REG_EPC, REG_T0

	/*
	 * a0 = struct thread_ctx_regs *regs
	 * a1 = cause
	 */
	mv	a0, sp
	csrr	a1, CSR_XCAUSE
	/* Load tmp_stack_va_end as current sp. */
	load_xregs tp, THREAD_CORE_LOCAL_TMP_STACK_VA_END, REG_SP

	/*
	 * Get interrupt code from XCAUSE and build XIP. For example, if the
	 * value of XCAUSE is 0x8000000000000005 (supervisor timer interrupt),
	 * we build 0x20, which is (1 << 5) and indicates the sip.STIP signal.
	 */
	li	a2, CSR_XCAUSE_INTR_FLAG
	sub	a2, a1, a2
	li	a3, 1
	sll	a3, a3, a2
	/*
	 * Compare built XIP with THREAD_EXCP_FOREIGN_INTR. If XIP is one of
	 * THREAD_EXCP_FOREIGN_INTR, call thread_foreign_interrupt_handler().
	 */
	li	a2, THREAD_EXCP_FOREIGN_INTR
	and	a2, a3, a2
	beqz	a2, native_interrupt_from_user

foreign_interrupt_from_user:
	/*
	 * a0 = struct thread_ctx_regs *regs
	 * Tail call thread_foreign_interrupt_handler(regs) since we will not
	 * return to here.
	 */
	tail	thread_foreign_interrupt_handler

native_interrupt_from_user:
	/* Update 32-bit core local flags */
	lw	a2, THREAD_CORE_LOCAL_FLAGS(tp)
	slli	a2, a2, THREAD_CLF_SAVED_SHIFT
	ori	a2, a2, (THREAD_CLF_TMP | THREAD_CLF_IRQ)
	sw	a2, THREAD_CORE_LOCAL_FLAGS(tp)

	/*
	 * a0 = struct thread_ctx_regs *regs
	 * a1 = cause
	 * Call thread_native_interrupt_handler(regs, cause)
	 */
	call	thread_native_interrupt_handler

	/* Update 32-bit core local flags */
	lw	a2, THREAD_CORE_LOCAL_FLAGS(tp)
	srli	a2, a2, THREAD_CLF_SAVED_SHIFT
	sw	a2, THREAD_CORE_LOCAL_FLAGS(tp)

	/* Get thread context as sp */
	get_thread_ctx sp, t0
	/* Restore XEPC */
	load_xregs sp, THREAD_CTX_REG_EPC, REG_T0
	csrw	CSR_XEPC, t0
	/* Restore XSTATUS */
	load_xregs sp, THREAD_CTX_REG_STATUS, REG_T0
	csrw	CSR_XSTATUS, t0
	/* Restore XIE */
	load_xregs sp, THREAD_CTX_REG_IE, REG_T0
	csrw	CSR_XIE, t0
	/* Set scratch as thread_core_local */
	csrw	CSR_XSCRATCH, tp
	/* Restore all GPRs */
	load_xregs sp, THREAD_CTX_REG_RA, REG_RA
	load_xregs sp, THREAD_CTX_REG_GP, REG_GP
	load_xregs sp, THREAD_CTX_REG_TP, REG_TP
	load_xregs sp, THREAD_CTX_REG_T0, REG_T0, REG_T2
	load_xregs sp, THREAD_CTX_REG_S0, REG_S0, REG_S1
	load_xregs sp, THREAD_CTX_REG_A0, REG_A0, REG_A7
	load_xregs sp, THREAD_CTX_REG_S2, REG_S2, REG_S11
	load_xregs sp, THREAD_CTX_REG_T3, REG_T3, REG_T6
	load_xregs sp, THREAD_CTX_REG_SP, REG_SP
	XRET

exception_from_user:
	/* a0 is CSR_XCAUSE */
	li	a1, CAUSE_USER_ECALL
	bne	a0, a1, abort_from_user
ecall_from_user:
	/* Load and set kernel sp from thread context */
	get_thread_ctx a0, a1
	load_xregs a0, THREAD_CTX_KERN_SP, REG_SP

	/* Now sp is kernel sp, create stack for struct thread_scall_regs */
	addi	sp, sp, -THREAD_SCALL_REGS_SIZE
	/* Save user sp */
	load_xregs tp, THREAD_CORE_LOCAL_X0, REG_A0
	store_xregs sp, THREAD_SCALL_REG_SP, REG_A0

	/* Restore user a0, a1 which can be saved later */
	load_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1

	/* Save user gp */
	store_xregs sp, THREAD_SCALL_REG_GP, REG_GP
	/*
	 * Set the scratch register to 0 such in case of a recursive
	 * exception thread_trap_vect() knows that it is emitted from kernel.
	 */
	csrrw	gp, CSR_XSCRATCH, zero
	/* Save user tp we previously swapped into CSR_XSCRATCH */
	store_xregs sp, THREAD_SCALL_REG_TP, REG_GP
	/* Set kernel gp */
.option push
.option norelax
	la	gp, __global_pointer$
.option pop

	/* Save other caller-saved registers */
	store_xregs sp, THREAD_SCALL_REG_RA, REG_RA
	store_xregs sp, THREAD_SCALL_REG_T0, REG_T0, REG_T2
	store_xregs sp, THREAD_SCALL_REG_A0, REG_A0, REG_A7
	store_xregs sp, THREAD_SCALL_REG_T3, REG_T3, REG_T6
	/* Save XIE */
	csrr	a0, CSR_XIE
	store_xregs sp, THREAD_SCALL_REG_IE, REG_A0
	/* Mask all interrupts */
	csrw	CSR_XIE, zero
	/* Save XSTATUS */
	csrr	a0, CSR_XSTATUS
	store_xregs sp, THREAD_SCALL_REG_STATUS, REG_A0
	/* Save XEPC */
	csrr	a0, CSR_XEPC
	store_xregs sp, THREAD_SCALL_REG_EPC, REG_A0

	/*
	 * a0 = struct thread_scall_regs *regs
	 * Call thread_scall_handler(regs)
	 */
	mv	a0, sp
	call	thread_scall_handler

	/*
	 * Save kernel sp we'll had at the beginning of this function.
	 * This is when this TA has called another TA because
	 * __thread_enter_user_mode() also saves the stack pointer in this
	 * field.
	 */
	get_thread_ctx a0, a1
	addi	t0, sp, THREAD_SCALL_REGS_SIZE
	store_xregs a0, THREAD_CTX_KERN_SP, REG_T0

	/* Restore XEPC */
	load_xregs sp, THREAD_SCALL_REG_EPC, REG_T0
	csrw	CSR_XEPC, t0
	/* Restore XSTATUS */
	load_xregs sp, THREAD_SCALL_REG_STATUS, REG_T0
	csrw	CSR_XSTATUS, t0
	/* Restore XIE */
	load_xregs sp, THREAD_SCALL_REG_IE, REG_T0
	csrw	CSR_XIE, t0
	/* Check previous privilege mode by status.SPP */
	csrr	t0, CSR_XSTATUS
	b_if_prev_priv_is_u t0, 1f
	/*
	 * We are going to XRET to kernel mode.
	 * XSCRATCH is already zero to indicate that we are in kernel mode.
	 * We must keep kernel gp & tp, so skip restoring user gp & tp.
	 */
	j	2f
1:
	/*
	 * We are going to XRET to user mode.
	 * XSCRATCH must be tp(thread_core_local) to be used in next trap.
	 * We also need to restore user gp & tp
	 */
	csrw	CSR_XSCRATCH, tp
	load_xregs sp, THREAD_SCALL_REG_GP, REG_GP
	load_xregs sp, THREAD_SCALL_REG_TP, REG_TP
2:
	/* Restore remaining caller-saved registers */
	load_xregs sp, THREAD_SCALL_REG_RA, REG_RA
	load_xregs sp, THREAD_SCALL_REG_T0, REG_T0, REG_T2
	load_xregs sp, THREAD_SCALL_REG_A0, REG_A0, REG_A7
	load_xregs sp, THREAD_SCALL_REG_T3, REG_T3, REG_T6
	load_xregs sp, THREAD_SCALL_REG_SP, REG_SP
	XRET

abort_from_user:
	/*
	 * Update core local flags
	 */
	lw	a0, THREAD_CORE_LOCAL_FLAGS(tp)
	slli	a0, a0, THREAD_CLF_SAVED_SHIFT
	ori	a0, a0, THREAD_CLF_ABORT
	sw	a0, THREAD_CORE_LOCAL_FLAGS(tp)

	/*
	 * Save state on stack
	 */

	/* Load abt_stack_va_end and set it as sp */
	load_xregs tp, THREAD_CORE_LOCAL_ABT_STACK_VA_END, REG_SP

	/* Now sp is abort sp, create stack for struct thread_abort_regs */
	addi	sp, sp, -THREAD_ABT_REGS_SIZE

	/* Save user sp */
	load_xregs tp, THREAD_CORE_LOCAL_X0, REG_A0
	store_xregs sp, THREAD_ABT_REG_SP, REG_A0

	/* Restore user a0, a1 which can be saved later */
	load_xregs tp, THREAD_CORE_LOCAL_X1, REG_A0, REG_A1

	/* Save user gp */
	store_xregs sp, THREAD_ABT_REG_GP, REG_GP

	/*
	 * Set the scratch register to 0 such in case of a recursive
	 * exception thread_trap_vect() knows that it is emitted from kernel.
	 */
	csrrw	gp, CSR_XSCRATCH, zero
	/* Save user tp we previously swapped into CSR_XSCRATCH */
	store_xregs sp, THREAD_ABT_REG_TP, REG_GP
	/* Set kernel gp */
.option push
.option norelax
	la	gp, __global_pointer$
.option pop
	/* Save all other GPRs */
	store_xregs sp, THREAD_ABT_REG_RA, REG_RA
	store_xregs sp, THREAD_ABT_REG_T0, REG_T0, REG_T2
	store_xregs sp, THREAD_ABT_REG_S0, REG_S0, REG_S1
	store_xregs sp, THREAD_ABT_REG_A0, REG_A0, REG_A7
	store_xregs sp, THREAD_ABT_REG_S2, REG_S2, REG_S11
	store_xregs sp, THREAD_ABT_REG_T3, REG_T3, REG_T6
	/* Save XIE */
	csrr	t0, CSR_XIE
	store_xregs sp, THREAD_ABT_REG_IE, REG_T0
	/* Mask all interrupts */
	csrw	CSR_XIE, x0
	/* Save XSTATUS */
	csrr	t0, CSR_XSTATUS
	store_xregs sp, THREAD_ABT_REG_STATUS, REG_T0
	/* Save XEPC */
	csrr	t0, CSR_XEPC
	store_xregs sp, THREAD_ABT_REG_EPC, REG_T0
	/* Save XTVAL */
	csrr	t0, CSR_XTVAL
	store_xregs sp, THREAD_ABT_REG_TVAL, REG_T0
	/* Save XCAUSE */
	csrr	a0, CSR_XCAUSE
	store_xregs sp, THREAD_ABT_REG_CAUSE, REG_A0

	/*
	 * a0 = cause
	 * a1 = sp (struct thread_abort_regs *regs)
	 * Call abort_handler(cause, regs)
	 */
	mv	a1, sp
	call	abort_handler

	/*
	 * Restore state from stack
	 */

	/* Restore XEPC */
	load_xregs sp, THREAD_ABT_REG_EPC, REG_T0
	csrw	CSR_XEPC, t0
	/* Restore XSTATUS */
	load_xregs sp, THREAD_ABT_REG_STATUS, REG_T0
	csrw	CSR_XSTATUS, t0
	/* Restore XIE */
	load_xregs sp, THREAD_ABT_REG_IE, REG_T0
	csrw	CSR_XIE, t0

	/* Update core local flags */
	lw	a0, THREAD_CORE_LOCAL_FLAGS(tp)
	srli	a0, a0, THREAD_CLF_SAVED_SHIFT
	sw	a0, THREAD_CORE_LOCAL_FLAGS(tp)

	/* Check previous privilege mode by status.SPP */
	csrr	t0, CSR_XSTATUS
	b_if_prev_priv_is_u t0, 1f
	/*
	 * We are going to XRET to kernel mode.
	 * XSCRATCH is already zero to indicate that we are in kernel mode.
	 * We must keep kernel gp & tp, so skip restoring user gp & tp.
	 */
	j	2f
1:
	/*
	 * We are going to XRET to user mode.
	 * XSCRATCH must be tp(thread_core_local) to be used in next trap.
	 * We also need to restore user gp & tp
	 */
	csrw	CSR_XSCRATCH, tp
	load_xregs sp, THREAD_ABT_REG_GP, REG_GP
	load_xregs sp, THREAD_ABT_REG_TP, REG_TP
2:
	/* Restore remaining GPRs */
	load_xregs sp, THREAD_ABT_REG_RA, REG_RA
	load_xregs sp, THREAD_ABT_REG_T0, REG_T0, REG_T2
	load_xregs sp, THREAD_ABT_REG_S0, REG_S0, REG_S1
	load_xregs sp, THREAD_ABT_REG_A0, REG_A0, REG_A7
	load_xregs sp, THREAD_ABT_REG_S2, REG_S2, REG_S11
	load_xregs sp, THREAD_ABT_REG_T3, REG_T3, REG_T6
	load_xregs sp, THREAD_ABT_REG_SP, REG_SP
	XRET
END_FUNC trap_from_user

/*
 * void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
 * 				uint32_t exit_status1);
 * See description in thread.h
 */
FUNC thread_unwind_user_mode , :
	/* Store the exit status */
	load_xregs sp, THREAD_USER_MODE_REC_CTX_REGS_PTR, REG_A3, REG_A5
	sw	a1, (a4)
	sw	a2, (a5)
	/* Save user callee-saved regs */
	store_xregs a3, THREAD_CTX_REG_S0, REG_S0, REG_S1
	store_xregs a3, THREAD_CTX_REG_S2, REG_S2, REG_S11
	/* Restore kernel ra(thread_enter_user_mode()) & callee-saved regs */
	load_xregs sp, THREAD_USER_MODE_REC_RA, REG_RA
	load_xregs sp, THREAD_USER_MODE_REC_S0, REG_S0, REG_S1
	load_xregs sp, THREAD_USER_MODE_REC_S2, REG_S2, REG_S11
	add	sp, sp, THREAD_USER_MODE_REC_SIZE
	/* Return from the call of thread_enter_user_mode() */
	ret
END_FUNC thread_unwind_user_mode

/*
 * uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
 *				     uint32_t *exit_status0,
 *				     uint32_t *exit_status1);
 */
FUNC __thread_enter_user_mode , :
	/*
	 * Create and fill in the struct thread_user_mode_rec
	 */
	addi	sp, sp, -THREAD_USER_MODE_REC_SIZE
	store_xregs sp, THREAD_USER_MODE_REC_CTX_REGS_PTR, REG_A0, REG_A2
	store_xregs sp, THREAD_USER_MODE_REC_RA, REG_RA
	store_xregs sp, THREAD_USER_MODE_REC_S0, REG_S0, REG_S1
	store_xregs sp, THREAD_USER_MODE_REC_S2, REG_S2, REG_S11

	/*
	 * Save the kernel stack pointer in the thread context
	 */

	/* Get pointer to current thread context */
	get_thread_ctx s0, s1

	/*
	 * Save kernel stack pointer to ensure that
	 * exception_from_user() uses correct stack pointer.
	 */

	store_xregs s0, THREAD_CTX_KERN_SP, REG_SP
	/*
	 * Save thread_core_local in xSCRATCH to ensure that thread_trap_vect()
	 * uses correct core local structure.
	 */
	csrw	CSR_XSCRATCH, tp

	/* Move struct thread_ctx_regs *regs to sp to reduce code size */
	mv	sp, a0

	/* Set exception return PC */
	load_xregs sp, THREAD_CTX_REG_EPC, REG_S0
	csrw	CSR_XEPC, s0
	/* Set user status */
	load_xregs sp, THREAD_CTX_REG_STATUS, REG_S0
	csrw	CSR_XSTATUS, s0
	/* Set user ie */
	load_xregs sp, THREAD_CTX_REG_IE, REG_S0
	csrw	CSR_XIE, s0
	/* Load the rest of the general purpose registers */
	load_xregs sp, THREAD_CTX_REG_RA, REG_RA
	load_xregs sp, THREAD_CTX_REG_GP, REG_GP
	load_xregs sp, THREAD_CTX_REG_TP, REG_TP
	load_xregs sp, THREAD_CTX_REG_T0, REG_T0, REG_T2
	load_xregs sp, THREAD_CTX_REG_S0, REG_S0, REG_S1
	load_xregs sp, THREAD_CTX_REG_A0, REG_A0, REG_A7
	load_xregs sp, THREAD_CTX_REG_S2, REG_S2, REG_S11
	load_xregs sp, THREAD_CTX_REG_T3, REG_T3, REG_T6
	load_xregs sp, THREAD_CTX_REG_SP, REG_SP /* sp must be last one */

	/* Jump into user mode */
	XRET
END_FUNC __thread_enter_user_mode

/* void thread_resume(struct thread_ctx_regs *regs) */
FUNC thread_resume , :
	/* Move struct thread_ctx_regs *regs to sp to reduce code size */
	mv	sp, a0

	/* Restore epc */
	load_xregs sp, THREAD_CTX_REG_EPC, REG_T0
	csrw	CSR_XEPC, t0
	/* Restore status */
	load_xregs sp, THREAD_CTX_REG_STATUS, REG_T0
	csrw	CSR_XSTATUS, t0
	/* Restore ie */
	load_xregs sp, THREAD_CTX_REG_IE, REG_T0
	csrw	CSR_XIE, t0

	/* Check if previous privilege mode by status.SPP */
	csrr	t0, CSR_XSTATUS
	b_if_prev_priv_is_u t0, 1f
	/* Set scratch as zero to indicate that we are in kernel mode */
	csrw	CSR_XSCRATCH, zero
	j	2f
1:
	/* Resume to U-mode, set scratch as tp to be used in the trap handler */
	csrw	CSR_XSCRATCH, tp
2:
	/* Restore all general-purpose registers */
	load_xregs sp, THREAD_CTX_REG_RA, REG_RA
	load_xregs sp, THREAD_CTX_REG_GP, REG_GP
	load_xregs sp, THREAD_CTX_REG_TP, REG_TP
	load_xregs sp, THREAD_CTX_REG_T0, REG_T0, REG_T2
	load_xregs sp, THREAD_CTX_REG_S0, REG_S0, REG_S1
	load_xregs sp, THREAD_CTX_REG_A0, REG_A0, REG_A7
	load_xregs sp, THREAD_CTX_REG_S2, REG_S2, REG_S11
	load_xregs sp, THREAD_CTX_REG_T3, REG_T3, REG_T6
	load_xregs sp, THREAD_CTX_REG_SP, REG_SP /* sp must be last one */

	XRET
END_FUNC thread_resume

/* void thread_foreign_interrupt_handler(struct thread_ctx_regs *regs) */
FUNC thread_foreign_interrupt_handler , :
	/* Update 32-bit core local flags */
	lw	s1, THREAD_CORE_LOCAL_FLAGS(tp)
	slli	s1, s1, THREAD_CLF_SAVED_SHIFT
	ori	s1, s1, (THREAD_CLF_TMP | THREAD_CLF_FIQ)
	sw	s1, THREAD_CORE_LOCAL_FLAGS(tp)

	/*
	 * Mark current thread as suspended.
	 * a0 = THREAD_FLAGS_EXIT_ON_FOREIGN_INTR
	 * a1 = status
	 * a2 = epc
	 * thread_state_suspend(flags, status, pc)
	 */
	LDR	a1, THREAD_CTX_REG_STATUS(a0)
	LDR	a2, THREAD_CTX_REG_EPC(a0)
	li	a0, THREAD_FLAGS_EXIT_ON_FOREIGN_INTR
	call	thread_state_suspend
	/* Now return value a0 contains suspended thread ID. */

	/* Update core local flags */
	lw	s1, THREAD_CORE_LOCAL_FLAGS(tp)
	srli	s1, s1, THREAD_CLF_SAVED_SHIFT
	ori	s1, s1, THREAD_CLF_TMP
	sw	s1, THREAD_CORE_LOCAL_FLAGS(tp)

	/* Passing thread index in a0, and return to untrusted domain. */
	mv	a4, a0
	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE
	li	a1, OPTEE_ABI_RETURN_RPC_FOREIGN_INTR
	li	a2, 0
	li	a3, 0
	li	a5, 0
	j	thread_return_to_udomain
END_FUNC thread_foreign_interrupt_handler
