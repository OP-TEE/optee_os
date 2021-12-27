/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <mm/core_mmu.h>
#include <riscv.h>

.section .data
.balign 4
.equ TRAP_MODE_CORE, 0
.equ TRAP_MODE_USER, 1

.macro save_regs, mode
	addi	sp, sp, -RISCV_TFRAME_SIZE
.if \mode == TRAP_MODE_USER
	STR	tp, RISCV_TFRAME_TP(sp)
	LDR	tp, (RISCV_TFRAME_SIZE - RISCV_XLEN_BYTES)(sp)
	STR	gp, RISCV_TFRAME_GP(sp)
	csrrw	gp, CSR_MSCRATCH, zero
	STR	gp, RISCV_TFRAME_SP(sp)
.endif
#ifdef RV64
	STR	t6, RISCV_TFRAME_T6(sp)
	STR	t5, RISCV_TFRAME_T5(sp)
	STR	t4, RISCV_TFRAME_T4(sp)
	STR	t3, RISCV_TFRAME_T3(sp)
	STR	a7, RISCV_TFRAME_A7(sp)
	STR	a6, RISCV_TFRAME_A6(sp)
#endif
	STR	t2, RISCV_TFRAME_T2(sp)
	STR	t1, RISCV_TFRAME_T1(sp)
	STR	t0, RISCV_TFRAME_T0(sp)

	STR	a5, RISCV_TFRAME_A5(sp)
	STR	a4, RISCV_TFRAME_A4(sp)
	STR	a3, RISCV_TFRAME_A3(sp)
	STR	a2, RISCV_TFRAME_A2(sp)
	STR	a1, RISCV_TFRAME_A1(sp)
	STR	a0, RISCV_TFRAME_A0(sp)
	STR	ra, RISCV_TFRAME_RA(sp)

	csrr	t0, CSR_MSTATUS
	STR	t0, RISCV_TFRAME_STATUS(sp)
	csrr	a0, CSR_MCAUSE
	csrr	a1, CSR_MEPC
	STR	a1, RISCV_TFRAME_EPC(sp)
	mv	a2, sp
    /* a0 = CSR_MCAUSE
     * a1 = CSR_MEPC
     * a2 = sp
     * thread_trap_handler(CSR_MCAUSE, CSR_MEPC, sp)
	 */
.endm

.macro restore_regs, mode
	LDR	t0, RISCV_TFRAME_EPC(sp)
	csrw	CSR_MEPC, t0
	LDR	t0, RISCV_TFRAME_STATUS(sp)
	csrw	CSR_MSTATUS, t0

	LDR	ra, RISCV_TFRAME_RA(sp)
	LDR	a0, RISCV_TFRAME_A0(sp)
	LDR	a1, RISCV_TFRAME_A1(sp)
	LDR	a2, RISCV_TFRAME_A2(sp)
	LDR	a3, RISCV_TFRAME_A3(sp)
	LDR	a4, RISCV_TFRAME_A4(sp)
	LDR	a5, RISCV_TFRAME_A5(sp)
	LDR	t0, RISCV_TFRAME_T0(sp)
	LDR	t1, RISCV_TFRAME_T1(sp)
	LDR	t2, RISCV_TFRAME_T2(sp)
#ifdef RV64
	LDR	a6, RISCV_TFRAME_A6(sp)
	LDR	a7, RISCV_TFRAME_A7(sp)
	LDR	t3, RISCV_TFRAME_T3(sp)
	LDR	t4, RISCV_TFRAME_T4(sp)
	LDR	t5, RISCV_TFRAME_T5(sp)
	LDR	t6, RISCV_TFRAME_T6(sp)
#endif
.if \mode == TRAP_MODE_USER
	addi	gp, sp, RISCV_TFRAME_SIZE
	STR	tp, REGOFF(-1)(gp)
	csrw	CSR_MSCRATCH, gp

	LDR	tp, RISCV_TFRAME_TP(sp)
	LDR	gp, RISCV_TFRAME_GP(sp)
	LDR	sp, RISCV_TFRAME_SP(sp)
.else
	addi	sp, sp, RISCV_TFRAME_SIZE
.endif
.endm

FUNC thread_trap_vect , :
	csrrw	sp, CSR_MSCRATCH, sp
	bnez	sp, _trap_from_user
	csrrw	sp, CSR_MSCRATCH, sp
	j	trap_from_core
_trap_from_user:
	j	trap_from_user
thread_trap_vect_end:
END_FUNC thread_trap_vect

LOCAL_FUNC trap_from_core, :
	save_regs	TRAP_MODE_CORE
	li	a3, 1
	jal	thread_trap_handler
	restore_regs	TRAP_MODE_CORE
	mret
END_FUNC trap_from_core

LOCAL_FUNC trap_from_user, :
	save_regs	TRAP_MODE_USER
	li	a3, 0
	jal	thread_trap_handler
	restore_regs	TRAP_MODE_USER
	mret
END_FUNC trap_from_user

/*
 * uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
 *				     uint32_t *exit_status0,
 *				     uint32_t *exit_status1);
 *
 * This function depends on being called with exceptions masked.
 */
FUNC __thread_enter_user_mode , :

	LDR	sp, RISCV_CTX_REG_SP(a0)

	LDR	t0, RISCV_CTX_REG_RA(a0)
	csrw	sepc, t0

	LDR	t1, RISCV_CTX_REG_STATUS(a0)
	csrw	sstatus, t1

	mv t0,	a2
	mv t1,	a3

	LDR	a1, RISCV_CTX_REG_A1(a0)
	LDR	a2, RISCV_CTX_REG_A2(a0)
	LDR	a3, RISCV_CTX_REG_A3(a0)
	LDR	a4, RISCV_CTX_REG_A4(a0)
	LDR	a5, RISCV_CTX_REG_A5(a0)
#ifdef RV64
	LDR	a6, RISCV_CTX_REG_A6(a0)
	LDR	a7, RISCV_CTX_REG_A7(a0)
#endif
	LDR	a0, RISCV_CTX_REG_A0(a0)

	sret

END_FUNC __thread_enter_user_mode
