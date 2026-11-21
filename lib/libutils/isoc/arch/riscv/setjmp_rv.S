/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023,2026 NXP
 * Copyright (c) 2023 Andes Technology Corporation
 */
#include <asm.S>

/* int setjmp (jmp_buf) */
FUNC setjmp , :
	STR	s0, REGOFF(0)(a0)
	STR	s1, REGOFF(1)(a0)
	STR	s2, REGOFF(2)(a0)
	STR	s3, REGOFF(3)(a0)
	STR	s4, REGOFF(4)(a0)
	STR	s5, REGOFF(5)(a0)
	STR	s6, REGOFF(6)(a0)
	STR	s7, REGOFF(7)(a0)
	STR	s8, REGOFF(8)(a0)
	STR	s9, REGOFF(9)(a0)
	STR	s10, REGOFF(10)(a0)
	STR	s11, REGOFF(11)(a0)
	STR	ra, REGOFF(12)(a0)
	STR	sp, REGOFF(13)(a0)
#if defined(CFG_TA_ZICFISS) && !defined(__KERNEL__)
	/* Zicfiss: record the shadow stack pointer, 0 if inactive */
	ssrdp	t0
	STR	t0, REGOFF(15)(a0)
#endif
#ifdef CFG_FTRACE_SUPPORT
	addi	sp, sp, -16
#ifdef RV32
	STR	ra, REGOFF(3)(sp)
	STR	s0, REGOFF(2)(sp)
#else
	STR	ra, REGOFF(1)(sp)
	STR	s0, REGOFF(0)(sp)
#endif
	addi	s0, sp, 16
	addi	a0, a0, REGOFF(14)
	call	ftrace_setjmp
#ifdef RV32
	LDR	s0, REGOFF(2)(sp)
	LDR	ra, REGOFF(3)(sp)
#else
	LDR	s0, REGOFF(0)(sp)
	LDR	ra, REGOFF(1)(sp)
#endif
	addi	sp, sp, 16
#endif
	li 	a0, 0
	ret
END_FUNC setjmp

/* void longjmp (jmp_buf, int) __attribute__ ((noreturn)) */
FUNC longjmp , :
#ifdef CFG_FTRACE_SUPPORT
	addi	sp, sp, -REGOFF(4)
	STR	a0, REGOFF(0)(sp)
	STR	a1, REGOFF(1)(sp)
	STR	s0, REGOFF(2)(sp)
	STR	ra, REGOFF(3)(sp)
	addi	s0, sp, REGOFF(4)
	addi	a0, a0, REGOFF(14)
	call	ftrace_longjmp
	LDR	a0, REGOFF(0)(sp)
	LDR	a1, REGOFF(1)(sp)
	LDR	s0, REGOFF(2)(sp)
	LDR	ra, REGOFF(3)(sp)
	addi	sp, sp, REGOFF(4)
#endif
#if defined(__KERNEL__) && defined(CFG_CORE_SANITIZE_KADDRESS) && \
    !defined(CFG_DYN_CONFIG)
#error longjmp() stack unpoisoning not implemented for RISC-V with ASAN
#endif
	LDR	s0, REGOFF(0)(a0)
	LDR	s1, REGOFF(1)(a0)
	LDR	s2, REGOFF(2)(a0)
	LDR	s3, REGOFF(3)(a0)
	LDR	s4, REGOFF(4)(a0)
	LDR	s5, REGOFF(5)(a0)
	LDR	s6, REGOFF(6)(a0)
	LDR	s7, REGOFF(7)(a0)
	LDR	s8, REGOFF(8)(a0)
	LDR	s9, REGOFF(9)(a0)
	LDR	s10, REGOFF(10)(a0)
	LDR	s11, REGOFF(11)(a0)
#if defined(CFG_TA_ZICFISS) && !defined(__KERNEL__)
	/*
	 * Zicfiss: unwind the shadow stack to where setjmp() recorded it,
	 * the frames in between are abandoned. Walk up by at most a page
	 * at a time and touch the shadow stack at each step (SSPUSH then
	 * SSPOPCHK of the same value) so that unwinding past the end of
	 * the shadow stack faults on the guard page instead of pointing
	 * ssp at arbitrary memory. Nothing to do when the shadow stack is
	 * inactive (SSRDP reads 0).
	 */
	ssrdp	t0
	beqz	t0, 2f
	LDR	t1, REGOFF(15)(a0)
1:	bgeu	t0, t1, 2f
	sub	t2, t1, t0
	li	t3, 4096
	bltu	t2, t3, 3f
	mv	t2, t3
3:	add	t0, t0, t2
	csrw	ssp, t0
	sspush	t0
	sspopchk t0
	j	1b
2:
#endif
	LDR	ra, REGOFF(12)(a0)
	LDR	sp, REGOFF(13)(a0)
	seqz	a0, a1
	add	a0, a0, a1
	ret
END_FUNC longjmp

RISCV_CFI(emit_riscv_feature_1_and RISCV_TA_FEATURE_1_AND)
