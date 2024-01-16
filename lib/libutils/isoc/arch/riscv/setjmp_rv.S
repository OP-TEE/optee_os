/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022-2023 NXP
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
	LDR	ra, REGOFF(12)(a0)
	LDR	sp, REGOFF(13)(a0)
	seqz	a0, a1
	add	a0, a0, a1
	ret
END_FUNC longjmp
