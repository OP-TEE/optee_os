/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */
#include <asm.S>

#ifdef RV32
#define STR       sw
#define LDR       lw
#define REGOFF(x) ((x) * 4)
#else
#define STR       sd
#define LDR       ld
#define REGOFF(x) ((x) * 8)
#endif /*RV32*/

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
	STR	ra, (sp)
	mov	x29, sp
	addi	a0, a0, REGOFF(12)
	jal	ftrace_setjmp
	LDR	ra, (sp)
	addi	sp, sp, 16
#endif
	li 	a0, 0
	ret
END_FUNC setjmp

/* void longjmp (jmp_buf, int) __attribute__ ((noreturn)) */
FUNC longjmp , :
#ifdef CFG_FTRACE_SUPPORT
	addi	sp, sp, -16
	STR	a0, REGOFF(0)(sp)
	STR	a1, REGOFF(1)(sp)
	STR	ra, REGOFF(2)(sp)
	addi	a0, a0, REGOFF(12)
	jal	ftrace_longjmp
	LDR	a0, REGOFF(0)(sp)
	LDR	a1, REGOFF(1)(sp)
	LDR	ra, REGOFF(2)(sp)
	addi	sp, sp, 16
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
