/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright (c) 2016, Linaro Limited
 */

#include <asm.S>

#if defined(CFG_FTRACE_SUPPORT)

/*
 * Convert return address to call site address by subtracting the size of one
 * instruction.
 */
.macro adjust_pc rd, rn
	addi	\rd, \rn, -4
.endm

#ifdef RV32

/* Get instrumented function's pc value */
.macro get_pc reg
	LDR	\reg, REGOFF(3)(sp)
	addi	\reg, \reg, -4
.endm

/* Get instrumented function's ra address pointer */
.macro get_ra_addr reg
	LDR	\reg, REGOFF(2)(sp)
	addi	\reg, \reg, -4
.endm

#else	/* RV64 */

/* Get instrumented function's pc value */
.macro get_pc reg
	LDR	\reg, REGOFF(1)(sp)
	addi	\reg, \reg, -4
.endm

/* Get instrumented function's ra address pointer */
.macro get_ra_addr reg
	LDR	\reg, REGOFF(0)(sp)
	addi	\reg, \reg, -8
.endm

#endif	/* RV32 */

/*
 * void _mcount(void *return_address)
 * @return_address: return address to instrumented function
 *
 * With the -pg option, the compiler inserts a call to _mcount into
 * every function prologue.
 * a0 contains the value of ra before the call, that is the return
 * address to the caller of the instrumented function. The callee, i.e. the
 * instrumented function itself, is determined from the current value of ra.
 * Then we call:
 *   void __mcount_internal(void *frompc, void *selfpc);
 */
FUNC _mcount, :
	addi		sp, sp, -16
	/* Save ra and s0(fp) onto stack */
#ifdef RV32
	STR		ra, REGOFF(3)(sp)
	STR		s0, REGOFF(2)(sp)
#else
	STR		ra, REGOFF(1)(sp)
	STR		s0, REGOFF(0)(sp)
#endif
	/* Setup frame pointer */
	addi		s0, sp, 16
#ifdef CFG_FTRACE_SUPPORT
	get_pc		a0
	get_ra_addr	a1
	call		ftrace_enter
#endif
	/* Restore ra and s0(fp) from stack */
#ifdef RV32
	LDR		s0, REGOFF(2)(sp)
	LDR		ra, REGOFF(3)(sp)
#else
	LDR		s0, REGOFF(0)(sp)
	LDR		ra, REGOFF(1)(sp)
#endif
	addi		sp, sp, 16
	ret
END_FUNC _mcount

#ifdef CFG_FTRACE_SUPPORT
FUNC __ftrace_return, :
	/* Save return value regs */
	addi		sp, sp, -REGOFF(8)
	STR		a0, REGOFF(0)(sp)
	STR		a1, REGOFF(1)(sp)
	STR		a2, REGOFF(2)(sp)
	STR		a3, REGOFF(3)(sp)
	STR		a4, REGOFF(4)(sp)
	STR		a5, REGOFF(5)(sp)
	STR		a6, REGOFF(6)(sp)
	STR		a7, REGOFF(7)(sp)

	/* Get return address of parent func */
	call		ftrace_return
	mv		ra, a0

	/* Restore return value regs */
	LDR		a0, REGOFF(0)(sp)
	LDR		a1, REGOFF(1)(sp)
	LDR		a2, REGOFF(2)(sp)
	LDR		a3, REGOFF(3)(sp)
	LDR		a4, REGOFF(4)(sp)
	LDR		a5, REGOFF(5)(sp)
	LDR		a6, REGOFF(6)(sp)
	LDR		a7, REGOFF(7)(sp)
	addi		sp, sp, REGOFF(8)

	ret
END_FUNC __ftrace_return
#endif

#endif /* CFG_FTRACE_SUPPORT */
