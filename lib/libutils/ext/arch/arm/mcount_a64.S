/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <asm.S>

#if defined(CFG_TA_GPROF_SUPPORT) || defined(CFG_FTRACE_SUPPORT)

/*
 * Convert return address to call site address by subtracting the size of one
 * instruction.
 */
.macro adjust_pc rd, rn
	sub	\rd, \rn, #4
.endm

/* Get instrumented function's pc value */
.macro get_pc reg
	ldr	\reg, [x29, #8]
	sub	\reg, \reg, #4
.endm

/* Get instrumented function's lr address pointer */
.macro get_lr_addr reg
	ldr	\reg, [x29]
	add	\reg, \reg, #8
.endm

/*
 * void _mcount(void *return_address)
 * @return_address: return address to instrumented function
 *
 * With the -pg option, the compiler inserts a call to _mcount into
 * every function prologue.
 * x0 contains the value of lr (x30) before the call, that is the return
 * address to the caller of the instrumented function. The callee, i.e. the
 * instrumented function itself, is determined from the current value of x30.
 * Then we call:
 *   void __mcount_internal(void *frompc, void *selfpc);
 */
FUNC _mcount, :
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp
#if defined(CFG_TA_GPROF_SUPPORT) && !defined(__KERNEL__)
	adjust_pc	x0, x0
	adjust_pc	x1, x30
	bl		__mcount_internal
#endif
#ifdef CFG_FTRACE_SUPPORT
	get_pc		x0
	get_lr_addr	x1
	bl		ftrace_enter
#endif
	ldp		x29, x30, [sp], #16
	ret
END_FUNC _mcount

#ifdef CFG_FTRACE_SUPPORT
FUNC __ftrace_return, :
	/* Save return value regs */
	sub		sp, sp, #64
	stp		x0, x1, [sp]
	stp		x2, x3, [sp, #16]
	stp		x4, x5, [sp, #32]
	stp		x6, x7, [sp, #48]

	/* Get return address of parent func */
	bl		ftrace_return
	mov		x30, x0

	/* Restore return value regs */
	ldp		x0, x1, [sp]
	ldp		x2, x3, [sp, #16]
	ldp		x4, x5, [sp, #32]
	ldp		x6, x7, [sp, #48]
	add		sp, sp, #64

	ret
END_FUNC __ftrace_return
#endif

#endif /* CFG_TA_GPROF_SUPPORT || CFG_FTRACE_SUPPORT */

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
