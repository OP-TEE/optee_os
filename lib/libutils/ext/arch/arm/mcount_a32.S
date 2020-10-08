/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <asm.S>

#if defined(CFG_TA_GPROF_SUPPORT) || defined(CFG_FTRACE_SUPPORT)

/*
 * Convert return address to call site address by subtracting the size of the
 * mcount call instruction (blx __gnu_mcount_nc).
 */
.macro mcount_adj_pc rd, rn
	bic	\rd, \rn, #1	/* Clear thumb bit if present */
	sub	\rd, \rd, #4
.endm

/*
 * With the -pg option, GCC (4.4+) inserts a call to __gnu_mcount_nc into
 * every function prologue.
 * The caller of the instrumented function can be determined from the lr value
 * stored on the top of the stack. The callee, i.e. the instrumented function
 * itself, is determined from the current value of lr. Then we call:
 *   void __mcount_internal(void *frompc, void *selfpc);
 */
FUNC __gnu_mcount_nc, :
UNWIND(	.cantunwind)
	stmdb		sp!, {r0-r3, lr}
#if defined(CFG_TA_GPROF_SUPPORT) && !defined(__KERNEL__)
	ldr		r0, [sp, #20]		/* lr of instrumented func */
	mcount_adj_pc	r0, r0
	mcount_adj_pc	r1, lr			/* instrumented func */
	bl		__mcount_internal
#endif
#ifdef CFG_FTRACE_SUPPORT
	/* Get instrumented function's pc value */
	ldr		r0, [sp, #16]
	mcount_adj_pc	r0, r0
	/* Get instrumented function's lr address pointer */
	sub		r1, fp, #4
	bl		ftrace_enter
#endif
	ldmia		sp!, {r0-r3, ip, lr}
	bx		ip
END_FUNC __gnu_mcount_nc

#ifdef CFG_FTRACE_SUPPORT
FUNC __ftrace_return, :
	/* save return value regs */
	stmdb		sp!, {r0-r3}

	/* get return address of parent func */
	bl		ftrace_return
	mov		lr, r0

	/* restore return value regs */
	ldmia		sp!, {r0-r3}
	bx		lr
END_FUNC __ftrace_return
#endif

#endif /* CFG_TA_GPROF_SUPPORT || CFG_FTRACE_SUPPORT */
