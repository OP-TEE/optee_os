/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <asm.S>

#ifdef CFG_TA_GPROF_SUPPORT

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
	stmdb		sp!, {r0-r3, lr}
	ldr		r0, [sp, #20]		/* lr of instrumented func */
	mcount_adj_pc	r0, r0
	mcount_adj_pc	r1, lr			/* instrumented func */
	bl		__mcount_internal
	ldmia		sp!, {r0-r3, ip, lr}
	bx		ip
END_FUNC __gnu_mcount_nc

#endif /* CFG_TA_GPROF_SUPPORT */
