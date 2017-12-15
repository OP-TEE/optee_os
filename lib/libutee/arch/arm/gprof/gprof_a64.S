/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <asm.S>

#ifdef CFG_TA_GPROF_SUPPORT


/*
 * Convert return address to call site address by subtracting the size of one
 * instruction.
 */
.macro adjust_pc rd, rn
	sub	\rd, \rn, #4
.endm

/*
 * void __utee_mcount(void *return_address)
 * @return_address: return address to instrumented function
 *
 * With the -pg option, the compiler inserts a call to _mcount into
 * every function prologue.
 * x0 contains the value of lr (x30) before the call, that is the return
 * address to the caller of the instrumented function. The callee, i.e. the
 * instrumented function itself, is determined from the current value of x30.
 * Then we call:
 *   void __mcount_internal(void *frompc, void *selfpc);
 *
 * _mcount is defined and set to the value of this function by the linker
 * script if the TA is instrumented, i.e., if _mcount is referenced
 */
FUNC __utee_mcount, :
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp
	adjust_pc	x0, x0
	adjust_pc	x1, x30
	bl		__mcount_internal
	ldp		x29, x30, [sp], #16
	ret
END_FUNC __utee_mcount

#else /* !CFG_TA_GPROF_SUPPORT */

/*
 * The TA linker script always references __utee_mcount so provide a version
 * that does nothing
 */
	.weak __utee_mcount
FUNC __utee_mcount, :
	ret
END_FUNC __utee_mcount

#endif /* CFG_TA_GPROF_SUPPORT */
