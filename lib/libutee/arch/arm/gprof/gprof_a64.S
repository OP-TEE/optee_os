/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
