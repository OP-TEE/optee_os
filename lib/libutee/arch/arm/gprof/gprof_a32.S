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

/* void __mcount_internal(void *frompc, void *selfpc) */

/*
 * Convert return address to call site address by subtracting the size of the
 * mcount call instruction (blx __gnu_mcount_nc).
 */
.macro mcount_adj_pc rd, rn
	bic	\rd, \rn, #1	/* Clear thumb bit if present */
	sub	\rd, \rd, #4
.endm

/*
 * With the -pg option, GCC (4.4+) inserts a call to this symbol into
 * every function prologue.
 * The caller of the instrumented function can be determined from the lr value
 * stored on the top of the stack. The callee, i.e. the instrumented function
 * itself, is determined from the current value of lr.
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

