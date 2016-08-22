/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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
#include <arm64_macros.S>
#include <arm64.h>

.global asm_switch_stack_pointer

/* X0 : Jump address */
/* X1 : Stack address */
FUNC asm_switch_stack_pointer , :

	/* lr to stack */
	mov	x2, x30
	sub	sp, sp, #16
	store_xregs sp, 0, 1, 2	/* x1 is dummy (sp is 16byte alignment) */

	/* change stack pointer */
	mov	x2, sp
	mov	sp, x1

	/* save stack pointer */
	sub	sp, sp, #16
	store_xregs sp, 0, 1, 2	/* x1 is dummy (sp is 16byte alignment) */

	/* data synchronization barrier */
	dsb	sy

	/* jump to code */
	blr	x0

	/* load stack pointer */
	load_xregs sp, 0, 1, 2	/* x1 is dummy (sp is 16byte alignment) */

	/* change stack pointer */
	add	sp, sp, #16
	mov	sp, x2

	/* return */
	load_xregs sp, 0, 1, 2	/* x1 is dummy (sp is 16byte alignment) */
	add	sp, sp, #16
	mov	x30, x2
	ret
END_FUNC asm_switch_stack_pointer
