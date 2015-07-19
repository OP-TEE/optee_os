/*
 * Copyright (c) 2015, Linaro Limited
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

	.section .text.vfp_asm

/* void vfp_save_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]); */
FUNC vfp_save_extension_regs , :
	stp	q0, q1, [x0, #16 * 0]
	stp	q2, q3, [x0, #16 * 2]
	stp	q4, q5, [x0, #16 * 4]
	stp	q6, q7, [x0, #16 * 6]
	stp	q8, q9, [x0, #16 * 8]
	stp	q10, q11, [x0, #16 * 10]
	stp	q12, q13, [x0, #16 * 12]
	stp	q14, q15, [x0, #16 * 14]
	stp	q16, q17, [x0, #16 * 16]
	stp	q18, q19, [x0, #16 * 18]
	stp	q20, q21, [x0, #16 * 20]
	stp	q22, q23, [x0, #16 * 22]
	stp	q24, q25, [x0, #16 * 24]
	stp	q26, q27, [x0, #16 * 26]
	stp	q28, q29, [x0, #16 * 28]
	stp	q30, q31, [x0, #16 * 30]
	ret
END_FUNC vfp_save_extension_regs

/* void vfp_restore_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]); */
FUNC vfp_restore_extension_regs , :
	ldp	q0, q1, [x0, #16 * 0]
	ldp	q2, q3, [x0, #16 * 2]
	ldp	q4, q5, [x0, #16 * 4]
	ldp	q6, q7, [x0, #16 * 6]
	ldp	q8, q9, [x0, #16 * 8]
	ldp	q10, q11, [x0, #16 * 10]
	ldp	q12, q13, [x0, #16 * 12]
	ldp	q14, q15, [x0, #16 * 14]
	ldp	q16, q17, [x0, #16 * 16]
	ldp	q18, q19, [x0, #16 * 18]
	ldp	q20, q21, [x0, #16 * 20]
	ldp	q22, q23, [x0, #16 * 22]
	ldp	q24, q25, [x0, #16 * 24]
	ldp	q26, q27, [x0, #16 * 26]
	ldp	q28, q29, [x0, #16 * 28]
	ldp	q30, q31, [x0, #16 * 30]
	ret
END_FUNC vfp_restore_extension_regs
