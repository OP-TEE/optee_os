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

	.macro FUNC name colon
	.global \name
	.type \name , %function
	\name \colon
	.endm

	.macro END_FUNC name
	.size \name , .-\name
	.endm

	.section .text
	.balign 4
	.code  32

/*
 * __value_in_regs lldiv_t __aeabi_ldivmod( long long n, long long d)
 */
FUNC __aeabi_ldivmod , :
	push	{ip, lr}
	push	{r0-r3}
	mov	r0, sp
	bl	__l_divmod
	pop	{r0-r3}
	pop	{ip, pc}
END_FUNC __aeabi_uldivmod

/*
 * __value_in_regs ulldiv_t __aeabi_uldivmod(
 *		unsigned long long n, unsigned long long d)
 */
FUNC __aeabi_uldivmod , :
	push	{ip, lr}
	push	{r0-r3}
	mov	r0, sp
	bl	__ul_divmod
	pop	{r0-r3}
	pop	{ip, pc}
END_FUNC __aeabi_uldivmod
