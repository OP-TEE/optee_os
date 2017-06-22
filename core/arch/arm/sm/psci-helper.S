/*
 * Copyright 2017 NXP
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

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <kernel/cache_helpers.h>
#include <kernel/unwind.h>

FUNC psci_disable_smp, :
UNWIND(	.fnstart)
	read_actlr r0
	bic	r0, r0, #ACTLR_SMP
	write_actlr r0
	isb
	bx	lr
UNWIND(	.fnend)
END_FUNC psci_disable_smp

FUNC psci_enable_smp, :
UNWIND(	.fnstart)
	read_actlr r0
	orr	r0, r0, #ACTLR_SMP
	write_actlr r0
	isb
	bx	lr
UNWIND(	.fnend)
END_FUNC psci_enable_smp

FUNC psci_armv7_cpu_off, :
UNWIND(	.fnstart)
	push	{r12, lr}

	mov     r0, #DCACHE_OP_CLEAN_INV
	bl	dcache_op_all

	/* Disable Cache */
	read_sctlr r0
	bic	r0, r0, #SCTLR_C
	write_sctlr r0
	isb
	dsb

	mov	r0, #DCACHE_OP_CLEAN_INV
	bl	dcache_op_all

	clrex

	bl	psci_disable_smp

	pop	{r12, pc}
UNWIND(	.fnend)
END_FUNC psci_armv7_cpu_off
