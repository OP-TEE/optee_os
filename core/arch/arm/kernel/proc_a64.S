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
#include <arm64.h>
#include <asm.S>

/* void cpu_mmu_enable(void) */
FUNC cpu_mmu_enable , :
	/* Invalidate TLB */
	tlbi	vmalle1

	/*
	 * Make sure translation table writes have drained into memory and
	 * the TLB invalidation is complete.
	 */
	dsb	sy
	isb

	/* Enable the MMU */
	mrs	x0, sctlr_el1
	orr	x0, x0, #SCTLR_M
	msr	sctlr_el1, x0
	isb

	ret
END_FUNC cpu_mmu_enable

/* void cpu_mmu_enable_icache(void) */
FUNC cpu_mmu_enable_icache , :
	/* Invalidate instruction cache and branch predictor */
	ic	iallu
	isb
	mrs	x0, sctlr_el1
	orr	x0, x0, #SCTLR_I
	msr	sctlr_el1, x0
	isb
	ret
END_FUNC cpu_mmu_enable_icache


/* void cpu_mmu_enable_dcache(void) */
FUNC cpu_mmu_enable_dcache , :
	mrs	x0, sctlr_el1
	orr	x0, x0, #SCTLR_C
	msr	sctlr_el1, x0
	isb
	ret
END_FUNC cpu_mmu_enable_dcache
