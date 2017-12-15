/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
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
#include <keep.h>
#include <kernel/unwind.h>

/*
 * void cpu_mmu_enable(void) - enable MMU
 *
 * TLBs are invalidated before MMU is enabled.
 * An DSB and ISB insures MMUs is enabled before routine returns
 */
FUNC cpu_mmu_enable , :
UNWIND(	.fnstart)
	/* Invalidate TLB */
	write_tlbiall

	/* Enable the MMU */
	read_sctlr r0
	orr	r0, r0, #SCTLR_M
	write_sctlr r0

	dsb
	isb

	bx	lr
UNWIND(	.fnend)
END_FUNC cpu_mmu_enable
KEEP_PAGER cpu_mmu_enable

/* void cpu_mmu_enable_icache(void) - enable instruction cache */
FUNC cpu_mmu_enable_icache , :
UNWIND(	.fnstart)
	/* Invalidate instruction cache and branch predictor */
	write_iciallu
	write_bpiall

	/* Enable the instruction cache */
	read_sctlr r1
	orr	r1, r1, #SCTLR_I
	write_sctlr r1

	dsb
	isb

	bx	lr
UNWIND(	.fnend)
END_FUNC cpu_mmu_enable_icache
KEEP_PAGER cpu_mmu_enable_icache

/* void cpu_mmu_enable_dcache(void) - enable data cache */
FUNC cpu_mmu_enable_dcache , :
UNWIND(	.fnstart)
	read_sctlr r0
	orr	r0, r0, #SCTLR_C
	write_sctlr r0

	dsb
	isb

	bx	lr
UNWIND(	.fnend)
END_FUNC cpu_mmu_enable_dcache
KEEP_PAGER cpu_mmu_enable_dcache
