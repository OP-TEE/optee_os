/*
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

	/* Please keep them sorted based on the CRn register */
	.macro read_mpidr reg
	mrc	p15, 0, \reg, c0, c0, 5
	.endm

	.macro read_sctlr reg
	mrc	p15, 0, \reg, c1, c0, 0
	.endm

	.macro write_sctlr reg
	mcr	p15, 0, \reg, c1, c0, 0
	.endm

	.macro write_actlr reg
	mcr	p15, 0, \reg, c1, c0, 1
	.endm

	.macro read_scr reg
	mrc	p15, 0, \reg, c1, c1, 0
	.endm

	.macro write_scr reg
	mcr	p15, 0, \reg, c1, c1, 0
	.endm

	.macro write_nsacr reg
	mcr	p15, 0, \reg, c1, c1, 2
	.endm

	.macro write_ttbr0 reg
	mcr	p15, 0, \reg, c2, c0, 0
	.endm

	.macro write_dacr reg
	mcr	p15, 0, \reg, c3, c0, 0
	.endm

	.macro read_dfsr reg
	mrc	p15, 0, \reg, c5, c0, 0
	.endm

	.macro write_iciallu
	/* Invalidate all instruction caches to PoU (register ignored) */
	mcr	p15, 0, r0, c7, c5, 0
	.endm

	.macro write_icialluis
	/*
	 * Invalidate all instruction caches to PoU, Inner Shareable
	 * (register ignored)
	 */
	mcr	p15, 0, r0, c7, c1, 0
	.endm

	.macro write_bpiall
	/* Invalidate entire branch predictor array (register ignored) */
	mcr	p15, 0, r0, c7, c5, 0
	.endm

	.macro write_bpiallis
	/*
	 * Invalidate entire branch predictor array, Inner Shareable
	 * (register ignored)
	 */
	mcr	p15, 0, r0, c7, c1, 6
	.endm

	.macro write_tlbiall
	/* Invalidate entire unified TLB (register ignored) */
	mcr	p15, 0, r0, c8, c7, 0
	.endm

	.macro write_tlbiallis
	/* Invalidate entire unified TLB Inner Sharable (register ignored) */
	mcr	p15, 0, r0, c8, c3, 0
	.endm

	.macro write_tlbiasidis reg
	/* Invalidate unified TLB by ASID Inner Sharable */
	mcr	p15, 0, \reg, c8, c3, 2
	.endm

	.macro write_vbar reg
	mcr	p15, 0, \reg, c12, c0, 0
	.endm

	.macro write_mvbar reg
	mcr	p15, 0, \reg, c12, c0, 1
	.endm

	.macro write_contextidr reg
	mcr	p15, 0, \reg, c13, c0, 1
	.endm

	.macro read_contextidr reg
	mrc	p15, 0, \reg, c13, c0, 1
	.endm

	.macro write_pcr reg
	mcr  p15, 0, \reg, c15, c0, 0
	.endm

	.macro read_actlr reg
	mrc	p15, 0, \reg, c1, c0, 1
	.endm

	.macro read_nsacr reg
	mrc	p15, 0, \reg, c1, c1, 2
	.endm

