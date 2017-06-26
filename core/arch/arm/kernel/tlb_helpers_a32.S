/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Linaro Limited
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

#include <arm32_macros.S>
#include <asm.S>
#include <kernel/unwind.h>

	.section .text.ssvce

/* void tlbi_all(void); */
FUNC tlbi_all , :
UNWIND(	.fnstart)
	dsb	ishst		/* Sync with table update */
	write_tlbiallis 	/* Invalidate TLBs */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	bx	lr
UNWIND(	.fnend)
END_FUNC tlbi_all

/* void tlbi_mva_allasid(vaddr_t mva); */
FUNC tlbi_mva_allasid , :
UNWIND(	.fnstart)
	dsb	ishst		/* Sync with table update */
	write_tlbimvaais r0	/* Inval TLB by MVA all ASID Inner Sharable */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	bx	lr
UNWIND(	.fnend)
END_FUNC tlbi_mva_allasid

/* void tlbi_asid(unsigned long asid); */
FUNC tlbi_asid , :
UNWIND(	.fnstart)
	and     r0, r0, #0xff	/* Get ASID */
	dsb	ishst		/* Sync with table update */
	write_tlbiasidis r0	/* Inval unified TLB by ASID Inner Sharable */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	bx	lr
UNWIND(	.fnend)
END_FUNC tlbi_asid
