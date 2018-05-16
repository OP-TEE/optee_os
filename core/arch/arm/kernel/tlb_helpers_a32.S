/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Linaro Limited
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
	dsb	ishst		/* Sync with table update */
	write_tlbiasidis r0	/* Inval unified TLB by ASID Inner Sharable */
	orr	r0, r0, #1	/* Select the kernel ASID */
	write_tlbiasidis r0	/* Inval unified TLB by ASID Inner Sharable */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	bx	lr
UNWIND(	.fnend)
END_FUNC tlbi_asid
