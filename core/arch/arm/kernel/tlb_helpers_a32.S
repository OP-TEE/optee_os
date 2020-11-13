/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Linaro Limited
 */

#include <arm32_macros.S>
#include <asm.S>

/* void tlbi_all(void); */
FUNC tlbi_all , :
	dsb	ishst		/* Sync with table update */
	write_tlbiallis 	/* Invalidate TLBs */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	bx	lr
END_FUNC tlbi_all

/* void tlbi_mva_allasid(vaddr_t mva); */
FUNC tlbi_mva_allasid , :
	dsb	ishst		/* Sync with table update */
	write_tlbimvaais r0	/* Inval TLB by MVA all ASID Inner Sharable */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	bx	lr
END_FUNC tlbi_mva_allasid

/* void tlbi_asid(unsigned long asid); */
FUNC tlbi_asid , :
	dsb	ishst		/* Sync with table update */
	write_tlbiasidis r0	/* Inval unified TLB by ASID Inner Sharable */
	orr	r0, r0, #1	/* Select the kernel ASID */
	write_tlbiasidis r0	/* Inval unified TLB by ASID Inner Sharable */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	bx	lr
END_FUNC tlbi_asid
