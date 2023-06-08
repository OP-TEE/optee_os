/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2017, Linaro Limited
 */

#include <arm64.h>
#include <asm.S>
#include <util.h>

/* void tlbi_all(void); */
FUNC tlbi_all , :
	dsb	ishst		/* Sync with table update */
	tlbi	vmalle1is	/* All tlb in inner shareable */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	ret
END_FUNC tlbi_all

/* void tlbi_va_allasid(vaddr_t va); */
FUNC tlbi_va_allasid , :
	lsr	x0, x0, #TLBI_VA_SHIFT
	dsb	ishst		/* Sync with table update */
	tlbi	vaae1is, x0	/* Invalidate tlb by va in inner shareable */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	ret
END_FUNC tlbi_va_allasid

/* void tlbi_asid(unsigned int asid); */
FUNC tlbi_asid , :
	lsl	x0, x0, #TLBI_ASID_SHIFT
	dsb	ishst		/* Sync with table update */
	tlbi	aside1is, x0	/* Invalidate tlb by asid in inner shareable */
	orr	x0, x0, #BIT(TLBI_ASID_SHIFT) /* Select the kernel ASID */
	tlbi	aside1is, x0	/* Invalidate tlb by asid in inner shareable */
	dsb	ish		/* Sync with tlb invalidation completion */
	isb			/* Sync execution on tlb update */
	ret
END_FUNC tlbi_asid

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
