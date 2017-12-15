/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
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
