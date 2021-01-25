/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, EPAM Systems
 */

#include <asm.S>
#include <arm.h>
#include <arm64_macros.S>
#include <kernel/cache_helpers.h>

/* uint32_t __plat_romapi_wrapper(paddr_t func, uint64_t arg1, uint64_t arg2,
 *				  uint64_t arg3)
 * Call MaskROM function func(arg1, arg2, arg3).
 * We need to disable MMU before calling any MaskROM API functions
 */
FUNC __plat_romapi_wrapper , : , .identity_map

	push	fp,  lr
	push	x19, x20
	push	x21, x22
	push	x23, x24

	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3

	/* Get PA of stack pointer */
	mov	x0, sp
#ifdef CFG_CORE_ASLR
	/*
	 * We are running at identity location, so we can't use bl there,
	 * because assembler will generate relative address to virt_to_phys(),
	 * which is not identity mapped. So we need to use absolute address.
	 */
	ldr	x9, =virt_to_phys
	blr	x9
#else
	bl	virt_to_phys
#endif
	mov	x23, x0

	/* We about to disable MMU. Make sure that all writes reached memory */
	mov     x0, #DCACHE_OP_CLEAN
#ifdef CFG_CORE_ASLR
	/* See the comment above */
	ldr	x9, =dcache_op_all
	blr	x9
#else
	bl	dcache_op_all
#endif

	/* Disable MMU */
	mrs	x9, sctlr_el1
	bic	x9, x9, #SCTLR_M
	bic	x9, x9, #SCTLR_C
	msr	sctlr_el1, x9
	isb
	/* Invalidate instruction cache and branch predictor */
	ic	ialluis
	dsb	ish	/* ensure that maintenance operations are seen */
	isb

	/* Save old SP to x24 and switch to a new stack */
	mov	x24, sp
	mov	sp, x23

	/* call the function */
	mov	x0, x20 	/* x20: uint64_t arg1 */
	mov	x1, x21		/* x21: uint64_t arg2 */
	mov	x2, x22		/* x22: uint64_t arg3 */
	blr	x19		/* x19: paddr_t func */

	/* restore sp */
	mov	sp, x24

	/* Enable MMU */
	mrs	x9, sctlr_el1
	orr	x9, x9, #SCTLR_M
	orr	x9, x9, #SCTLR_C
	msr	sctlr_el1, x9
	isb

	/* Invalidate instruction cache and branch predictor */
	ic	iallu
	isb

	pop	x23, x24
	pop	x21, x22
	pop	x19, x20
	pop	fp, lr
	ret
END_FUNC __plat_romapi_wrapper
