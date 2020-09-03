/*
 * Copyright (c) 2017, Linaro Limited. All rights reserved.
 * Copyright (c) 2016, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <kernel/cache_helpers.h>

/*
 * Cache line size helpers
 */
.macro  dcache_line_size  reg, tmp
	read_ctr \tmp
	ubfx    \tmp, \tmp, #CTR_DMINLINE_SHIFT, #CTR_DMINLINE_WIDTH
	mov     \reg, #CTR_WORD_SIZE
	lsl     \reg, \reg, \tmp
.endm

.macro  icache_line_size  reg, tmp
	read_ctr \tmp
	and     \tmp, \tmp, #CTR_IMINLINE_MASK
	mov     \reg, #CTR_WORD_SIZE
	lsl     \reg, \reg, \tmp
.endm

/*
 * This macro can be used for implementing various data cache operations `op`
 */
.macro do_dcache_maintenance_by_mva reg
	dcache_line_size r2, r3
	add	r1, r0, r1
	sub	r3, r2, #1
	bic	r0, r0, r3
loop_\reg:
	write_\reg	r0
	add	r0, r0, r2
	cmp	r0, r1
	blo	loop_\reg
	dsb	sy
	bx	lr
.endm

	/* ------------------------------------------
	 * Clean+Invalidate from base address till
	 * size. 'r0' = addr, 'r1' = size
	 * ------------------------------------------
	 */
FUNC dcache_cleaninv_range , :
	do_dcache_maintenance_by_mva dccimvac
END_FUNC dcache_cleaninv_range

	/* ------------------------------------------
	 * Clean from base address till size.
	 * 'r0' = addr, 'r1' = size
	 * ------------------------------------------
	 */
FUNC dcache_clean_range , :
	do_dcache_maintenance_by_mva dccmvac
END_FUNC dcache_clean_range

	/* ------------------------------------------
	 * Invalidate from base address till
	 * size. 'r0' = addr, 'r1' = size
	 * ------------------------------------------
	 */
FUNC dcache_inv_range , :
	do_dcache_maintenance_by_mva dcimvac
END_FUNC dcache_inv_range


	/* ------------------------------------------
	 * Clean from base address till size to point of unification
	 * 'r0' = addr, 'r1' = size
	 * ------------------------------------------
	 */
FUNC dcache_clean_range_pou , :
	do_dcache_maintenance_by_mva dccmvau
END_FUNC dcache_clean_range_pou

	/* ----------------------------------------------------------------
	 * Data cache operations by set/way to the level specified
	 *
	 * The main function, do_dcsw_op requires:
	 * r0: The operation type (DCACHE_OP_INV, DCACHE_OP_CLEAN_INV,
	 *     DCACHE_OP_CLEAN), as defined in cache_helpers.h
	 * r1: The cache level to begin operation from
	 * r2: clidr_el1
	 * r3: The last cache level to operate on
	 * and will carry out the operation on each data cache from level 0
	 * to the level in r3 in sequence
	 *
	 * The dcsw_op macro sets up the r2 and r3 parameters based on
	 * clidr_el1 cache information before invoking the main function
	 * ----------------------------------------------------------------
	 */

	.macro	dcsw_op shift, fw, ls
	read_clidr r2
	ubfx	r3, r2, \shift, \fw
	lsl	r3, r3, \ls
	mov	r1, #0
	b	do_dcsw_op
	.endm

LOCAL_FUNC do_dcsw_op , :
	push	{r4-r12,lr}
	adr	r11, dcsw_loop_table	// compute cache op based on the operation type
	add	r6, r11, r0, lsl #3	// cache op is 2x32-bit instructions
loop1:
	add	r10, r1, r1, LSR #1	// Work out 3x current cache level
	mov	r12, r2, LSR r10	// extract cache type bits from clidr
	and	r12, r12, #7   		// mask the bits for current cache only
	cmp	r12, #2			// see what cache we have at this level
	blo	level_done      	// no cache or only instruction cache at this level

	write_csselr r1			// select current cache level in csselr
	isb				// isb to sych the new cssr&csidr
	read_ccsidr r12			// read the new ccsidr
	and	r10, r12, #7   		// extract the length of the cache lines
	add	r10, r10, #4        	// add 4 (r10 = line length offset)
	ubfx	r4, r12, #3, #10	// r4 = maximum way number (right aligned)
	clz	r5, r4            	// r5 = the bit position of the way size increment
	mov	r9, r4			// r9 working copy of the aligned max way number

loop2:
	ubfx	r7, r12, #13, #15	// r7 = max set number (right aligned)

loop3:
	orr	r0, r1, r9, LSL r5	// factor in the way number and cache level into r0
	orr	r0, r0, r7, LSL r10	// factor in the set number

	blx	r6
	subs	r7, r7, #1              // decrement the set number
	bhs	loop3
	subs	r9, r9, #1              // decrement the way number
	bhs	loop2
level_done:
	add	r1, r1, #2		// increment the cache number
	cmp	r3, r1
	dsb	sy			// ensure completion of previous cache maintenance instruction
	bhi	loop1

	mov	r6, #0
	write_csselr r6			//select cache level 0 in csselr
	dsb	sy
	isb
	pop	{r4-r12,pc}

dcsw_loop_table:
	write_dcisw r0
	bx	lr
	write_dccisw r0
	bx	lr
	write_dccsw r0
	bx	lr
END_FUNC do_dcsw_op

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way till PoU.
	 *
	 * The function requires :
	 * r0: The operation type (DCACHE_OP_INV, DCACHE_OP_CLEAN_INV,
	 * DCACHE_OP_CLEAN), as defined in cache_helpers.h
	 * ---------------------------------------------------------------
	 */
FUNC dcache_op_louis , :
	dcsw_op #CLIDR_LOUIS_SHIFT, #CLIDR_FIELD_WIDTH, #CSSELR_LEVEL_SHIFT
END_FUNC dcache_op_louis

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way till PoC.
	 *
	 * The function requires :
	 * r0: The operation type (DCACHE_OP_INV, DCACHE_OP_CLEAN_INV,
	 * DCACHE_OP_CLEAN), as defined in cache_helpers.h
	 * ---------------------------------------------------------------
	 */
FUNC dcache_op_all , :
	dcsw_op #CLIDR_LOC_SHIFT, #CLIDR_FIELD_WIDTH, #CSSELR_LEVEL_SHIFT
END_FUNC dcache_op_all


	/* ---------------------------------------------------------------
	 *  Helper macro for data cache operations by set/way for the
	 *  level specified
	 * ---------------------------------------------------------------
	 */
	.macro	dcsw_op_level level
	read_clidr r2
	mov	r3, \level
	sub	r1, r3, #2
	b	do_dcsw_op
	.endm

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way for level 1 cache
	 *
	 * The main function, do_dcsw_op requires:
	 * r0: The operation type (DCACHE_OP_INV, DCACHE_OP_CLEAN_INV,
	 * DCACHE_OP_CLEAN), as defined in cache_helpers.h
	 * ---------------------------------------------------------------
	 */
FUNC dcache_op_level1 , :
	dcsw_op_level #(1 << CSSELR_LEVEL_SHIFT)
END_FUNC dcache_op_level1

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way for level 2 cache
	 *
	 * The main function, do_dcsw_op requires:
	 * r0: The operation type (DCACHE_OP_INV, DCACHE_OP_CLEAN_INV,
	 * DCACHE_OP_CLEAN), as defined in cache_helpers.h
	 * ---------------------------------------------------------------
	 */
FUNC dcache_op_level2 , :
	dcsw_op_level #(2 << CSSELR_LEVEL_SHIFT)
END_FUNC dcache_op_level2

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way for level 3 cache
	 *
	 * The main function, do_dcsw_op requires:
	 * r0: The operation type (DCACHE_OP_INV, DCACHE_OP_CLEAN_INV,
	 * DCACHE_OP_CLEAN), as defined in cache_helpers.h
	 * ---------------------------------------------------------------
	 */
FUNC dcache_op_level3 , :
	dcsw_op_level #(3 << CSSELR_LEVEL_SHIFT)
END_FUNC dcache_op_level3

FUNC icache_inv_all , :
	/* Invalidate Entire Instruction Cache (and branch predictors) */
	write_icialluis

	dsb	ishst	/* ensure that maintenance operations are seen */
	isb		/* by the instructions rigth after the isb */

	bx      lr
END_FUNC icache_inv_all

	/* ------------------------------------------
	 * Invalidate from base address till
	 * size. 'r0' = addr, 'r1' = size
	 * ------------------------------------------
	 */
FUNC icache_inv_range , :
	icache_line_size r2, r3
	add	r1, r0, r1
	sub	r3, r2, #1
	bic	r0, r0, r3
loop_ic_inv:
	write_icimvau r0
	add	r0, r0, r2
	cmp	r0, r1
	blo	loop_ic_inv

	/* Invalidate entire branch predictor array inner shareable */
	write_bpiallis

	dsb	ishst
	isb

	bx	lr
END_FUNC icache_inv_range
