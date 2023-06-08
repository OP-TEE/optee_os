/*
 * Copyright (c) 2017, Linaro Limited. All rights reserved.
 * Copyright (c) 2013-2014, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arm.h>
#include <asm.S>

.macro  dcache_line_size  reg, tmp
	mrs     \tmp, ctr_el0
	ubfx    \tmp, \tmp, #CTR_DMINLINE_SHIFT, #CTR_DMINLINE_WIDTH
	mov     \reg, #CTR_WORD_SIZE
	lsl     \reg, \reg, \tmp
.endm

.macro  icache_line_size  reg, tmp
	mrs     \tmp, ctr_el0
	and     \tmp, \tmp, #CTR_IMINLINE_MASK
	mov     \reg, #CTR_WORD_SIZE
	lsl     \reg, \reg, \tmp
.endm

/*
 * This macro can be used for implementing various data cache operations `op`
 */
.macro do_dcache_maintenance_by_va op
	dcache_line_size x2, x3
	add	x1, x0, x1
	sub	x3, x2, #1
	bic	x0, x0, x3
loop_\op:
	dc	\op, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo    loop_\op
	dsb	sy
	ret
.endm
	/* ------------------------------------------
	 * Clean+Invalidate from base address till
	 * size. 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
FUNC dcache_cleaninv_range , :
	do_dcache_maintenance_by_va civac
END_FUNC dcache_cleaninv_range

	/* ------------------------------------------
	 * Clean from base address till size.
	 * 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
FUNC dcache_clean_range , :
	do_dcache_maintenance_by_va cvac
END_FUNC dcache_clean_range

	/* ------------------------------------------
	 * Invalidate from base address till
	 * size. 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
FUNC dcache_inv_range , :
	do_dcache_maintenance_by_va ivac
END_FUNC dcache_inv_range

	/* ------------------------------------------
	 * Clean from base address till size to point of unification
	 * 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
FUNC dcache_clean_range_pou , :
	do_dcache_maintenance_by_va cvau
END_FUNC dcache_clean_range_pou

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way to the level specified
	 *
	 * The main function, do_dcsw_op requires:
	 * x0: The operation type (0-2), as defined in cache_helpers.h
	 * x3: The last cache level to operate on
	 * x9: clidr_el1
	 * x10: The cache level to begin operation from
	 * and will carry out the operation on each data cache from level 0
	 * to the level in x3 in sequence
	 *
	 * The dcsw_op macro sets up the x3 and x9 parameters based on
	 * clidr_el1 cache information before invoking the main function
	 * ---------------------------------------------------------------
	 */

	.macro	dcsw_op shift, fw, ls
	mrs	x9, clidr_el1
	ubfx	x3, x9, \shift, \fw
	lsl	x3, x3, \ls
	mov	x10, xzr
	b	do_dcsw_op
	.endm

LOCAL_FUNC do_dcsw_op , :
	cbz	x3, exit
	adr	x14, dcsw_loop_table	// compute inner loop address
	add	x14, x14, x0, lsl #5	// inner loop is 8x32-bit instructions
BTI(	add	x14, x14, x0, lsl #2)	// inner loop is + "bti j" instruction
	mov	x0, x9
	mov	w8, #1
loop1:
	add	x2, x10, x10, lsr #1	// work out 3x current cache level
	lsr	x1, x0, x2		// extract cache type bits from clidr
	and	x1, x1, #7		// mask the bits for current cache only
	cmp	x1, #2			// see what cache we have at this level
	b.lo	level_done		// nothing to do if no cache or icache

	msr	csselr_el1, x10		// select current cache level in csselr
	isb				// isb to sych the new cssr&csidr
	mrs	x1, ccsidr_el1		// read the new ccsidr
	and	x2, x1, #7		// extract the length of the cache lines
	add	x2, x2, #4		// add 4 (line length offset)
	ubfx	x4, x1, #3, #10		// maximum way number
	clz	w5, w4			// bit position of way size increment
	lsl	w9, w4, w5		// w9 = aligned max way number
	lsl	w16, w8, w5		// w16 = way number loop decrement
	orr	w9, w10, w9		// w9 = combine way and cache number
	ubfx	w6, w1, #13, #15	// w6 = max set number
	lsl	w17, w8, w2		// w17 = set number loop decrement
	dsb	sy			// barrier before we start this level
	br	x14			// jump to DC operation specific loop

	.macro	dcsw_loop _op
BTI(	bti	j)
loop2_\_op:
	lsl	w7, w6, w2		// w7 = aligned max set number

loop3_\_op:
	orr	w11, w9, w7		// combine cache, way and set number
	dc	\_op, x11
	subs	w7, w7, w17		// decrement set number
	b.hs	loop3_\_op

	subs	x9, x9, x16		// decrement way number
	b.hs	loop2_\_op

	b	level_done
	.endm

level_done:
	add	x10, x10, #2		// increment cache number
	cmp	x3, x10
	b.hi    loop1
	msr	csselr_el1, xzr		// select cache level 0 in csselr
	dsb	sy			// barrier to complete final cache operation
	isb
exit:
	ret

dcsw_loop_table:
	dcsw_loop isw
	dcsw_loop cisw
	dcsw_loop csw
END_FUNC do_dcsw_op

FUNC dcache_op_louis , :
	dcsw_op #CLIDR_LOUIS_SHIFT, #CLIDR_FIELD_WIDTH, #CSSELR_LEVEL_SHIFT
END_FUNC dcache_op_louis

FUNC dcache_op_all , :
	dcsw_op #CLIDR_LOC_SHIFT, #CLIDR_FIELD_WIDTH, #CSSELR_LEVEL_SHIFT
END_FUNC dcache_op_all

	/* ---------------------------------------------------------------
	 *  Helper macro for data cache operations by set/way for the
	 *  level specified
	 * ---------------------------------------------------------------
	 */
	.macro dcsw_op_level level
	mrs	x9, clidr_el1
	mov	x3, \level
	sub	x10, x3, #2
	b	do_dcsw_op
	.endm

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way for level 1 cache
	 *
	 * The main function, do_dcsw_op requires:
	 * x0: The operation type (0-2), as defined in cache_helpers.h
	 * ---------------------------------------------------------------
	 */
FUNC dcache_op_level1 , :
	dcsw_op_level #(1 << CSSELR_LEVEL_SHIFT)
END_FUNC dcache_op_level1

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way for level 2 cache
	 *
	 * The main function, do_dcsw_op requires:
	 * x0: The operation type (0-2), as defined in cache_helpers.h
	 * ---------------------------------------------------------------
	 */
FUNC dcache_op_level2 , :
	dcsw_op_level #(2 << CSSELR_LEVEL_SHIFT)
END_FUNC dcache_op_level2

	/* ---------------------------------------------------------------
	 * Data cache operations by set/way for level 3 cache
	 *
	 * The main function, do_dcsw_op requires:
	 * x0: The operation type (0-2), as defined in cache_helpers.h
	 * ---------------------------------------------------------------
	 */
FUNC dcache_op_level3 , :
	dcsw_op_level #(3 << CSSELR_LEVEL_SHIFT)
END_FUNC dcache_op_level3

FUNC icache_inv_all , :
	/* Invalidate Entire Instruction Cache */
	ic	ialluis

	dsb	ish	/* ensure that maintenance operations are seen */
	isb		/* by the instructions rigth after the isb */

	ret
END_FUNC icache_inv_all

FUNC icache_inv_range , :
	icache_line_size x2, x3
	add	x1, x0, x1
	sub	x3, x2, #1
	bic	x0, x0, x3
loop_ic_inv:
	ic	ivau, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo    loop_ic_inv
	dsb	ish
	ret

END_FUNC icache_inv_range

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
