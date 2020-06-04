/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <asm.S>

/*
 * void ftmn_expect_val(struct ftmn_check *check, enum ftmn_incr incr,
 *			unsigned long ret, unsigned long val);
 */
FUNC ftmn_expect_val , :
	/*
	 * Clear PSTATE.Z and swap x0 and x1 to make sure that the
	 * instruction just before the test must be executed.
	 *
	 * Make reduntant comparisons interleaved with the xoring to make
	 * it harder to glitch a cmp instruction without affecting an
	 * eor(s).
	 *
	 * Note that the ldr depends on x0 and x1 being swapped so it's a
	 * way of seeing that the instructions just before the cmp wasn't
	 * glitched either.
	 */
	subs	x4, x4, x4
	eor	x0, x0, x1
	cmp	x2, x3
	b.ne	ftmn_do_panic
	eor	x1, x1, x0
	b.ne	ftmn_do_panic
	subs	x4, x4, x4
	eor	x0, x0, x1
	cmp	x2, x3
	b.ne	ftmn_do_panic
	ldr	x2, [x1]
	b.ne	ftmn_do_panic
	add	x2, x2, x0
	b.ne	ftmn_do_panic
	str	x2, [x1]
	br	lr
	b	ftmn_do_panic
END_FUNC ftmn_expect_val

/*
 * void ftmn_expect_not_val(struct ftmn_check *check, enum ftmn_incr incr,
 *			    unsigned long ret, unsigned long val);
 */
FUNC ftmn_expect_not_val , :
	/*
	 * Set PSTATE.Z and swap r0 and r1 to make sure that the
	 * instruction just before the test must be executed.
	 *
	 * Make reduntant comparisons interleaved with the xoring to make
	 * it harder to glitch a cmp instruction without affecting an
	 * eor(s).
	 *
	 * Note that the ldreq depends on r0 and r1 being swapped so it's a
	 * way of seeing that the instructions just before the cmp wasn't
	 * glitched either.
	 */
	subs	x4, x4, x4
	eor	x0, x0, x1
	cmp	x2, x3
	b.eq	ftmn_do_panic
	eor	x1, x1, x0
	b.eq	ftmn_do_panic
	subs	x4, x4, x4
	eor	x0, x0, x1
	cmp	x2, x3
	b.eq	ftmn_do_panic
	ldr	x2, [x1]
	b.eq	ftmn_do_panic
	add	x2, x2, x0
	b.eq	ftmn_do_panic
	str	x2, [x1]
	br	lr
	b	ftmn_do_panic
END_FUNC ftmn_expect_not_val

#ifdef __KERNEL__
LOCAL_FUNC ftmn_do_panic , :
#ifdef CFG_TEE_CORE_DEBUG
	adr	x0, 1f
	mov	x1, #__LINE__
#else
	mov	x0, #0
	mov	x1, #0
#endif
	mov	x2, #0
	mov	x3, #0
	bl	__do_panic
#ifdef CFG_TEE_CORE_DEBUG
1:	.asciz __FILE__
	.balign 4
#endif
END_FUNC ftmn_do_panic

#else /* !__KERNEL__*/
LOCAL_FUNC ftmn_do_panic , :
	mov	x0, #0
	bl	TEE_Panic
END_FUNC ftmn_do_panic
#endif
