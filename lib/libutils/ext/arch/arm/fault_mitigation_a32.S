/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <asm.S>

/*
 * void ftmn_expect_val(struct ftmn_check *check, enum ftmn_incr incr,
 *			unsigned long ret, unsigned long val)
 * {
 * 	if (ret != val)
 * 		ftmn_panic();
 * 	check->steps += incr;
 * }
 */
FUNC ftmn_expect_val , :
	/*
	 * Clear PSTATE.Z and swap r0 and r1 to make sure that the
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
	eors	r0, r0, r1
	cmp	r2, r3
	eor	r1, r1, r0
	bne	ftmn_do_panic
	eors	r0, r0, r1
	cmp	r2, r3
	ldreq	r2, [r1]
	bne	ftmn_do_panic
	addeq	r2, r2, r0
	streq	r2, [r1]
	blx	lr
END_FUNC ftmn_expect_val

/*
 * void ftmn_expect_not_val(struct ftmn_check *check, enum ftmn_incr incr,
 *			    unsigned long ret, unsigned long val);
 * {
 * 	if (ret == val)
 * 		ftmn_panic();
 * 	check->steps += incr;
 * }
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
	eors	r12, r12, r12
	cmp	r2, r3
	eor	r0, r0, r1
	beq	ftmn_do_panic
	eors	r12, r12, r12
	eor	r1, r1, r0
	eor	r0, r0, r1
	cmp	r2, r3
	ldrne	r2, [r1]
	beq	ftmn_do_panic
	addne	r2, r2, r0
	strne	r2, [r1]
	blx	lr
END_FUNC ftmn_expect_not_val

/*
 * unsigned long __ftmn_return_val(unsigned long hashed_val, unsigned long hash,
 *				   unsigned long val)
 * {
 * 	if ((hashed_val ^ hash) != val)
 * 		ftmn_panic();
 * 	return val;
 * }
 */
FUNC __ftmn_return_val , :
	/*
	 * r0 holds a bit pattern which is very unlikely the desired return
	 * value. When extracting the return value be careful to only update
	 * r0 once we're just about to return.
	 */
	cmp	r1, #0
	eor	r3, r0, r1
	cmp	r3, r2
	bne	ftmn_do_panic
	cmp	r1, #0
	mov	r12, r3
	cmp	r12, r2
	bne	ftmn_do_panic
	mov	r0, r12
	blx	lr
END_FUNC __ftmn_return_val

#ifdef __KERNEL__
LOCAL_FUNC ftmn_do_panic , :
#ifdef CFG_TEE_CORE_DEBUG
	/* Be nice to the stack unwinding */
	push	{r12, lr}
UNWIND(	.save	{r12, lr})
	adr	r0, 1f
	mov	r1, #__LINE__
#else
UNWIND(	.cantunwind)
	mov	r0, #0
	mov	r1, #0
#endif
	mov	r2, #0
	mov	r3, #0
	bl	__do_panic
#ifdef CFG_TEE_CORE_DEBUG
1:	.asciz __FILE__
	.balign 4
#endif
END_FUNC ftmn_do_panic

#else /* !__KERNEL__*/
LOCAL_FUNC ftmn_do_panic , :
	mov	r0, #0
	bl	TEE_Panic
END_FUNC ftmn_do_panic
#endif
