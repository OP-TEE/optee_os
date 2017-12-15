/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */

#include <asm.S>

/* uint32_t atomic_inc32(uint32_t *v); */
FUNC atomic_inc32 , :
	ldrex	r1, [r0]
	add	r1, r1, #1
	strex	r2, r1, [r0]
	cmp	r2, #0
	bne	atomic_inc32
	mov	r0, r1
	bx	lr
END_FUNC atomic_inc32

/* uint32_t atomic_dec32(uint32_t *v); */
FUNC atomic_dec32 , :
	ldrex	r1, [r0]
	sub	r1, r1, #1
	strex	r2, r1, [r0]
	cmp	r2, #0
	bne	atomic_dec32
	mov	r0, r1
	bx	lr
END_FUNC atomic_dec32
