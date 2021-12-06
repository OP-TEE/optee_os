/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */

#include <asm.S>


/* uint32_t atomic_inc32(uint32_t *v); */
FUNC atomic_inc32 , :
	ldaxr	w1, [x0]
	add	w1, w1, #1
	stxr	w2, w1, [x0]
	cmp	w2, #0
	bne	atomic_inc32
	mov	w0, w1
	ret
END_FUNC atomic_inc32

/* uint32_t atomic_dec32(uint32_t *v); */
FUNC atomic_dec32 , :
	ldaxr	w1, [x0]
	sub	w1, w1, #1
	stxr	w2, w1, [x0]
	cmp	w2, #0
	bne	atomic_dec32
	mov	w0, w1
	ret
END_FUNC atomic_dec32

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
