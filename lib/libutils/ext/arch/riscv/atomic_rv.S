/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#include <asm.S>

/* uint32_t atomic_inc32(uint32_t *v); */
FUNC atomic_inc32 , :
	li	a1, 1
	amoadd.w.aqrl a2, a1, (a0)
	add	a0, a1, a2
	ret
END_FUNC atomic_inc32

/* uint32_t atomic_dec32(uint32_t *v); */
FUNC atomic_dec32 , :
	li	a1, -1
	amoadd.w.aqrl a2, a1, (a0)
	add	a0, a1, a2
	ret
END_FUNC atomic_dec32
