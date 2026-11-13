/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <asm.S>

.text

/* Repeated words make ShiftRows a no-op; a zero key leaves SubBytes. */
FUNC riscv_aes_subword , :
	vsetivli	zero, 4, e32, m1, ta, ma
	vmv.v.x		v1, a0
	vmv.v.i		v2, 0
	vaesef.vs	v1, v2
	vmv.x.s		a0, v1
	ret
END_FUNC riscv_aes_subword
