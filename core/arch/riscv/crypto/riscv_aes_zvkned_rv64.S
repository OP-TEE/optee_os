/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 *
 * AES ECB using the RISC-V Zvkned vector crypto extension.
 */

#include <asm.S>

	.option arch, +v, +zvkned

#include "riscv_aes_macros.S"

/*
 * void riscv_aes_ecb_encrypt(const void *key, const void *src, void *dst,
 *			      size_t len, unsigned int rounds)
 * void riscv_aes_ecb_decrypt(const void *key, const void *src, void *dst,
 *			      size_t len, unsigned int rounds)
 *
 * a0 key, a1 src, a2 dst, a3 len in bytes, a4 rounds. len is a whole
 * number of 16-byte blocks and is not zero, both checked by the caller.
 */
#define KEYP	a0
#define INP	a1
#define OUTP	a2
#define LEN	a3
#define ROUNDS	a4

	.macro aes_ecb_body enc, rounds
	srli	t2, LEN, 2		# length in 32-bit elements
1:
	vsetvli	t3, t2, e32, m4, ta, ma
	sub	t2, t2, t3
	vle32.v	v16, (INP)
	.if \enc
	aes_encrypt v16, \rounds
	.else
	aes_decrypt v16, \rounds
	.endif
	vse32.v	v16, (OUTP)
	slli	t3, t3, 2		# elements consumed back to bytes
	add	INP, INP, t3
	add	OUTP, OUTP, t3
	bnez	t2, 1b
	ret
	.endm

	.macro aes_ecb_crypt enc
	aes_load_schedule KEYP, ROUNDS, 20f, 30f
	aes_ecb_body \enc, 14
20:
	aes_ecb_body \enc, 10
30:
	aes_ecb_body \enc, 12
	.endm

FUNC riscv_aes_ecb_encrypt , :
	aes_ecb_crypt 1
END_FUNC riscv_aes_ecb_encrypt

FUNC riscv_aes_ecb_decrypt , :
	aes_ecb_crypt 0
END_FUNC riscv_aes_ecb_decrypt
