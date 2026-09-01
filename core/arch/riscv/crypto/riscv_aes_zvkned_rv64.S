/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 *
 * AES ECB and CBC using the RISC-V Zvkned vector crypto extension.
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

/*
 * void riscv_aes_cbc_encrypt(const void *key, const void *src, void *dst,
 *			      size_t len, void *iv, unsigned int rounds)
 * void riscv_aes_cbc_decrypt(const void *key, const void *src, void *dst,
 *			      size_t len, void *iv, unsigned int rounds)
 *
 * a0 key, a1 src, a2 dst, a3 len, a4 iv, a5 rounds. The iv is updated in
 * place so that a caller can continue a chain across calls.
 *
 * CBC encryption is serial: block n feeds block n+1, so this runs one
 * block at a time whatever vl the hart offers. Decryption has no such
 * dependency and could be done several blocks at once, but is kept to one
 * block here so that both directions share the loop and the chaining
 * value is handled the same way.
 */
#define IVP	a4
#define CBC_ROUNDS a5

	.macro aes_cbc_body enc, rounds
	vsetivli	zero, 4, e32, m1, ta, ma
	vle32.v		v16, (IVP)		# chaining value
	srli		t2, LEN, 4		# block count
1:
	vle32.v		v17, (INP)
	.if \enc
	vxor.vv		v16, v16, v17
	aes_encrypt	v16, \rounds
	vse32.v		v16, (OUTP)
	.else
	vmv.v.v		v18, v17		# keep the ciphertext block
	aes_decrypt	v17, \rounds
	vxor.vv		v17, v17, v16
	vse32.v		v17, (OUTP)
	vmv.v.v		v16, v18
	.endif
	addi		INP, INP, 16
	addi		OUTP, OUTP, 16
	addi		t2, t2, -1
	bnez		t2, 1b
	vse32.v		v16, (IVP)		# hand the chain back
	ret
	.endm

	.macro aes_cbc_crypt enc
	aes_load_schedule KEYP, CBC_ROUNDS, 40f, 50f
	aes_cbc_body \enc, 14
40:
	aes_cbc_body \enc, 10
50:
	aes_cbc_body \enc, 12
	.endm

FUNC riscv_aes_cbc_encrypt , :
	aes_cbc_crypt 1
END_FUNC riscv_aes_cbc_encrypt

FUNC riscv_aes_cbc_decrypt , :
	aes_cbc_crypt 0
END_FUNC riscv_aes_cbc_decrypt
