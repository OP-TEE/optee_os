// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026-2026, RISCStar Solutions Limited
 */

/*
 *  RISCV extension
 *  ZKVNED - AES ECB and CBC mode
 */

#include <asm.S>

.option arch, +v, +zvkned

#include "riscv_aes_macros.S"

#define KEYP		a0
#define INP		a1
#define OUTP		a2
#define LEN		a3
#define IVP		a4
#define ROUNDS		a5

.macro __aes_ecb_crypt enc, rounds
	srli t0, LEN, 2
1:
	vsetvli t1, t0, e32, m8, ta, ma
	sub t0, t0, t1
	slli t1, t1, 2
	vle32.v v16, (INP)
.if \enc
	aes_encrypt v16, \rounds
.else
	aes_decrypt v16, \rounds
.endif
	vse32.v v16, (OUTP)
	add INP, INP, t1
	add OUTP, OUTP, t1
	bnez t0, 1b
	ret
.endm

.macro aes_ecb_crypt enc
	aes_begin KEYP, IVP, 128f, 192f
	__aes_ecb_crypt \enc, 14
128:
	__aes_ecb_crypt \enc, 10
192:
	__aes_ecb_crypt \enc, 12
.endm

/*
 * void riscv_aes_ecb_encrypt(const uint8_t *key, const uint8_t *src,
 *                            uint8_t *dst, size_t len, unsigned int rounds)
 */
FUNC riscv_aes_ecb_encrypt , :
	aes_ecb_crypt 1
END_FUNC riscv_aes_ecb_encrypt

FUNC riscv_aes_ecb_decrypt , :
	aes_ecb_crypt 0
END_FUNC riscv_aes_ecb_decrypt

.macro __aes_cbc_encrypt rounds
	vle32.v v16, (IVP)
1:
	vle32.v v17, (INP)
	vxor.vv v16, v16, v17
	aes_encrypt v16, \rounds
	vse32.v v16, (OUTP)
	addi INP, INP, 16
	addi OUTP, OUTP, 16
	addi LEN, LEN, -16
	bnez LEN, 1b
	vse32.v v16, (IVP)
	ret
.endm

.macro aes_cbc_encrypt
	aes_begin KEYP, ROUNDS, 128f, 192f
	__aes_cbc_encrypt 14
128:
	__aes_cbc_encrypt 10
192:
	__aes_cbc_encrypt 12
.endm

.macro __aes_cbc_decrypt rounds
	srli LEN, LEN, 2
	vle32.v v16, (IVP)
1:
	vsetvli t0, LEN, e32, m4, ta, ma
	vle32.v v20, (INP)
	vslideup.vi v16, v20, 4
	addi t1, t0, -4
	vslidedown.vx v24, v20, t1
	aes_decrypt v20, \rounds
	vxor.vv v20, v20, v16
	vse32.v v20, (OUTP)
	vmv.v.v v16, v24
	slli t1, t0, 2
	add INP, INP, t1
	add OUTP, OUTP, t1
	sub LEN, LEN, t0
	bnez LEN, 1b
	vsetivli zero, 4, e32, m1, ta, ma
	vse32.v v16, (IVP)
	ret
.endm

.macro aes_cbc_decrypt
	aes_begin KEYP, ROUNDS, 128f, 192f
	__aes_cbc_decrypt 14
128:
	__aes_cbc_decrypt 10
192:
	__aes_cbc_decrypt 12
.endm

/*
 * void riscv_aes_cbc_encrypt(const uint8_t *key, const uint8_t *src,
 *                            uint8_t *dst, size_t len, uint8_t iv[16],
 *                            unsigned int rounds)
 */
FUNC riscv_aes_cbc_encrypt , :
	aes_cbc_encrypt
END_FUNC riscv_aes_cbc_encrypt

FUNC riscv_aes_cbc_decrypt , :
	aes_cbc_decrypt
END_FUNC riscv_aes_cbc_decrypt

