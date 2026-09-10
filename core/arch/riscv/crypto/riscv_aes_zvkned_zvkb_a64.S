// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026-2026, RISCStar Solutions Limited
 */

/*
 *  RISCV extension
 *  ZKVNED - AES ECB and CBC mode
 *  ZVKB   - AES CTR mode
 */
#include <asm.S>

.option arch, +v, +zvkned, +zvkb

#include "riscv_aes_macros.S"

#define KEYP		a0
#define INP		a1
#define OUTP		a2
#define LEN		a3
#define IVP		a4
#define ROUNDS		a5

#define LEN32		t3
#define VL_E32		t4
#define VL_BLOCKS	t5

.macro __aes_ctr_crypt rounds
	/* Convert the byte length to the number of 32-bit elements. */
	addi t0, LEN, 15
	srli t0, t0, 4
	slli LEN32, t0, 2

	/* Select word 3 of every four-word AES counter block. */
	li t0, 0x88
	vsetvli t1, zero, e8, m1, ta, ma
	vmv.v.x v0, t0

	/* Load the big-endian counter and byte-swap only its low word. */
	vsetivli zero, 4, e32, m1, ta, ma
	vle32.v v31, (CTRP)
	vsetivli zero, 4, e32, m1, ta, mu
	vrev8.v v31, v31, v0.t

	/* Replicate the initial counter and form consecutive counter values. */
	vsetvli zero, LEN32, e32, m4, ta, ma
	vmv.v.i v16, 0
	vaesz.vs v16, v31
	viota.m v20, v0, v0.t
	vsetvli VL_E32, LEN32, e32, m4, ta, mu
	vadd.vv v16, v16, v20, v0.t
	j 2f
1:
	vsetvli VL_E32, LEN32, e32, m4, ta, mu
	vadd.vx v16, v16, VL_BLOCKS, v0.t
2:
	vmv.v.v v24, v16
	vrev8.v v24, v24, v0.t
	aes_encrypt v24, \rounds

	vsetvli t0, LEN, e8, m4, ta, ma
	vle8.v v20, (INP)
	vxor.vv v20, v20, v24
	vse8.v v20, (OUTP)

	add INP, INP, t0
	add OUTP, OUTP, t0
	sub LEN, LEN, t0
	sub LEN32, LEN32, VL_E32
	srli VL_BLOCKS, VL_E32, 2
	bnez LEN, 1b

	/* Return the next counter value to the caller. */
	vsetivli zero, 4, e32, m1, ta, mu
	vadd.vx v16, v16, VL_BLOCKS, v0.t
	vrev8.v v16, v16, v0.t
	vse32.v v16, (CTRP)
	ret
.endm

.macro aes_ctr_crypt
	aes_begin KEYP, ROUNDS, 128f, 192f
	__aes_ctr_crypt 14
128:
	__aes_ctr_crypt 10
192:
	__aes_ctr_crypt 12
.endm

/*
 * void riscv_aes_ctr_encrypt(const uint8_t *key, const uint8_t *src,
 *                            uint8_t *dst, size_t len, uint8_t ctr[16],
 *                            unsigned int rounds)
 */
FUNC riscv_aes_ctr_encrypt , :
	aes_ctr_crypt
END_FUNC riscv_aes_ctr_encrypt
