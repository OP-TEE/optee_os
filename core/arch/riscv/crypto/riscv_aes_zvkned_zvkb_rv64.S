/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 *
 * AES CTR using the RISC-V Zvkned and Zvkb vector crypto extensions.
 *
 * Zvkb is here for vrev8.v. The counter is a 128-bit big-endian integer but
 * vector arithmetic is little-endian per element, so counting several blocks
 * ahead in vector registers means byte-swapping the counter, adding, and
 * swapping back. Without vrev8.v that costs more than the parallelism wins,
 * which is why this is a separate file from the Zvkned-only ECB and CBC.
 */

#include <asm.S>

	.option arch, +v, +zvkned, +zvkb

#include "riscv_aes_macros.S"

#define KEYP		a0
#define INP		a1
#define OUTP		a2
#define LEN		a3
#define CTRP		a4
#define ROUNDS		a5

/*
 * Encrypt t2 counter blocks, which the caller has already clamped so that
 * the low 32 bits of the counter cannot overflow. Only word 3 of each block
 * is byte-swapped and incremented, which is what makes the arithmetic a
 * single masked vadd; the caller owns everything above it.
 *
 * Clobbers t0, t1, t5, t6 and v16-v27, v31. v0 holds the element mask.
 */
	.macro aes_ctr_batch rounds
	slli		t5, t2, 2		# batch length in elements

	vsetivli	zero, 4, e32, m1, ta, ma
	vle32.v		v31, (CTRP)
	vsetivli	zero, 4, e32, m1, ta, mu
	vrev8.v		v31, v31, v0.t		# word 3 to little-endian
4:
	vsetvli		t0, t5, e32, m4, ta, ma
	/*
	 * vaesz.vs XORs its scalar element group into every element group of
	 * the destination, so against a zeroed destination it replicates the
	 * counter block across the whole group.
	 */
	vmv.v.i		v16, 0
	vaesz.vs	v16, v31
	viota.m		v20, v0, v0.t		# 0, 1, 2, ... per block
	vsetvli		t0, t5, e32, m4, ta, mu
	vadd.vv		v16, v16, v20, v0.t
	vmv.v.v		v24, v16
	vrev8.v		v24, v24, v0.t		# back to big-endian for AES

	vsetvli		t0, t5, e32, m4, ta, ma
	aes_encrypt	v24, \rounds

	slli		t6, t0, 2		# elements consumed to bytes
	vsetvli		zero, t6, e8, m4, ta, ma
	vle8.v		v20, (INP)
	vxor.vv		v20, v20, v24
	vse8.v		v20, (OUTP)

	add		INP, INP, t6
	add		OUTP, OUTP, t6
	sub		t5, t5, t0
	srli		t1, t0, 2		# blocks consumed
	vsetivli	zero, 4, e32, m1, ta, mu
	vadd.vx		v31, v31, t1, v0.t
	bnez		t5, 4b

	vrev8.v		v31, v31, v0.t		# word 3 back to big-endian
	vsetivli	zero, 4, e32, m1, ta, ma
	vse32.v		v31, (CTRP)
	.endm

	.macro __aes_ctr_crypt rounds
	/*
	 * 0x88 per byte makes an element mask that selects element 3 of every
	 * four, which is word 3 of every 16-byte counter block.
	 */
	li		t0, 0x88
	vsetvli		t1, zero, e8, m1, ta, ma
	vmv.v.x		v0, t0
1:
	srli		t2, LEN, 4		# blocks left
	beqz		t2, 9f

	/*
	 * Read the low 32 bits of the counter and work out how many blocks
	 * are left before they wrap. Everything above those 32 bits is
	 * carried in scalar code below, so a batch must stop at the wrap.
	 */
	lbu		t3, 12(CTRP)
	lbu		t4, 13(CTRP)
	slli		t3, t3, 8
	or		t3, t3, t4
	lbu		t4, 14(CTRP)
	slli		t3, t3, 8
	or		t3, t3, t4
	lbu		t4, 15(CTRP)
	slli		t3, t3, 8
	or		t3, t3, t4		# t3 = low 32 bits
	li		t4, 1
	slli		t4, t4, 32
	sub		t4, t4, t3		# blocks until the wrap

	bltu		t2, t4, 2f
	mv		t2, t4			# clamp the batch to the wrap
2:
	slli		a6, t2, 4		# batch length in bytes
	sub		LEN, LEN, a6
	aes_ctr_batch	\rounds

	/*
	 * If the batch ended exactly on the wrap the low word is now zero
	 * and the carry has to be propagated into the upper 96 bits, which
	 * the masked vadd above never touches.
	 */
	bne		t2, t4, 1b
	addi		t3, CTRP, 11
3:
	lbu		t4, 0(t3)
	addi		t4, t4, 1
	andi		t4, t4, 0xff
	sb		t4, 0(t3)
	bnez		t4, 1b
	addi		t3, t3, -1
	bgeu		t3, CTRP, 3b
	j		1b
9:
	ret
	.endm

	.macro aes_ctr_crypt
	aes_load_schedule KEYP, ROUNDS, 60f, 70f
	__aes_ctr_crypt 14
60:
	__aes_ctr_crypt 10
70:
	__aes_ctr_crypt 12
	.endm

/*
 * void riscv_aes_ctr_be_encrypt(const void *key, const void *src, void *dst,
 *				 size_t len, void *ctr, unsigned int rounds)
 */
FUNC riscv_aes_ctr_be_encrypt , :
	aes_ctr_crypt
END_FUNC riscv_aes_ctr_be_encrypt
