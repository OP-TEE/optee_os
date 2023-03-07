/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2023. All rights reserved.
 * Copyright (C) 2022, Alibaba Group.
 * Copyright (C) 2022 Tianjia Zhang <tianjia.zhang@linux.alibaba.com>
 *
 * SM4 optimization for ARMv8 by NEON and AES HW instruction, which is an
 * optional Cryptographic Extension for ARMv8-A.
 *
 * The NEON implementation refers to Linux kernel (sm4-neon-core.S contributed
 * by Tianjia Zhang <tianjia.zhang@linux.alibaba.com>).
 *
 * The AES trick refers to sm4ni (https://github.com/mjosaarinen/sm4ni). The
 * constants used in load_sbox_matrix are from this blog (https://www.cnblogs.
 * com/kentle/p/15826075.html). We've done some further optimizations so the
 * constants don't look the same.
 */

#include <asm.S>

.arch	armv8-a+crypto

#define m0	w9
#define m1	w10
#define m2	w11
#define m3	w12
#define tw0l	x7
#define tw0h	x8
#define tw1l	x9
#define tw1h	x10
#define tw2l	x11
#define tw2h	x12
#define tw3l	x13
#define tw3h	x14
#define tw4l	x15
#define tw4h	x16
#define tw5l	x17
#define tw5h	x18
#define tw6l	x19
#define tw6h	x20
#define tw7l	x21
#define tw7h	x22
#define tmpw0	w23
#define tmpx0	x23
#define tmpw1	w24
#define tmpx1	x24
#define tmpw2	w25

/* round keys: v0-v7 */
#define RK0	v0
#define RK1	v1
#define RK2	v2
#define RK3	v3
#define RK4	v4
#define RK5	v5
#define RK6	v6
#define RK7	v7

/* plain blocks: v8-v15 */
#define BLK0	v8
#define BLK1	v9
#define BLK2	v10
#define BLK3	v11
#define BLK4	v12
#define BLK5	v13
#define BLK6	v14
#define BLK7	v15

#define TMP0	v16
#define TMP1	v17
#define TMP2	v18
#define TMP3	v19
#define TMP4	v20
#define TMP5	v21
#define TMP6	v22
#define TMP7	v23
#define	TMP8	v24
#define	IV	v25
#define ANDMASKV	v26
#define ANDMASKQ	q26
#define ATALMaskV	v27
#define ATALMaskQ	q27
#define ATAHMaskV	v28
#define ATAHMaskQ	q28
#define TALMaskV	v29
#define TALMaskQ	q29
#define TAHMaskV	v30
#define TAHMaskQ	q30
#define MASKV	v31
#define MASKQ	q31

.macro frame_push
	stp	x15, x16, [sp, #-0x10]!
	stp	x17, x18, [sp, #-0x10]!
	stp	x19, x20, [sp, #-0x10]!
	stp	x21, x22, [sp, #-0x10]!
	stp	x23, x24, [sp, #-0x10]!
	stp	x25, x26, [sp, #-0x10]!
	stp	x27, x28, [sp, #-0x10]!
	stp	x29, x30, [sp, #-0x10]!
	stp	d8, d9, [sp, #-0x10]!
	stp	d10, d11, [sp, #-0x10]!
	stp	d12, d13, [sp, #-0x10]!
	stp	d14, d15, [sp, #-0x10]!
.endm

.macro frame_pop
	ldp	d14, d15, [sp], #0x10
	ldp	d12, d13, [sp], #0x10
	ldp	d10, d11, [sp], #0x10
	ldp	d8, d9, [sp], #0x10
	ldp	x29, x30, [sp], #0x10
	ldp	x27, x28, [sp], #0x10
	ldp	x25, x26, [sp], #0x10
	ldp	x23, x24, [sp], #0x10
	ldp	x21, x22, [sp], #0x10
	ldp	x19, x20, [sp], #0x10
	ldp	x17, x18, [sp], #0x10
	ldp	x15, x16, [sp], #0x10
.endm

.macro load_sbox_matrix
	ldr MASKQ, .Lsbox_magic
	ldr TAHMaskQ, .Lsbox_magic+16
	ldr TALMaskQ, .Lsbox_magic+32
	ldr ATAHMaskQ, .Lsbox_magic+48
	ldr ATALMaskQ, .Lsbox_magic+64
	ldr ANDMASKQ, .Lsbox_magic+80
.endm

.macro	multi_matrix, x, high, low, tmp
	ushr	\tmp\().16b, \x\().16b, 4
	and	\x\().16b, \x\().16b, ANDMASKV.16b
	tbl	\x\().16b, {\low\().16b}, \x\().16b
	tbl	\tmp\().16b, {\high\().16b}, \tmp\().16b
	eor	\x\().16b, \x\().16b, \tmp\().16b
.endm

.macro	sbox, des, src, tmp1, tmp2
	tbl	\des\().16b, {\src\().16b}, MASKV.16b
	multi_matrix	\des, TAHMaskV, TALMaskV, \tmp2
	eor	\tmp1\().16b, \tmp1\().16b, \tmp1\().16b
	aese	\des\().16b, \tmp1\().16b
	multi_matrix	\des, ATAHMaskV, ATALMaskV, \tmp2
.endm

.macro	sbox_double, des0, src0, des1, src1, tmp1, tmp2
	tbl	\des0\().16b, {\src0\().16b}, MASKV.16b
	tbl	\des1\().16b, {\src1\().16b}, MASKV.16b
	multi_matrix	\des0, TAHMaskV, TALMaskV, \tmp2
	multi_matrix	\des1, TAHMaskV, TALMaskV, \tmp2
	eor	\tmp1\().16b, \tmp1\().16b, \tmp1\().16b
	aese	\des0\().16b, \tmp1\().16b
	multi_matrix	\des0, ATAHMaskV, ATALMaskV, \tmp2
	aese	\des1\().16b, \tmp1\().16b
	multi_matrix	\des1, ATAHMaskV, ATALMaskV, \tmp2
.endm

.macro	round, c0, c1, c2, c3, k
	mov	tmpw0, \k
	eor	tmpw1, \c1, \c2
	eor	tmpw0, \c3, tmpw0
	eor	tmpw2, tmpw1, tmpw0
	mov	TMP0.s[0], tmpw2
	/* nonlinear transformation */
	sbox	TMP1, TMP0, TMP2, TMP3
	/* linear transformation */
	mov	tmpw2, TMP1.s[0]
	ror	tmpw0, tmpw2, #(32-10)
	eor	tmpw0, tmpw0, tmpw2, ror #(32-2)
	ror	tmpw1, tmpw2, #(32-24)
	eor	tmpw1, tmpw1, tmpw2, ror #(32-18)
	eor	tmpw0, tmpw0, tmpw1
	eor	tmpw2, tmpw0, tmpw2
	eor	\c0, \c0, tmpw2
.endm

.macro	round4_enc, k
	round	m0, m1, m2, m3, \k\().s[0]
	round	m1, m2, m3, m0, \k\().s[1]
	round	m2, m3, m0, m1, \k\().s[2]
	round	m3, m0, m1, m2, \k\().s[3]
.endm

.macro	round4_dec, k
	round	m0, m1, m2, m3, \k\().s[3]
	round	m1, m2, m3, m0, \k\().s[2]
	round	m2, m3, m0, m1, \k\().s[1]
	round	m3, m0, m1, m2, \k\().s[0]
.endm

.macro	encrypt_block_no_rev, in
	mov	m0, \in\().s[0]
	mov	m1, \in\().s[1]
	mov	m2, \in\().s[2]
	mov	m3, \in\().s[3]
	round4_enc	RK0
	round4_enc	RK1
	round4_enc	RK2
	round4_enc	RK3
	round4_enc	RK4
	round4_enc	RK5
	round4_enc	RK6
	round4_enc	RK7
	mov	\in\().s[0], m3
	mov	\in\().s[1], m2
	mov	\in\().s[2], m1
	mov	\in\().s[3], m0
.endm

.macro	encrypt_block, in
	rev32	\in\().16b, \in\().16b
	encrypt_block_no_rev	\in
	rev32	\in\().16b, \in\().16b
.endm

.macro	decrypt_block_no_rev, in
	mov	m0, \in\().s[0]
	mov	m1, \in\().s[1]
	mov	m2, \in\().s[2]
	mov	m3, \in\().s[3]
	round4_dec	RK7
	round4_dec	RK6
	round4_dec	RK5
	round4_dec	RK4
	round4_dec	RK3
	round4_dec	RK2
	round4_dec	RK1
	round4_dec	RK0
	mov	\in\().s[0], m3
	mov	\in\().s[1], m2
	mov	\in\().s[2], m1
	mov	\in\().s[3], m0
.endm

.macro	decrypt_block, in
	rev32	\in\().16b, \in\().16b
	decrypt_block_no_rev	\in
	rev32	\in\().16b, \in\().16b
.endm

LOCAL_FUNC sm4_encrypt_block1x , :
	encrypt_block	BLK0
	ret
END_FUNC sm4_encrypt_block1x

LOCAL_FUNC sm4_decrypt_block1x , :
	decrypt_block	BLK0
	ret
END_FUNC sm4_decrypt_block1x

.macro	transpose_4x4, s0, s1, s2, s3
	zip1	TMP0.4s, \s0\().4s, \s1\().4s
	zip1	TMP1.4s, \s2\().4s, \s3\().4s
	zip2	TMP2.4s, \s0\().4s, \s1\().4s
	zip2	TMP3.4s, \s2\().4s, \s3\().4s
	zip1	\s0\().2d, TMP0.2d, TMP1.2d
	zip2	\s1\().2d, TMP0.2d, TMP1.2d
	zip1	\s2\().2d, TMP2.2d, TMP3.2d
	zip2	\s3\().2d, TMP2.2d, TMP3.2d
.endm

.macro	rotate_clockwise_90, s0, s1, s2, s3
	zip1	TMP0.4s, \s1\().4s, \s0\().4s
	zip2	TMP1.4s, \s1\().4s, \s0\().4s
	zip1	TMP2.4s, \s3\().4s, \s2\().4s
	zip2	TMP3.4s, \s3\().4s, \s2\().4s
	zip1	\s0\().2d, TMP2.2d, TMP0.2d
	zip2	\s1\().2d, TMP2.2d, TMP0.2d
	zip1	\s2\().2d, TMP3.2d, TMP1.2d
	zip2	\s3\().2d, TMP3.2d, TMP1.2d
.endm


.macro	round_4x, s0, s1, s2, s3, k
	dup	TMP8.4s, \k
	eor	TMP1.16b, \s2\().16b, \s3\().16b
	eor	TMP8.16b, TMP8.16b, \s1\().16b
	eor	TMP8.16b, TMP8.16b, TMP1.16b

	/* nonlinear transformation */
	sbox	TMP0, TMP8, TMP2, TMP3

	/* linear transformation */
	shl	TMP1.4s, TMP0.4s, #2
	shl	TMP2.4s, TMP0.4s, #10
	shl	TMP3.4s, TMP0.4s, #18
	shl	TMP4.4s, TMP0.4s, #24
	sri	TMP1.4s, TMP0.4s, #(32-2)
	sri	TMP2.4s, TMP0.4s, #(32-10)
	sri	TMP3.4s, TMP0.4s, #(32-18)
	sri	TMP4.4s, TMP0.4s, #(32-24)
	eor	TMP0.16b, TMP0.16b, TMP1.16b
	eor	TMP2.16b, TMP2.16b, TMP3.16b
	eor	TMP4.16b, TMP4.16b, \s0\().16b
	eor	TMP0.16b, TMP0.16b, TMP2.16b
	eor	\s0\().16b, TMP0.16b, TMP4.16b
.endm

.macro	round4_4x, k
	round_4x	BLK0, BLK1, BLK2, BLK3, \k\().s[0]
	round_4x	BLK1, BLK2, BLK3, BLK0, \k\().s[1]
	round_4x	BLK2, BLK3, BLK0, BLK1, \k\().s[2]
	round_4x	BLK3, BLK0, BLK1, BLK2, \k\().s[3]
.endm

LOCAL_FUNC sm4_encrypt_block4x , :
	rev32	BLK0.16b, BLK0.16b
	rev32	BLK1.16b, BLK1.16b
	rev32	BLK2.16b, BLK2.16b
	rev32	BLK3.16b, BLK3.16b

	transpose_4x4	BLK0, BLK1, BLK2, BLK3

	round4_4x	RK0
	round4_4x	RK1
	round4_4x	RK2
	round4_4x	RK3
	round4_4x	RK4
	round4_4x	RK5
	round4_4x	RK6
	round4_4x	RK7

	rotate_clockwise_90	BLK0, BLK1, BLK2, BLK3
	rev32	BLK0.16b, BLK0.16b
	rev32	BLK1.16b, BLK1.16b
	rev32	BLK2.16b, BLK2.16b
	rev32	BLK3.16b, BLK3.16b
	ret
END_FUNC sm4_encrypt_block4x

.macro	round_8x, s0, s1, s2, s3, t0, t1, t2, t3, k
	dup	TMP8.4s, \k
	eor	TMP0.16b, \s2\().16b, \s3\().16b
	mov	TMP7.16b, TMP8.16b
	eor	TMP1.16b, \t2\().16b, \t3\().16b
	eor	TMP8.16b, TMP8.16b, \s1\().16b
	eor	TMP7.16b, TMP7.16b, \t1\().16b
	eor	TMP8.16b, TMP8.16b, TMP0.16b
	eor	TMP7.16b, TMP7.16b, TMP1.16b

	/* nonlinear transformation */
	sbox_double	TMP0, TMP8, TMP1, TMP7, TMP2, TMP3

	/* linear transformation */
	shl	TMP6.4s, TMP0.4s, #2
	shl	TMP8.4s, TMP1.4s, #2
	shl	TMP2.4s, TMP0.4s, #10
	shl	TMP5.4s, TMP1.4s, #10
	shl	TMP3.4s, TMP0.4s, #18
	shl	TMP4.4s, TMP0.4s, #24
	sri	TMP6.4s, TMP0.4s, #(32-2)
	sri	TMP2.4s, TMP0.4s, #(32-10)
	sri	TMP3.4s, TMP0.4s, #(32-18)
	sri	TMP4.4s, TMP0.4s, #(32-24)
	eor	TMP0.16b, TMP0.16b, TMP6.16b
	eor	TMP2.16b, TMP2.16b, TMP3.16b
	shl	TMP6.4s, TMP1.4s, #18
	shl	TMP7.4s, TMP1.4s, #24
	sri	TMP8.4s, TMP1.4s, #(32-2)
	sri	TMP5.4s, TMP1.4s, #(32-10)
	sri	TMP6.4s, TMP1.4s, #(32-18)
	sri	TMP7.4s, TMP1.4s, #(32-24)
	eor	TMP4.16b, TMP4.16b, \s0\().16b
	eor	TMP1.16b, TMP1.16b, TMP8.16b
	eor	\s0\().16b, TMP0.16b, TMP2.16b
	eor	\s0\().16b, \s0\().16b, TMP4.16b
	eor	TMP5.16b, TMP5.16b, TMP6.16b
	eor	TMP7.16b, TMP7.16b, \t0\().16b
	eor	TMP1.16b, TMP1.16b, TMP5.16b
	eor	\t0\().16b, TMP1.16b, TMP7.16b
.endm

.macro	round4_8x, k
	round_8x BLK0, BLK1, BLK2, BLK3, BLK4, BLK5, BLK6, BLK7, \k\().s[0]
	round_8x BLK1, BLK2, BLK3, BLK0, BLK5, BLK6, BLK7, BLK4, \k\().s[1]
	round_8x BLK2, BLK3, BLK0, BLK1, BLK6, BLK7, BLK4, BLK5, \k\().s[2]
	round_8x BLK3, BLK0, BLK1, BLK2, BLK7, BLK4, BLK5, BLK6, \k\().s[3]
.endm

LOCAL_FUNC sm4_encrypt_block8x , :
	rev32	BLK0.16b, BLK0.16b
	rev32	BLK1.16b, BLK1.16b
	rev32	BLK2.16b, BLK2.16b
	rev32	BLK3.16b, BLK3.16b
	rev32	BLK4.16b, BLK4.16b
	rev32	BLK5.16b, BLK5.16b
	rev32	BLK6.16b, BLK6.16b
	rev32	BLK7.16b, BLK7.16b

	transpose_4x4	BLK0, BLK1, BLK2, BLK3
	transpose_4x4	BLK4, BLK5, BLK6, BLK7

	round4_8x	RK0
	round4_8x	RK1
	round4_8x	RK2
	round4_8x	RK3
	round4_8x	RK4
	round4_8x	RK5
	round4_8x	RK6
	round4_8x	RK7

	rotate_clockwise_90	BLK0, BLK1, BLK2, BLK3
	rotate_clockwise_90	BLK4, BLK5, BLK6, BLK7

	rev32	BLK0.16b, BLK0.16b
	rev32	BLK1.16b, BLK1.16b
	rev32	BLK2.16b, BLK2.16b
	rev32	BLK3.16b, BLK3.16b
	rev32	BLK4.16b, BLK4.16b
	rev32	BLK5.16b, BLK5.16b
	rev32	BLK6.16b, BLK6.16b
	rev32	BLK7.16b, BLK7.16b
	ret
END_FUNC sm4_encrypt_block8x

.macro	inc_le128, vctr, low, high
	mov	\vctr\().d[1], \high
	mov	\vctr\().d[0], \low
	adds	\high, \high, #1
	adc	\low, \low, xzr
	rev64	\vctr\().16b, \vctr\().16b
.endm

.macro	mov_reg_to_vec, desv, src0, src1
	mov	\desv\().d[0], \src0
	mov	\desv\().d[1], \src1
.endm

.macro	next_tweak, des0, des1, src0, src1
	mov	tmpw2, 0x87
	extr	tmpx0, \src1, \src1, #32
	extr	\des1, \src1, \src0, #63
	and	tmpw1, tmpw2, tmpw0, asr#31
	eor	\des0, tmpx1, \src0, lsl#1
.endm

.macro	next_tweak_vec, desv, srcv
	mov	tw0l, \srcv\().d[0]
	mov	tw0h, \srcv\().d[1]
	next_tweak	tw1l, tw1h, tw0l, tw0h
	mov	\desv\().d[0], tw1l
	mov	\desv\().d[1], tw1h
.endm

LOCAL_DATA .Lck , :
	.long	0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269
	.long	0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9
	.long	0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249
	.long	0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9
	.long	0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229
	.long	0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299
	.long	0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209
	.long	0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
END_DATA .Lck

LOCAL_DATA .Lfk , :
	.long	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
END_DATA .Lfk

LOCAL_DATA .Lshuffles , :
	.long	0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x03020100
END_DATA .Lshuffles

LOCAL_DATA .Lsbox_magic , :
	.dword	0x0b0e0104070a0d00, 0x0306090c0f020508
	.dword	0x62185a2042387a00, 0x22581a6002783a40
	.dword	0x15df62a89e54e923, 0xc10bb67c4a803df7
	.dword	0xb9aa6b78c1d21300, 0x1407c6d56c7fbead
	.dword	0x6404462679195b3b, 0xe383c1a1fe9edcbc
	.dword	0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
END_DATA .Lsbox_magic

.macro	sm4_setkey
	ld1	{v5.4s}, [x1]
	load_sbox_matrix
	rev32	v5.16b, v5.16b
	adr	x5, .Lfk
	ld1	{v6.4s}, [x5]
	eor	v5.16b, v5.16b, v6.16b
	mov	x6, #32
	adr	x5, .Lck
1:
	mov	w7, v5.s[1]
	ldr	w8, [x5], #4
	eor	w8, w8, w7
	mov	w7, v5.s[2]
	eor	w8, w8, w7
	mov	w7, v5.s[3]
	eor	w8, w8, w7

	/* optimize sbox using AESE instruction */
	mov	TMP0.s[0], w8
	sbox	TMP1, TMP0, TMP2, TMP3
	mov	w7, TMP1.s[0]

	/* linear transformation */
	eor	w8, w7, w7, ror #19
	eor	w8, w8, w7, ror #9
	mov	w7, v5.s[0]
	eor	w8, w8, w7
	mov	v5.s[0], w8
	ext	v5.16b, v5.16b, v5.16b, 4
	subs	x6, x6, #1
.endm

/*
 * void neon_sm4_setkey_enc(uint32_t sk[32], uint8_t const key[16]);
 * x0: round key
 * x1: user key
 */
FUNC neon_sm4_setkey_enc , :
	sm4_setkey
	str	w8, [x0], #4
	b.ne	1b
	ret
END_FUNC neon_sm4_setkey_enc

/*
 * void neon_sm4_setkey_dec(uint32_t sk[32], uint8_t const key[16]);
 * x0: round key
 * x1: user key
 */
FUNC neon_sm4_setkey_dec , :
	add	x0, x0, 124
	sm4_setkey
	str	w8, [x0], #-4
	b.ne	1b
	ret
END_FUNC neon_sm4_setkey_dec

/*
 * void neon_sm4_ecb_encrypt(uint8_t out[], uint8_t const in[],
 *			     uint8_t const rk[], size_t len);
 * x0: output
 * x1: input
 * x2: round key
 * w3: length
 */
FUNC neon_sm4_ecb_encrypt , :
	frame_push
	load_sbox_matrix
	ld1	{RK0.4s, RK1.4s, RK2.4s, RK3.4s}, [x2], #64
	ld1	{RK4.4s, RK5.4s, RK6.4s, RK7.4s}, [x2], #64
	lsr	w3, w3, 4

.Lecbloop8x:
	cmp	w3, 8
	b.lt	.Lecb4x
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x1], #64
	ld1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [x1], #64
	bl	sm4_encrypt_block8x
	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	st1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [x0], #64
	subs	w3, w3, #8
	b.gt	.Lecbloop8x

.Lecb4x:
	cmp	w3, 1
	b.lt	.Lecbout
	cmp	w3, 2
	b.lt	.Lecb1x
	cmp	w3, 3
	b.lt	.Lecb2x
	cmp	w3, 4
	b.lt	.Lecb3x
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x1], #64
	bl	sm4_encrypt_block4x
	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	sub	w3, w3, #4
	b	.Lecb4x

.Lecb3x:
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b}, [x1], #48
	bl	sm4_encrypt_block4x
	st1	{BLK0.16b, BLK1.16b, BLK2.16b}, [x0], #48
	subs	w3, w3, #3
	b.le	.Lecbout

.Lecb2x:
	ld1	{BLK0.16b, BLK1.16b}, [x1], #32
	bl	sm4_encrypt_block4x
	st1	{BLK0.16b, BLK1.16b}, [x0], #32
	subs	w3, w3, #2
	b.le	.Lecbout

.Lecb1x:
	ld1	{BLK0.16b}, [x1], #16
	bl	sm4_encrypt_block1x
	st1	{BLK0.16b}, [x0], #16

.Lecbout:
	frame_pop
	ret

END_FUNC neon_sm4_ecb_encrypt

/*
 * void neon_sm4_cbc_encrypt(uint8_t out[], uint8_t const in[],
 *			     uint8_t const rk[], size_t len,
 *			     uint8_t iv[]);
 * x0: output
 * x1: input
 * x2: round key
 * w3: length
 * x4: iv
 */
FUNC neon_sm4_cbc_encrypt , :
	frame_push
	load_sbox_matrix

	ld1	{RK0.4s, RK1.4s, RK2.4s, RK3.4s}, [x2], #64
	ld1	{RK4.4s, RK5.4s, RK6.4s, RK7.4s}, [x2], #64
	lsr	w3, w3, 4
	ld1	{IV.16b}, [x4]

.Lcbcencloop4x:
	cmp	w3, 4
	b.lt	.Lcbcenc1x
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x1], #64
	eor	BLK0.16b, BLK0.16b, IV.16b
	rev32	BLK0.16b, BLK0.16b
	rev32	BLK1.16b, BLK1.16b
	rev32	BLK2.16b, BLK2.16b
	rev32	BLK3.16b, BLK3.16b
	encrypt_block_no_rev	BLK0
	eor	BLK1.16b, BLK1.16b, BLK0.16b
	encrypt_block_no_rev	BLK1
	rev32	BLK0.16b, BLK0.16b
	eor	BLK2.16b, BLK2.16b, BLK1.16b
	encrypt_block_no_rev	BLK2
	rev32	BLK1.16b, BLK1.16b
	eor	BLK3.16b, BLK3.16b, BLK2.16b
	encrypt_block_no_rev	BLK3
	rev32	BLK2.16b, BLK2.16b
	rev32	BLK3.16b, BLK3.16b
	mov	IV.16b, BLK3.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	subs	w3, w3, #4
	b	.Lcbcencloop4x
.Lcbcenc1x:
	cmp	w3, 1
	b.lt	.Lcbcencout
.Lcbcencloop:
	ld1	{BLK0.16b}, [x1], #16
	eor	BLK0.16b, BLK0.16b, IV.16b
	bl	sm4_encrypt_block1x
	mov	IV.16b, BLK0.16b
	st1	{BLK0.16b}, [x0], #16
	subs	w3, w3, #1
	bne	.Lcbcencloop
.Lcbcencout:
	st1	{IV.16b}, [x4]
	frame_pop
	ret
END_FUNC neon_sm4_cbc_encrypt

/*
 * void neon_sm4_cbc_decrypt(uint8_t out[], uint8_t const in[],
 *			     uint8_t const rk[], size_t len,
 *			     uint8_t iv[]);
 * x0: output
 * x1: input
 * x2: round key
 * w3: length
 * x4: iv
 */
FUNC neon_sm4_cbc_decrypt , :
	frame_push
	load_sbox_matrix

	ld1	{RK0.4s, RK1.4s, RK2.4s, RK3.4s}, [x2], #64
	ld1	{RK4.4s, RK5.4s, RK6.4s, RK7.4s}, [x2], #64
	lsr	w3, w3, 4
	ld1	{IV.16b}, [x4]

.Lcbcdecloop8x:
	cmp	w3, 8
	b.lt	.Lcbcdec4x

	ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x1], #64
	ld1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [x1], #64
	bl	sm4_encrypt_block8x
	sub	x5, x1, #128
	eor	BLK0.16b, BLK0.16b, IV.16b
	ld1	{TMP0.16b, TMP1.16b, TMP2.16b, TMP3.16b}, [x5], #64
	eor	BLK1.16b, BLK1.16b, TMP0.16b
	eor	BLK2.16b, BLK2.16b, TMP1.16b
	eor	BLK3.16b, BLK3.16b, TMP2.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	ld1	{TMP4.16b, TMP5.16b, TMP6.16b, TMP7.16b}, [x5], #64
	eor	BLK4.16b, BLK4.16b, TMP3.16b
	eor	BLK5.16b, BLK5.16b, TMP4.16b
	mov	IV.16b, TMP7.16b
	eor	BLK6.16b, BLK6.16b, TMP5.16b
	eor	BLK7.16b, BLK7.16b, TMP6.16b
	st1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [x0], #64
	subs	w3, w3, #8
	b.gt	.Lcbcdecloop8x

.Lcbcdec4x:
	cmp	w3, 1
	b.lt	.Lcbcdecout
	cmp	w3, 2
	b.lt	.Lcbcdec1x
	cmp	w3, 3
	b.lt	.Lcbcdec2x
	cmp	w3, 4
	b.lt	.Lcbcdec3x
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x1], #64
	bl	sm4_encrypt_block4x
	sub	x5, x1, 64
	ld1	{TMP0.16b, TMP1.16b, TMP2.16b, TMP3.16b}, [x5], #64
	eor	BLK0.16b, BLK0.16b, IV.16b
	eor	BLK1.16b, BLK1.16b, TMP0.16b
	eor	BLK2.16b, BLK2.16b, TMP1.16b
	eor	BLK3.16b, BLK3.16b, TMP2.16b
	mov	IV.16b, TMP3.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	sub	w3, w3, #4
	b	.Lcbcdec4x

.Lcbcdec3x:
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b}, [x1], #48
	bl	sm4_encrypt_block4x
	sub	x5, x1, 48
	ld1	{TMP0.16b, TMP1.16b, TMP2.16b}, [x5], #48
	eor	BLK0.16b, BLK0.16b, IV.16b
	eor	BLK1.16b, BLK1.16b, TMP0.16b
	eor	BLK2.16b, BLK2.16b, TMP1.16b
	mov	IV.16b, TMP2.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b}, [x0], #48
	subs	w3, w3, #3
	b.le	.Lcbcdecout

.Lcbcdec2x:
	ld1	{BLK0.16b, BLK1.16b}, [x1], #32
	bl	sm4_encrypt_block4x
	sub	x5, x1, 32
	ld1	{TMP0.16b, TMP1.16b}, [x5], #32
	eor	BLK0.16b, BLK0.16b, IV.16b
	eor	BLK1.16b, BLK1.16b, TMP0.16b
	mov	IV.16b, TMP1.16b
	st1	{BLK0.16b, BLK1.16b}, [x0], #32
	subs	w3, w3, #2
	b.le	.Lcbcdecout

.Lcbcdec1x:
	ld1	{BLK0.16b}, [x1], #16
	bl	sm4_encrypt_block1x
	sub	x5, x1, 16
	ld1	{TMP0.16b}, [x5], #16
	eor	BLK0.16b, BLK0.16b, IV.16b
	mov	IV.16b, TMP0.16b
	st1	{BLK0.16b}, [x0], #16

.Lcbcdecout:
	st1	{IV.16b}, [x4]
	frame_pop
	ret
END_FUNC neon_sm4_cbc_decrypt

/*
 * void neon_sm4_ctr_encrypt(uint8_t out[], uint8_t const in[],
 *			     uint8_t const rk[], size_t len,
 *			     uint8_t iv[]);
 * x0: output
 * x1: input
 * x2: round key
 * w3: length
 * x4: iv
 */
FUNC neon_sm4_ctr_encrypt , :
	frame_push
	load_sbox_matrix

	ld1	{RK0.4s, RK1.4s, RK2.4s, RK3.4s}, [x2], #64
	ld1	{RK4.4s, RK5.4s, RK6.4s, RK7.4s}, [x2], #64
	lsr	w3, w3, 4
	ldp	x7, x8, [x4]
	rev	x7, x7
	rev	x8, x8

.Lctrloop8x:
	cmp	w3, 8
	b.lt	.Lctr4x

	/* construct CTRs */
	inc_le128	BLK0, x7, x8
	inc_le128	BLK1, x7, x8
	inc_le128	BLK2, x7, x8
	inc_le128	BLK3, x7, x8
	inc_le128	BLK4, x7, x8
	inc_le128	BLK5, x7, x8
	inc_le128	BLK6, x7, x8
	inc_le128	BLK7, x7, x8
	bl	sm4_encrypt_block8x
	ld1	{TMP0.16b, TMP1.16b, TMP2.16b, TMP3.16b}, [x1], #64
	ld1	{TMP4.16b, TMP5.16b, TMP6.16b, TMP7.16b}, [x1], #64
	eor	BLK0.16b, BLK0.16b, TMP0.16b
	eor	BLK1.16b, BLK1.16b, TMP1.16b
	eor	BLK2.16b, BLK2.16b, TMP2.16b
	eor	BLK3.16b, BLK3.16b, TMP3.16b
	eor	BLK4.16b, BLK4.16b, TMP4.16b
	eor	BLK5.16b, BLK5.16b, TMP5.16b
	eor	BLK6.16b, BLK6.16b, TMP6.16b
	eor	BLK7.16b, BLK7.16b, TMP7.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	st1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [x0], #64
	subs	w3, w3, #8
	b.gt	.Lctrloop8x

.Lctr4x:
	cmp	w3, 1
	b.lt	.Lctrout
	cmp	w3, 2
	b.lt	.Lctr1x
	cmp	w3, 3
	b.lt	.Lctr2x
	cmp	w3, 4
	b.lt	.Lctr3x
	inc_le128	BLK0, x7, x8
	inc_le128	BLK1, x7, x8
	inc_le128	BLK2, x7, x8
	inc_le128	BLK3, x7, x8
	bl	sm4_encrypt_block4x
	ld1	{TMP0.16b, TMP1.16b, TMP2.16b, TMP3.16b}, [x1], #64
	eor	BLK0.16b, BLK0.16b, TMP0.16b
	eor	BLK1.16b, BLK1.16b, TMP1.16b
	eor	BLK2.16b, BLK2.16b, TMP2.16b
	eor	BLK3.16b, BLK3.16b, TMP3.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	sub	w3, w3, #4
	b	.Lctr4x

.Lctr3x:
	inc_le128	BLK0, x7, x8
	inc_le128	BLK1, x7, x8
	inc_le128	BLK2, x7, x8
	bl	sm4_encrypt_block4x
	ld1	{TMP0.16b, TMP1.16b, TMP2.16b}, [x1], #48
	eor	BLK0.16b, BLK0.16b, TMP0.16b
	eor	BLK1.16b, BLK1.16b, TMP1.16b
	eor	BLK2.16b, BLK2.16b, TMP2.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b}, [x0], #48
	subs	w3, w3, #3
	b.le	.Lctrout

.Lctr2x:
	inc_le128	BLK0, x7, x8
	inc_le128	BLK1, x7, x8
	bl	sm4_encrypt_block4x
	ld1	{TMP0.16b, TMP1.16b}, [x1], #32
	eor	BLK0.16b, BLK0.16b, TMP0.16b
	eor	BLK1.16b, BLK1.16b, TMP1.16b
	st1	{BLK0.16b, BLK1.16b}, [x0], #32
	subs	w3, w3, #2
	b.le	.Lctrout

.Lctr1x:
	inc_le128	BLK0, x7, x8
	bl	sm4_encrypt_block1x
	ld1	{TMP0.16b}, [x1], #16
	eor	BLK0.16b, BLK0.16b, TMP0.16b
	st1	{BLK0.16b}, [x0], #16

.Lctrout:
	rev	x7, x7
	rev	x8, x8
	stp	x7, x8, [x4]
	frame_pop
	ret
END_FUNC neon_sm4_ctr_encrypt

/*
 * x0: output
 * x1: input
 * x2: round key1
 * x3: round key2
 * w4: blocks
 * x26: enc/dec
 */
LOCAL_FUNC xts_do_cipher , :
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	load_sbox_matrix
	ld1	{IV.16b}, [x5]
	/* load round key2 for first tweak */
	ld1	{RK0.4s, RK1.4s, RK2.4s, RK3.4s}, [x3], #64
	ld1	{RK4.4s, RK5.4s, RK6.4s, RK7.4s}, [x3], #64
	encrypt_block	IV
	/* load round key1 for block cipher */
	ld1	{RK0.4s, RK1.4s, RK2.4s, RK3.4s}, [x2], #64
	ld1	{RK4.4s, RK5.4s, RK6.4s, RK7.4s}, [x2], #64
	/* w6: remain */
	and	w6, w4, #0x0F
	/* w4: blocks */
	lsr	w4, w4, 4
	/* blocks == 0: ret */
	cmp	w4, #1
	b.lt	.Lxtsout
	cmp	w6, 0
	b.eq	.Lxtsblks
	subs	w4, w4, #1
	b.eq	.Lxtstail
.Lxtsblks:
	mov	tw0l, IV.d[0]
	mov	tw0h, IV.d[1]
	next_tweak	tw1l, tw1h, tw0l, tw0h
	next_tweak	tw2l, tw2h, tw1l, tw1h
	next_tweak	tw3l, tw3h, tw2l, tw2h
	next_tweak	tw4l, tw4h, tw3l, tw3h
	next_tweak	tw5l, tw5h, tw4l, tw4h
	next_tweak	tw6l, tw6h, tw5l, tw5h
	next_tweak	tw7l, tw7h, tw6l, tw6h
.Lxtsloop8x:
	cmp	w4, 8
	b.lt	.Lxts4x
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x1], #64
	mov_reg_to_vec	TMP0, tw0l, tw0h
	mov_reg_to_vec	TMP1, tw1l, tw1h
	mov_reg_to_vec	TMP2, tw2l, tw2h
	mov_reg_to_vec	TMP3, tw3l, tw3h
	eor BLK0.16b, BLK0.16b, TMP0.16b
	eor BLK1.16b, BLK1.16b, TMP1.16b
	eor BLK2.16b, BLK2.16b, TMP2.16b
	eor BLK3.16b, BLK3.16b, TMP3.16b
	ld1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [x1], #64
	mov_reg_to_vec	TMP4, tw4l, tw4h
	mov_reg_to_vec	TMP5, tw5l, tw5h
	mov_reg_to_vec	TMP6, tw6l, tw6h
	mov_reg_to_vec	IV, tw7l, tw7h
	eor BLK4.16b, BLK4.16b, TMP4.16b
	eor BLK5.16b, BLK5.16b, TMP5.16b
	eor BLK6.16b, BLK6.16b, TMP6.16b
	eor BLK7.16b, BLK7.16b, IV.16b

	bl	sm4_encrypt_block8x

	mov_reg_to_vec	TMP0, tw0l, tw0h
	next_tweak	tw0l, tw0h, tw7l, tw7h
	mov_reg_to_vec	TMP1, tw1l, tw1h
	next_tweak	tw1l, tw1h, tw0l, tw0h
	mov_reg_to_vec	TMP2, tw2l, tw2h
	next_tweak	tw2l, tw2h, tw1l, tw1h
	mov_reg_to_vec	TMP3, tw3l, tw3h
	next_tweak	tw3l, tw3h, tw2l, tw2h
	mov_reg_to_vec	TMP4, tw4l, tw4h
	next_tweak	tw4l, tw4h, tw3l, tw3h
	mov_reg_to_vec	TMP5, tw5l, tw5h
	next_tweak	tw5l, tw5h, tw4l, tw4h
	mov_reg_to_vec	TMP6, tw6l, tw6h
	next_tweak	tw6l, tw6h, tw5l, tw5h
	mov_reg_to_vec	IV, tw7l, tw7h
	next_tweak	tw7l, tw7h, tw6l, tw6h

	eor BLK0.16b, BLK0.16b, TMP0.16b
	eor BLK1.16b, BLK1.16b, TMP1.16b
	eor BLK2.16b, BLK2.16b, TMP2.16b
	eor BLK3.16b, BLK3.16b, TMP3.16b
	eor BLK4.16b, BLK4.16b, TMP4.16b
	eor BLK5.16b, BLK5.16b, TMP5.16b
	eor BLK6.16b, BLK6.16b, TMP6.16b
	eor BLK7.16b, BLK7.16b, IV.16b

	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	st1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [x0], #64
	subs	w4, w4, #8
	b.gt	.Lxtsloop8x

.Lxts4x:
	cmp	w4, 1
	b.lt	.Lxtsblksout
	cmp	w4, 2
	b.lt	.Lxts1x
	cmp	w4, 3
	b.lt	.Lxts2x
	cmp	w4, 4
	b.lt	.Lxts3x
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x1], #64
	mov_reg_to_vec	BLK4, tw0l, tw0h
	mov_reg_to_vec	BLK5, tw1l, tw1h
	mov_reg_to_vec	BLK6, tw2l, tw2h
	mov_reg_to_vec	IV, tw3l, tw3h
	eor	BLK0.16b, BLK0.16b, BLK4.16b
	eor	BLK1.16b, BLK1.16b, BLK5.16b
	eor	BLK2.16b, BLK2.16b, BLK6.16b
	eor	BLK3.16b, BLK3.16b, IV.16b
	bl	sm4_encrypt_block4x
	eor	BLK0.16b, BLK0.16b, BLK4.16b
	eor	BLK1.16b, BLK1.16b, BLK5.16b
	eor	BLK2.16b, BLK2.16b, BLK6.16b
	eor	BLK3.16b, BLK3.16b, IV.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [x0], #64
	sub	w4, w4, #4

	mov	tw0l, tw4l
	mov	tw0h, tw4h
	mov	tw1l, tw5l
	mov	tw1h, tw5h
	mov	tw2l, tw6l
	mov	tw2h, tw6h
	b	.Lxts4x

.Lxts3x:
	ld1	{BLK0.16b, BLK1.16b, BLK2.16b}, [x1], #48
	mov_reg_to_vec	BLK4, tw0l, tw0h
	mov_reg_to_vec	BLK5, tw1l, tw1h
	mov_reg_to_vec	IV, tw2l, tw2h
	eor	BLK0.16b, BLK0.16b, BLK4.16b
	eor	BLK1.16b, BLK1.16b, BLK5.16b
	eor	BLK2.16b, BLK2.16b, IV.16b
	bl	sm4_encrypt_block4x
	eor	BLK0.16b, BLK0.16b, BLK4.16b
	eor	BLK1.16b, BLK1.16b, BLK5.16b
	eor	BLK2.16b, BLK2.16b, IV.16b
	st1	{BLK0.16b, BLK1.16b, BLK2.16b}, [x0], #48
	subs	w4, w4, #3
	b.le	.Lxtsblksout

.Lxts2x:
	ld1	{BLK0.16b, BLK1.16b}, [x1], #32
	mov_reg_to_vec	BLK4, tw0l, tw0h
	mov_reg_to_vec	IV, tw1l, tw1h
	eor	BLK0.16b, BLK0.16b, BLK4.16b
	eor	BLK1.16b, BLK1.16b, IV.16b
	bl	sm4_encrypt_block4x
	eor	BLK0.16b, BLK0.16b, BLK4.16b
	eor	BLK1.16b, BLK1.16b, IV.16b
	st1	{BLK0.16b, BLK1.16b}, [x0], #32
	subs	w4, w4, #2
	b.le	.Lxtsblksout

.Lxts1x:
	ld1	{BLK0.16b}, [x1], #16
	mov_reg_to_vec	IV, tw0l, tw0h
	eor	BLK0.16b, BLK0.16b, IV.16b
	bl	sm4_encrypt_block1x
	eor	BLK0.16b, BLK0.16b, IV.16b
	st1	{BLK0.16b}, [x0], #16
.Lxtsblksout:
	cmp	w6, 0
	/* if encrypt some blocks with a partial block */
	next_tweak_vec	IV, IV
	b.eq	.Lxtsout
.Lxtstail:
	next_tweak_vec	TMP7, IV
	cmp	x26, 1
	b.eq	1f
	/* The last two tweaks IV, TMP7 need to be swapped for decryption */
	mov	TMP8.16b, IV.16b
	mov	IV.16b, TMP7.16b
	mov	TMP7.16b, TMP8.16b
	1:
	ld1	{BLK0.16b}, [x1], #16
	eor	BLK0.16b, BLK0.16b, IV.16b
	bl	sm4_encrypt_block1x
	eor	BLK0.16b, BLK0.16b, IV.16b
	st1	{BLK0.16b}, [x0], #16
	sub	x7, x0, 16
	10:
	subs	x6, x6, 1
	ldrb	tmpw0, [x7, x6]
	strb	tmpw0, [x0, x6]
	ldrb	tmpw0, [x1, x6]
	strb	tmpw0, [x7, x6]
	b.gt	10b
	ld1	{BLK0.16b}, [x7]
	eor	BLK0.16b, BLK0.16b, TMP7.16b
	bl	sm4_encrypt_block1x
	eor	BLK0.16b, BLK0.16b, TMP7.16b
	st1	{BLK0.16b}, [x7]

.Lxtsout:
	/* load round key2 for last tweak */
	sub	x3, x3, #128
	ld1	{RK0.4s, RK1.4s, RK2.4s, RK3.4s}, [x3], #64
	ld1	{RK4.4s, RK5.4s, RK6.4s, RK7.4s}, [x3], #64
	/* decrypt last tweak for next update */
	decrypt_block	IV
	st1	{IV.16b}, [x5]
	ldp x29, x30, [sp], #16
	ret
END_FUNC xts_do_cipher

/*
 * void neon_sm4_xts_encrypt(uint8_t out[], uint8_t const in[],
 * 			     uint8_t const rk1[], uint8_t const rk2[],
 * 			     size_t len, uint8_t iv[])
 * x0: output
 * x1: input
 * x2: round key1
 * x3: round key2
 * w4: len
 * x5: iv
 */
FUNC neon_sm4_xts_encrypt , :
	frame_push
	mov	x26, 1
	bl	xts_do_cipher
	frame_pop
	ret
END_FUNC neon_sm4_xts_encrypt

/*
 * void neon_sm4_xts_decrypt(uint8_t out[], uint8_t const in[],
 * 			     uint8_t const rk1[], uint8_t const rk2[],
 * 			     size_t len, uint8_t iv[])
 * x0: output
 * x1: input
 * x2: round key1
 * x3: round key2
 * w4: len
 * x5: iv
 */
FUNC neon_sm4_xts_decrypt , :
	frame_push
	mov	x26, 0
	bl	xts_do_cipher
	frame_pop
	ret
END_FUNC neon_sm4_xts_decrypt
