/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018 Linaro Ltd <ard.biesheuvel@linaro.org>
 * Copyright (c) 2023 Linaro Limited
 */

/* Core SHA-3 transform using v8 Crypto Extensions */

#include <asm.S>
#include <arm64_macros.S>

	.irp	b,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,\
		21,22,23,24,25,26,27,28,29,30,31
	.set	.Lv\b\().2d, \b
	.set	.Lv\b\().16b, \b
	.endr

	/*
	 * ARMv8.2 Crypto Extensions instructions
	 */
	.macro	eor3, rd, rn, rm, ra
	.inst	0xce000000 | .L\rd | (.L\rn << 5) | (.L\ra << 10) | \
		(.L\rm << 16)
	.endm

	.macro	rax1, rd, rn, rm
	.inst	0xce608c00 | .L\rd | (.L\rn << 5) | (.L\rm << 16)
	.endm

	.macro	bcax, rd, rn, rm, ra
	.inst	0xce200000 | .L\rd | (.L\rn << 5) | (.L\ra << 10) | \
		(.L\rm << 16)
	.endm

	.macro	xar, rd, rn, rm, imm6
	.inst	0xce800000 | .L\rd | (.L\rn << 5) | ((\imm6) << 10) | \
		(.L\rm << 16)
	.endm

	/*
	 * int sha3_ce_transform(u64 *st, const u8 *data, int blocks,
	 *			 int dg_size)
	 */
	.text
FUNC sha3_ce_transform , :
	/* load state */
	add	x8, x0, #32
	ld1	{ v0.1d- v3.1d}, [x0]
	ld1	{ v4.1d- v7.1d}, [x8], #32
	ld1	{ v8.1d-v11.1d}, [x8], #32
	ld1	{v12.1d-v15.1d}, [x8], #32
	ld1	{v16.1d-v19.1d}, [x8], #32
	ld1	{v20.1d-v23.1d}, [x8], #32
	ld1	{v24.1d}, [x8]

0:	sub	w2, w2, #1
	mov	w8, #24
	adr_l	x9, .Lsha3_rcon

	/* load input */
	ld1	{v25.8b-v28.8b}, [x1], #32
	ld1	{v29.8b-v31.8b}, [x1], #24
	eor	v0.8b, v0.8b, v25.8b
	eor	v1.8b, v1.8b, v26.8b
	eor	v2.8b, v2.8b, v27.8b
	eor	v3.8b, v3.8b, v28.8b
	eor	v4.8b, v4.8b, v29.8b
	eor	v5.8b, v5.8b, v30.8b
	eor	v6.8b, v6.8b, v31.8b

	/* Bit 6 set? -> SHA3-512 */
	tbnz	x3, #6, 3f

	/* SHA3-384, SHA3-256, SHA3-224 or SHA3-128 */
	ld1	{v25.8b-v28.8b}, [x1], #32
	ld1	{v29.8b-v30.8b}, [x1], #16
	eor	 v7.8b,  v7.8b, v25.8b
	eor	 v8.8b,  v8.8b, v26.8b
	eor	 v9.8b,  v9.8b, v27.8b
	eor	v10.8b, v10.8b, v28.8b
	eor	v11.8b, v11.8b, v29.8b
	eor	v12.8b, v12.8b, v30.8b

	/* bit 4 set? -> SHA3-384, SHA3-224 or SHA3-128 */
	tbnz	x3, #4, 1f

	/* SHA3-256: digest size 32 bytes, block size 136 bytes */
	ld1	{v25.8b-v28.8b}, [x1], #32
	eor	v13.8b, v13.8b, v25.8b
	eor	v14.8b, v14.8b, v26.8b
	eor	v15.8b, v15.8b, v27.8b
	eor	v16.8b, v16.8b, v28.8b
	b	4f

	/* bit 5 set? -> SHA-384 */
1:	tbnz	x3, #5, 4f

	/* SHA3-224 or SHA3-128 */
	ld1	{v25.8b-v28.8b}, [x1], #32
	eor	v13.8b, v13.8b, v25.8b
	eor	v14.8b, v14.8b, v26.8b
	eor	v15.8b, v15.8b, v27.8b
	eor	v16.8b, v16.8b, v28.8b

	/* bit 2 set? -> SHA-224 */
	tbnz	x3, #2, 2f

	/* SHA3-128: digest size 16 bytes, block size 168 bytes */
	ld1	{v25.8b-v28.8b}, [x1], #32
	eor	v17.8b, v17.8b, v25.8b
	eor	v18.8b, v18.8b, v26.8b
	eor	v19.8b, v19.8b, v27.8b
	eor	v20.8b, v20.8b, v28.8b
	b	4f

	/* SHA3-224: digest size 28 bytes, block size 144 bytes */
2:	ld1	{v29.8b}, [x1], #8
	eor	v17.8b, v17.8b, v29.8b
	b	4f

	/* SHA3-512: digest size 64 bytes , block size 72 bytes */
3:	ld1	{v25.8b-v26.8b}, [x1], #16
	eor	 v7.8b,  v7.8b, v25.8b
	eor	 v8.8b,  v8.8b, v26.8b

4:	sub	w8, w8, #1

	eor3	v29.16b,  v4.16b,  v9.16b, v14.16b
	eor3	v26.16b,  v1.16b,  v6.16b, v11.16b
	eor3	v28.16b,  v3.16b,  v8.16b, v13.16b
	eor3	v25.16b,  v0.16b,  v5.16b, v10.16b
	eor3	v27.16b,  v2.16b,  v7.16b, v12.16b
	eor3	v29.16b, v29.16b, v19.16b, v24.16b
	eor3	v26.16b, v26.16b, v16.16b, v21.16b
	eor3	v28.16b, v28.16b, v18.16b, v23.16b
	eor3	v25.16b, v25.16b, v15.16b, v20.16b
	eor3	v27.16b, v27.16b, v17.16b, v22.16b

	rax1	v30.2d, v29.2d, v26.2d	// bc[0]
	rax1	v26.2d, v26.2d, v28.2d	// bc[2]
	rax1	v28.2d, v28.2d, v25.2d	// bc[4]
	rax1	v25.2d, v25.2d, v27.2d	// bc[1]
	rax1	v27.2d, v27.2d, v29.2d	// bc[3]

	eor	 v0.16b,  v0.16b, v30.16b
	xar	 v29.2d,   v1.2d,  v25.2d, (64 - 1)
	xar	  v1.2d,   v6.2d,  v25.2d, (64 - 44)
	xar	  v6.2d,   v9.2d,  v28.2d, (64 - 20)
	xar	  v9.2d,  v22.2d,  v26.2d, (64 - 61)
	xar	 v22.2d,  v14.2d,  v28.2d, (64 - 39)
	xar	 v14.2d,  v20.2d,  v30.2d, (64 - 18)
	xar	 v31.2d,   v2.2d,  v26.2d, (64 - 62)
	xar	  v2.2d,  v12.2d,  v26.2d, (64 - 43)
	xar	 v12.2d,  v13.2d,  v27.2d, (64 - 25)
	xar	 v13.2d,  v19.2d,  v28.2d, (64 - 8)
	xar	 v19.2d,  v23.2d,  v27.2d, (64 - 56)
	xar	 v23.2d,  v15.2d,  v30.2d, (64 - 41)
	xar	 v15.2d,   v4.2d,  v28.2d, (64 - 27)
	xar	 v28.2d,  v24.2d,  v28.2d, (64 - 14)
	xar	 v24.2d,  v21.2d,  v25.2d, (64 - 2)
	xar	  v8.2d,   v8.2d,  v27.2d, (64 - 55)
	xar	  v4.2d,  v16.2d,  v25.2d, (64 - 45)
	xar	 v16.2d,   v5.2d,  v30.2d, (64 - 36)
	xar	  v5.2d,   v3.2d,  v27.2d, (64 - 28)
	xar	 v27.2d,  v18.2d,  v27.2d, (64 - 21)
	xar	  v3.2d,  v17.2d,  v26.2d, (64 - 15)
	xar	 v25.2d,  v11.2d,  v25.2d, (64 - 10)
	xar	 v26.2d,   v7.2d,  v26.2d, (64 - 6)
	xar	 v30.2d,  v10.2d,  v30.2d, (64 - 3)

	bcax	v20.16b, v31.16b, v22.16b,  v8.16b
	bcax	v21.16b,  v8.16b, v23.16b, v22.16b
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	bcax	v23.16b, v23.16b, v31.16b, v24.16b
	bcax	v24.16b, v24.16b,  v8.16b, v31.16b

	ld1r	{v31.2d}, [x9], #8

	bcax	v17.16b, v25.16b, v19.16b,  v3.16b
	bcax	v18.16b,  v3.16b, v15.16b, v19.16b
	bcax	v19.16b, v19.16b, v16.16b, v15.16b
	bcax	v15.16b, v15.16b, v25.16b, v16.16b
	bcax	v16.16b, v16.16b,  v3.16b, v25.16b

	bcax	v10.16b, v29.16b, v12.16b, v26.16b
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	bcax	v13.16b, v13.16b, v29.16b, v14.16b
	bcax	v14.16b, v14.16b, v26.16b, v29.16b

	bcax	 v7.16b, v30.16b,  v9.16b,  v4.16b
	bcax	 v8.16b,  v4.16b,  v5.16b,  v9.16b
	bcax	 v9.16b,  v9.16b,  v6.16b,  v5.16b
	bcax	 v5.16b,  v5.16b, v30.16b,  v6.16b
	bcax	 v6.16b,  v6.16b,  v4.16b, v30.16b

	bcax	 v3.16b, v27.16b,  v0.16b, v28.16b
	bcax	 v4.16b, v28.16b,  v1.16b,  v0.16b
	bcax	 v0.16b,  v0.16b,  v2.16b,  v1.16b
	bcax	 v1.16b,  v1.16b, v27.16b,  v2.16b
	bcax	 v2.16b,  v2.16b, v28.16b, v27.16b

	eor	 v0.16b,  v0.16b, v31.16b

	cbnz	w8, 4b
	cbnz	w2, 0b

	/* save state */
	st1	{ v0.1d- v3.1d}, [x0], #32
	st1	{ v4.1d- v7.1d}, [x0], #32
	st1	{ v8.1d-v11.1d}, [x0], #32
	st1	{v12.1d-v15.1d}, [x0], #32
	st1	{v16.1d-v19.1d}, [x0], #32
	st1	{v20.1d-v23.1d}, [x0], #32
	st1	{v24.1d}, [x0]
	mov	w0, w2
	ret
END_FUNC sha3_ce_transform

	.section	".rodata", "a"
	.align		8
LOCAL_DATA .Lsha3_rcon , :
	.quad	0x0000000000000001, 0x0000000000008082, 0x800000000000808a
	.quad	0x8000000080008000, 0x000000000000808b, 0x0000000080000001
	.quad	0x8000000080008081, 0x8000000000008009, 0x000000000000008a
	.quad	0x0000000000000088, 0x0000000080008009, 0x000000008000000a
	.quad	0x000000008000808b, 0x800000000000008b, 0x8000000000008089
	.quad	0x8000000000008003, 0x8000000000008002, 0x8000000000000080
	.quad	0x000000000000800a, 0x800000008000000a, 0x8000000080008081
	.quad	0x8000000000008080, 0x0000000080000001, 0x8000000080008008

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
