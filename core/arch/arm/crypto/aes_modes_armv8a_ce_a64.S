/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, 2020 Linaro Limited
 * Copyright (C) 2013 Linaro Ltd <ard.biesheuvel@linaro.org>
 *
 * - AES cipher for ARMv8 with Crypto Extensions
 * - Chaining mode wrappers for AES
 */

#include <asm.S>

	.arch		armv8-a+crypto

	/* Preload all round keys */
	.macro		load_round_keys, rounds, rk
	cmp		\rounds, #12
	blo		2222f		/* 128 bits */
	beq		1111f		/* 192 bits */
	ld1		{v17.16b-v18.16b}, [\rk], #32
1111:	ld1		{v19.16b-v20.16b}, [\rk], #32
2222:	ld1		{v21.16b-v24.16b}, [\rk], #64
	ld1		{v25.16b-v28.16b}, [\rk], #64
	ld1		{v29.16b-v31.16b}, [\rk]
	.endm

	/* Prepare for encryption with key in rk[] */
	.macro		enc_prepare, rounds, rk, ignore
	load_round_keys	\rounds, \rk
	.endm

	/* Prepare for encryption (again) but with new key in rk[] */
	.macro		enc_switch_key, rounds, rk, ignore
	load_round_keys	\rounds, \rk
	.endm

	/* Prepare for decryption with key in rk[] */
	.macro		dec_prepare, rounds, rk, ignore
	load_round_keys	\rounds, \rk
	.endm

	.macro		do_enc_Nx, de, mc, k, i0, i1, i2, i3
	aes\de		\i0\().16b, \k\().16b
	aes\mc		\i0\().16b, \i0\().16b
	.ifnb		\i1
	aes\de		\i1\().16b, \k\().16b
	aes\mc		\i1\().16b, \i1\().16b
	.ifnb		\i3
	aes\de		\i2\().16b, \k\().16b
	aes\mc		\i2\().16b, \i2\().16b
	aes\de		\i3\().16b, \k\().16b
	aes\mc		\i3\().16b, \i3\().16b
	.endif
	.endif
	.endm

	/* Up to 4 interleaved encryption rounds with the same round key */
	.macro		round_Nx, enc, k, i0, i1, i2, i3
	.ifc		\enc, e
	do_enc_Nx	e, mc, \k, \i0, \i1, \i2, \i3
	.else
	do_enc_Nx	d, imc, \k, \i0, \i1, \i2, \i3
	.endif
	.endm

	/* Up to 4 interleaved final rounds */
	.macro		fin_round_Nx, de, k, k2, i0, i1, i2, i3
	aes\de		\i0\().16b, \k\().16b
	.ifnb		\i1
	aes\de		\i1\().16b, \k\().16b
	.ifnb		\i3
	aes\de		\i2\().16b, \k\().16b
	aes\de		\i3\().16b, \k\().16b
	.endif
	.endif
	eor		\i0\().16b, \i0\().16b, \k2\().16b
	.ifnb		\i1
	eor		\i1\().16b, \i1\().16b, \k2\().16b
	.ifnb		\i3
	eor		\i2\().16b, \i2\().16b, \k2\().16b
	eor		\i3\().16b, \i3\().16b, \k2\().16b
	.endif
	.endif
	.endm

	/* Up to 4 interleaved blocks */
	.macro		do_block_Nx, enc, rounds, i0, i1, i2, i3
	cmp		\rounds, #12
	blo		2222f		/* 128 bits */
	beq		1111f		/* 192 bits */
	round_Nx	\enc, v17, \i0, \i1, \i2, \i3
	round_Nx	\enc, v18, \i0, \i1, \i2, \i3
1111:	round_Nx	\enc, v19, \i0, \i1, \i2, \i3
	round_Nx	\enc, v20, \i0, \i1, \i2, \i3
2222:	.irp		key, v21, v22, v23, v24, v25, v26, v27, v28, v29
	round_Nx	\enc, \key, \i0, \i1, \i2, \i3
	.endr
	fin_round_Nx	\enc, v30, v31, \i0, \i1, \i2, \i3
	.endm

	.macro		encrypt_block, in, rounds, t0, t1, t2
	do_block_Nx	e, \rounds, \in
	.endm

	.macro		encrypt_block2x, i0, i1, rounds, t0, t1, t2
	do_block_Nx	e, \rounds, \i0, \i1
	.endm

	.macro		encrypt_block4x, i0, i1, i2, i3, rounds, t0, t1, t2
	do_block_Nx	e, \rounds, \i0, \i1, \i2, \i3
	.endm

	.macro		decrypt_block, in, rounds, t0, t1, t2
	do_block_Nx	d, \rounds, \in
	.endm

	.macro		decrypt_block2x, i0, i1, rounds, t0, t1, t2
	do_block_Nx	d, \rounds, \i0, \i1
	.endm

	.macro		decrypt_block4x, i0, i1, i2, i3, rounds, t0, t1, t2
	do_block_Nx	d, \rounds, \i0, \i1, \i2, \i3
	.endm


/*
 * There are several ways to instantiate this code:
 * - no interleave, all inline
 * - 2-way interleave, 2x calls out of line (-DINTERLEAVE=2)
 * - 2-way interleave, all inline (-DINTERLEAVE=2 -DINTERLEAVE_INLINE)
 * - 4-way interleave, 4x calls out of line (-DINTERLEAVE=4)
 * - 4-way interleave, all inline (-DINTERLEAVE=4 -DINTERLEAVE_INLINE)
 *
 * Macros imported by this code:
 * - enc_prepare	- setup NEON registers for encryption
 * - dec_prepare	- setup NEON registers for decryption
 * - enc_switch_key	- change to new key after having prepared for encryption
 * - encrypt_block	- encrypt a single block
 * - decrypt block	- decrypt a single block
 * - encrypt_block2x	- encrypt 2 blocks in parallel (if INTERLEAVE == 2)
 * - decrypt_block2x	- decrypt 2 blocks in parallel (if INTERLEAVE == 2)
 * - encrypt_block4x	- encrypt 4 blocks in parallel (if INTERLEAVE == 4)
 * - decrypt_block4x	- decrypt 4 blocks in parallel (if INTERLEAVE == 4)
 */

#if defined(INTERLEAVE) && !defined(INTERLEAVE_INLINE)
#define FRAME_PUSH	stp x29, x30, [sp,#-16]! ; mov x29, sp
#define FRAME_POP	ldp x29, x30, [sp],#16

#if INTERLEAVE == 2

LOCAL_FUNC aes_encrypt_block2x , :
	encrypt_block2x	v0, v1, w3, x2, x6, w7
	ret
END_FUNC aes_encrypt_block2x

LOCAL_FUNC aes_decrypt_block2x , :
	decrypt_block2x	v0, v1, w3, x2, x6, w7
	ret
END_FUNC aes_decrypt_block2x

#elif INTERLEAVE == 4

LOCAL_FUNC aes_encrypt_block4x , :
	encrypt_block4x	v0, v1, v2, v3, w3, x2, x6, w7
	ret
END_FUNC aes_encrypt_block4x

LOCAL_FUNC aes_decrypt_block4x , :
	decrypt_block4x	v0, v1, v2, v3, w3, x2, x6, w7
	ret
END_FUNC aes_decrypt_block4x

#else
#error INTERLEAVE should equal 2 or 4
#endif

	.macro		do_encrypt_block2x
	bl		aes_encrypt_block2x
	.endm

	.macro		do_decrypt_block2x
	bl		aes_decrypt_block2x
	.endm

	.macro		do_encrypt_block4x
	bl		aes_encrypt_block4x
	.endm

	.macro		do_decrypt_block4x
	bl		aes_decrypt_block4x
	.endm

#else
#define FRAME_PUSH
#define FRAME_POP

	.macro		do_encrypt_block2x
	encrypt_block2x	v0, v1, w3, x2, x6, w7
	.endm

	.macro		do_decrypt_block2x
	decrypt_block2x	v0, v1, w3, x2, x6, w7
	.endm

	.macro		do_encrypt_block4x
	encrypt_block4x	v0, v1, v2, v3, w3, x2, x6, w7
	.endm

	.macro		do_decrypt_block4x
	decrypt_block4x	v0, v1, v2, v3, w3, x2, x6, w7
	.endm

#endif

	/*
	 * uint32_t ce_aes_sub(uint32_t in) - use the aese instruction to
	 * perform the AES sbox substitution on each byte in 'input'
	 */
FUNC ce_aes_sub , :
	dup		v1.4s, w0
	movi		v0.16b, #0
	aese		v0.16b, v1.16b
	umov		w0, v0.s[0]
	ret
END_FUNC ce_aes_sub

	/*
	 * void ce_aes_invert(void *dst, const void *src);
	 */
FUNC ce_aes_invert , :
	ld1		{v0.16b}, [x1]
	aesimc		v1.16b, v0.16b
	st1		{v1.16b}, [x0]
	ret
END_FUNC ce_aes_invert

	/*
	 * ce_aes_ecb_encrypt(u8 out[], u8 const in[], u8 const rk[],
	 *                    int rounds, int blocks, int first)
	 */
FUNC ce_aes_ecb_encrypt , :
	FRAME_PUSH
	cbz		w5, .LecbencloopNx

	enc_prepare	w3, x2, x5

.LecbencloopNx:
#if INTERLEAVE >= 2
	subs		w4, w4, #INTERLEAVE
	bmi		.Lecbenc1x
#if INTERLEAVE == 2
	ld1		{v0.16b-v1.16b}, [x1], #32	/* get 2 pt blocks */
	do_encrypt_block2x
	st1		{v0.16b-v1.16b}, [x0], #32
#else
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 pt blocks */
	do_encrypt_block4x
	st1		{v0.16b-v3.16b}, [x0], #64
#endif
	b		.LecbencloopNx
.Lecbenc1x:
	adds		w4, w4, #INTERLEAVE
	beq		.Lecbencout
#endif
.Lecbencloop:
	ld1		{v0.16b}, [x1], #16		/* get next pt block */
	encrypt_block	v0, w3, x2, x5, w6
	st1		{v0.16b}, [x0], #16
	subs		w4, w4, #1
	bne		.Lecbencloop
.Lecbencout:
	FRAME_POP
	ret
END_FUNC ce_aes_ecb_encrypt

	/*
	 * ce_aes_ecb_decrypt(u8 out[], u8 const in[], u8 const rk[],
	 *                    int rounds, int blocks, int first)
	 */
FUNC ce_aes_ecb_decrypt , :
	FRAME_PUSH
	cbz		w5, .LecbdecloopNx

	dec_prepare	w3, x2, x5

.LecbdecloopNx:
#if INTERLEAVE >= 2
	subs		w4, w4, #INTERLEAVE
	bmi		.Lecbdec1x
#if INTERLEAVE == 2
	ld1		{v0.16b-v1.16b}, [x1], #32	/* get 2 ct blocks */
	do_decrypt_block2x
	st1		{v0.16b-v1.16b}, [x0], #32
#else
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 ct blocks */
	do_decrypt_block4x
	st1		{v0.16b-v3.16b}, [x0], #64
#endif
	b		.LecbdecloopNx
.Lecbdec1x:
	adds		w4, w4, #INTERLEAVE
	beq		.Lecbdecout
#endif
.Lecbdecloop:
	ld1		{v0.16b}, [x1], #16		/* get next ct block */
	decrypt_block	v0, w3, x2, x5, w6
	st1		{v0.16b}, [x0], #16
	subs		w4, w4, #1
	bne		.Lecbdecloop
.Lecbdecout:
	FRAME_POP
	ret
END_FUNC ce_aes_ecb_decrypt

	/*
	 * void ce_aes_cbc_encrypt(uint8_t out[], uint8_t const in[],
	 *			   uint8_t const rk[], int rounds, int blocks,
	 *			   uint8_t iv[])
	 */
FUNC ce_aes_cbc_encrypt , :
	ld1		{v4.16b}, [x5]			/* get iv */
	enc_prepare	w3, x2, x6

.Lcbcencloop4x:
	subs		w4, w4, #4
	bmi		.Lcbcenc1x
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 pt blocks */
	eor		v0.16b, v0.16b, v4.16b		/* ..and xor with iv */
	encrypt_block	v0, w3, x2, x6, w7
	eor		v1.16b, v1.16b, v0.16b
	encrypt_block	v1, w3, x2, x6, w7
	eor		v2.16b, v2.16b, v1.16b
	encrypt_block	v2, w3, x2, x6, w7
	eor		v3.16b, v3.16b, v2.16b
	encrypt_block	v3, w3, x2, x6, w7
	st1		{v0.16b-v3.16b}, [x0], #64
	mov		v4.16b, v3.16b
	b		.Lcbcencloop4x
.Lcbcenc1x:
	adds		w4, w4, #4
	beq		.Lcbcencout
.Lcbcencloop:
	ld1		{v0.16b}, [x1], #16		/* get next pt block */
	eor		v4.16b, v4.16b, v0.16b		/* ..and xor with iv */
	encrypt_block	v4, w3, x2, x6, w7
	st1		{v4.16b}, [x0], #16
	subs		w4, w4, #1
	bne		.Lcbcencloop
.Lcbcencout:
	st1		{v4.16b}, [x5]			/* return iv */
	ret
END_FUNC ce_aes_cbc_encrypt

	/*
	 * void ce_aes_cbc_decrypt(uint8_t out[], uint8_t const in[],
	 *			   uint8_t const rk[], int rounds, int blocks,
	 *			   uint8_t iv[])
	 */
FUNC ce_aes_cbc_decrypt , :
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp

	ld1		{v7.16b}, [x5]			/* get iv */
	dec_prepare	w3, x2, x6

.LcbcdecloopNx:
	subs		w4, w4, #4
	bmi		.Lcbcdec1x
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 ct blocks */
	mov		v4.16b, v0.16b
	mov		v5.16b, v1.16b
	mov		v6.16b, v2.16b
	bl		aes_decrypt_block4x
	sub		x1, x1, #16
	eor		v0.16b, v0.16b, v7.16b
	eor		v1.16b, v1.16b, v4.16b
	ld1		{v7.16b}, [x1], #16		/* reload 1 ct block */
	eor		v2.16b, v2.16b, v5.16b
	eor		v3.16b, v3.16b, v6.16b
	st1		{v0.16b-v3.16b}, [x0], #64
	b		.LcbcdecloopNx
.Lcbcdec1x:
	adds		w4, w4, #4
	beq		.Lcbcdecout
.Lcbcdecloop:
	ld1		{v1.16b}, [x1], #16		/* get next ct block */
	mov		v0.16b, v1.16b			/* ...and copy to v0 */
	decrypt_block	v0, w3, x2, x6, w7
	eor		v0.16b, v0.16b, v7.16b		/* xor with iv => pt */
	mov		v7.16b, v1.16b			/* ct is next iv */
	st1		{v0.16b}, [x0], #16
	subs		w4, w4, #1
	bne		.Lcbcdecloop
.Lcbcdecout:
	st1		{v7.16b}, [x5]			/* return iv */
	ldp		x29, x30, [sp], #16
	ret
END_FUNC ce_aes_cbc_decrypt


	/*
	 * void ce_aes_ctr_encrypt(uint8_t out[], uint8_t const in[],
	 *			   uint8_t const rk[], int rounds, int blocks,
	 *			   uint8_t ctr[], int first)
	 */
FUNC ce_aes_ctr_encrypt , :
	stp             x29, x30, [sp, #-16]!
	mov             x29, sp

	enc_prepare     w3, x2, x6
	ld1             {v4.16b}, [x5]

	umov            x6, v4.d[1]             /* keep swabbed ctr in reg */
	rev             x6, x6
	cmn             w6, w4                  /* 32 bit overflow? */
	bcs             .Lctrloop
.LctrloopNx:
	subs            w4, w4, #4
	bmi             .Lctr1x
	add		w7, w6, #1
	mov             v0.16b, v4.16b
	add		w8, w6, #2
	mov             v1.16b, v4.16b
	add		w9, w6, #3
	mov             v2.16b, v4.16b
	rev		w7, w7
	mov             v3.16b, v4.16b
	rev		w8, w8
	mov		v1.s[3], w7
	rev		w9, w9
	mov		v2.s[3], w8
	mov		v3.s[3], w9
	ld1             {v5.16b-v7.16b}, [x1], #48      /* get 3 input blocks */
	bl              aes_encrypt_block4x
	eor             v0.16b, v5.16b, v0.16b
	ld1             {v5.16b}, [x1], #16             /* get 1 input block  */
	eor             v1.16b, v6.16b, v1.16b
	eor             v2.16b, v7.16b, v2.16b
	eor             v3.16b, v5.16b, v3.16b
	st1             {v0.16b-v3.16b}, [x0], #64
	add             x6, x6, #4
	rev             x7, x6
	ins             v4.d[1], x7
	cbz             w4, .Lctrout
	b               .LctrloopNx
.Lctr1x:
	adds            w4, w4, #4
	beq             .Lctrout
.Lctrloop:
	mov             v0.16b, v4.16b
	encrypt_block   v0, w3, x2, x8, w7

	adds            x6, x6, #1              /* increment BE ctr */
	rev             x7, x6
	ins             v4.d[1], x7
	bcs             .Lctrcarry              /* overflow? */

.Lctrcarrydone:
	subs            w4, w4, #1
	bmi             .Lctrtailblock          /* blocks <0 means tail block */
	ld1             {v3.16b}, [x1], #16
	eor             v3.16b, v0.16b, v3.16b
	st1             {v3.16b}, [x0], #16
	bne             .Lctrloop

.Lctrout:
	st1             {v4.16b}, [x5]          /* return next CTR value */
	ldp             x29, x30, [sp], #16
	ret

.Lctrtailblock:
	st1             {v0.16b}, [x0]
	ldp             x29, x30, [sp], #16
	ret

.Lctrcarry:
	umov            x7, v4.d[0]             /* load upper word of ctr  */
	rev             x7, x7                  /* ... to handle the carry */
	add             x7, x7, #1
	rev             x7, x7
	ins             v4.d[0], x7
	b               .Lctrcarrydone
END_FUNC ce_aes_ctr_encrypt


	.macro		next_tweak, out, in, const, tmp
	sshr		\tmp\().2d,  \in\().2d,   #63
	and		\tmp\().16b, \tmp\().16b, \const\().16b
	add		\out\().2d,  \in\().2d,   \in\().2d
	ext		\tmp\().16b, \tmp\().16b, \tmp\().16b, #8
	eor		\out\().16b, \out\().16b, \tmp\().16b
	.endm

	/*
	 * void ce_aes_xts_encrypt(uint8_t out[], uint8_t const in[],
	 *			   uint8_t const rk1[], int rounds, int blocks,
	 *			   uint8_t const rk2[], uint8_t iv[])
	 */
FUNC ce_aes_xts_encrypt , :
	FRAME_PUSH

	ld1		{v4.16b}, [x6]
	enc_prepare	w3, x5, x6
	encrypt_block	v4, w3, x5, x6, w7		/* first tweak */
	enc_switch_key	w3, x2, x6
	ldr		q7, .Lxts_mul_x
	b		.LxtsencNx

.LxtsencloopNx:
	ldr		q7, .Lxts_mul_x
	next_tweak	v4, v4, v7, v8
.LxtsencNx:
#if INTERLEAVE >= 2
	subs		w4, w4, #INTERLEAVE
	bmi		.Lxtsenc1x
#if INTERLEAVE == 2
	ld1		{v0.16b-v1.16b}, [x1], #32	/* get 2 pt blocks */
	next_tweak	v5, v4, v7, v8
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	do_encrypt_block2x
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	st1		{v0.16b-v1.16b}, [x0], #32
	cbz		w4, .LxtsencoutNx
	next_tweak	v4, v5, v7, v8
	b		.LxtsencNx
.LxtsencoutNx:
	mov		v4.16b, v5.16b
	b		.Lxtsencout
#else
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 pt blocks */
	next_tweak	v5, v4, v7, v8
	eor		v0.16b, v0.16b, v4.16b
	next_tweak	v6, v5, v7, v8
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	next_tweak	v7, v6, v7, v8
	eor		v3.16b, v3.16b, v7.16b
	do_encrypt_block4x
	eor		v3.16b, v3.16b, v7.16b
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	st1		{v0.16b-v3.16b}, [x0], #64
	mov		v4.16b, v7.16b
	cbz		w4, .Lxtsencout
	b		.LxtsencloopNx
#endif
.Lxtsenc1x:
	adds		w4, w4, #INTERLEAVE
	beq		.Lxtsencout
#endif
.Lxtsencloop:
	ld1		{v1.16b}, [x1], #16
	eor		v0.16b, v1.16b, v4.16b
	encrypt_block	v0, w3, x2, x6, w7
	eor		v0.16b, v0.16b, v4.16b
	st1		{v0.16b}, [x0], #16
	subs		w4, w4, #1
	beq		.Lxtsencout
	next_tweak	v4, v4, v7, v8
	b		.Lxtsencloop
.Lxtsencout:
	next_tweak	v4, v4, v7, v8
	st1		{v4.16b}, [x6], #16
	FRAME_POP
	ret

	.align		4
.Lxts_mul_x:
	.word		1, 0, 0x87, 0
END_FUNC ce_aes_xts_encrypt

	/*
	 * void ce_aes_xts_decrypt(uint8_t out[], uint8_t const in[],
	 *			   uint8_t const rk1[], int rounds, int blocks,
	 *			   uint8_t const rk2[], uint8_t iv[])
	 */
FUNC ce_aes_xts_decrypt , :
	FRAME_PUSH

	ld1		{v4.16b}, [x6]
	enc_prepare	w3, x5, x6
	encrypt_block	v4, w3, x5, x6, w7		/* first tweak */
	dec_prepare	w3, x2, x6
	ldr		q7, .Lxts_mul_x
	b		.LxtsdecNx

.LxtsdecloopNx:
	ldr		q7, .Lxts_mul_x
	next_tweak	v4, v4, v7, v8
.LxtsdecNx:
#if INTERLEAVE >= 2
	subs		w4, w4, #INTERLEAVE
	bmi		.Lxtsdec1x
#if INTERLEAVE == 2
	ld1		{v0.16b-v1.16b}, [x1], #32	/* get 2 ct blocks */
	next_tweak	v5, v4, v7, v8
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	do_decrypt_block2x
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	st1		{v0.16b-v1.16b}, [x0], #32
	cbz		w4, .LxtsdecoutNx
	next_tweak	v4, v5, v7, v8
	b		.LxtsdecNx
.LxtsdecoutNx:
	mov		v4.16b, v5.16b
	b		.Lxtsdecout
#else
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 ct blocks */
	next_tweak	v5, v4, v7, v8
	eor		v0.16b, v0.16b, v4.16b
	next_tweak	v6, v5, v7, v8
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	next_tweak	v7, v6, v7, v8
	eor		v3.16b, v3.16b, v7.16b
	do_decrypt_block4x
	eor		v3.16b, v3.16b, v7.16b
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	st1		{v0.16b-v3.16b}, [x0], #64
	mov		v4.16b, v7.16b
	cbz		w4, .Lxtsdecout
	b		.LxtsdecloopNx
#endif
.Lxtsdec1x:
	adds		w4, w4, #INTERLEAVE
	beq		.Lxtsdecout
#endif
.Lxtsdecloop:
	ld1		{v1.16b}, [x1], #16
	eor		v0.16b, v1.16b, v4.16b
	decrypt_block	v0, w3, x2, x6, w7
	eor		v0.16b, v0.16b, v4.16b
	st1		{v0.16b}, [x0], #16
	subs		w4, w4, #1
	beq		.Lxtsdecout
	next_tweak	v4, v4, v7, v8
	b		.Lxtsdecloop
.Lxtsdecout:
	FRAME_POP
	next_tweak	v4, v4, v7, v8
	st1		{v4.16b}, [x6], #16
	ret
END_FUNC ce_aes_xts_decrypt

	/*
	 * void ce_aes_xor_block(uint8_t out[], uint8_t const op1[],
	 *			 uint8_t const op2[]);
	 */
FUNC ce_aes_xor_block , :
	ld1	{v0.16b}, [x1]
	ld1	{v1.16b}, [x2]
	eor	v0.16b, v0.16b, v1.16b
	st1	{v0.16b}, [x0]
	ret
END_FUNC ce_aes_xor_block
