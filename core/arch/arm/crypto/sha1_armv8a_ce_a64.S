/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2020, Linaro Limited
 * Copyright (C) 2014 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

 /* SHA-1 secure hash using ARMv8 Crypto Extensions */

#include <asm.S>

	.arch		armv8-a+crypto

	k0		.req	v0
	k1		.req	v1
	k2		.req	v2
	k3		.req	v3

	t0		.req	v4
	t1		.req	v5

	dga		.req	q6
	dgav		.req	v6
	dgb		.req	s7
	dgbv		.req	v7

	dg0q		.req	q12
	dg0s		.req	s12
	dg0v		.req	v12
	dg1s		.req	s13
	dg1v		.req	v13
	dg2s		.req	s14

	.macro		add_only, op, ev, rc, s0, dg1
	.ifc		\ev, ev
	add		t1.4s, v\s0\().4s, \rc\().4s
	sha1h		dg2s, dg0s
	.ifnb		\dg1
	sha1\op		dg0q, \dg1, t0.4s
	.else
	sha1\op		dg0q, dg1s, t0.4s
	.endif
	.else
	.ifnb		\s0
	add		t0.4s, v\s0\().4s, \rc\().4s
	.endif
	sha1h		dg1s, dg0s
	sha1\op		dg0q, dg2s, t1.4s
	.endif
	.endm

	.macro		add_update, op, ev, rc, s0, s1, s2, s3, dg1
	sha1su0		v\s0\().4s, v\s1\().4s, v\s2\().4s
	add_only	\op, \ev, \rc, \s1, \dg1
	sha1su1		v\s0\().4s, v\s3\().4s
	.endm

	/*
	 * void sha1_ce_transform(u32 state[5], u8 const *src, int blocks)
	 */
FUNC sha1_ce_transform , :
	/* load round constants */
	adr		x6, .Lsha1_rcon
	ld1r		{k0.4s}, [x6], #4
	ld1r		{k1.4s}, [x6], #4
	ld1r		{k2.4s}, [x6], #4
	ld1r		{k3.4s}, [x6]

	/* load state */
	ld1		{dgav.4s}, [x0]
	ldr		dgb, [x0, #16]

	/* load input */
0:	ld1		{v8.16b-v11.16b}, [x1], #64
	sub		w2, w2, #1

	rev32		v8.16b, v8.16b
	rev32		v9.16b, v9.16b
	rev32		v10.16b, v10.16b
	rev32		v11.16b, v11.16b

1:	add		t0.4s, v8.4s, k0.4s
	mov		dg0v.16b, dgav.16b

	add_update	c, ev, k0,  8,  9, 10, 11, dgb
	add_update	c, od, k0,  9, 10, 11,  8
	add_update	c, ev, k0, 10, 11,  8,  9
	add_update	c, od, k0, 11,  8,  9, 10
	add_update	c, ev, k1,  8,  9, 10, 11

	add_update	p, od, k1,  9, 10, 11,  8
	add_update	p, ev, k1, 10, 11,  8,  9
	add_update	p, od, k1, 11,  8,  9, 10
	add_update	p, ev, k1,  8,  9, 10, 11
	add_update	p, od, k2,  9, 10, 11,  8

	add_update	m, ev, k2, 10, 11,  8,  9
	add_update	m, od, k2, 11,  8,  9, 10
	add_update	m, ev, k2,  8,  9, 10, 11
	add_update	m, od, k2,  9, 10, 11,  8
	add_update	m, ev, k3, 10, 11,  8,  9

	add_update	p, od, k3, 11,  8,  9, 10
	add_only	p, ev, k3,  9
	add_only	p, od, k3, 10
	add_only	p, ev, k3, 11
	add_only	p, od

	/* update state */
	add		dgbv.2s, dgbv.2s, dg1v.2s
	add		dgav.4s, dgav.4s, dg0v.4s

	cbnz		w2, 0b

	/* store new state */
3:	st1		{dgav.4s}, [x0]
	str		dgb, [x0, #16]
	ret

	/* The SHA1 round constants */
	.align		4
.Lsha1_rcon:
	.word		0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
END_FUNC sha1_ce_transform

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
