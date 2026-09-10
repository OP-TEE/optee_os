/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

/*
 * Round key load. The schedule is a run of consecutive 16-byte round keys,
 * as produced by crypto_accel_aes_expand_keys(), and is held one key per
 * vector register: v1..v11 for AES-128, v1..v13 for AES-192 and v1..v15
 * for AES-256.
 *
 * The .vs forms of the AES instructions take their round key from element
 * group 0 of vs2 and broadcast it across every element group of vd, so the
 * keys are loaded with vl = 4 and SEW = 32 whatever vl the data is later
 * processed with.
 *
 * rounds selects the schedule length and must be the register holding the
 * round count, which differs between the modes, so every caller passes it
 * explicitly rather than relying on a fixed argument register.
 */
	.macro aes_load_schedule key, rounds, l128, l192
	vsetivli	zero, 4, e32, m1, ta, ma
	vle32.v		v1, (\key)
	addi		t1, \key, 16
	vle32.v		v2, (t1)
	addi		t1, \key, 32
	vle32.v		v3, (t1)
	addi		t1, \key, 48
	vle32.v		v4, (t1)
	addi		t1, \key, 64
	vle32.v		v5, (t1)
	addi		t1, \key, 80
	vle32.v		v6, (t1)
	addi		t1, \key, 96
	vle32.v		v7, (t1)
	addi		t1, \key, 112
	vle32.v		v8, (t1)
	addi		t1, \key, 128
	vle32.v		v9, (t1)
	addi		t1, \key, 144
	vle32.v		v10, (t1)
	addi		t1, \key, 160
	vle32.v		v11, (t1)
	li		t0, 10
	beq		\rounds, t0, \l128
	addi		t1, \key, 176
	vle32.v		v12, (t1)
	addi		t1, \key, 192
	vle32.v		v13, (t1)
	li		t0, 12
	beq		\rounds, t0, \l192
	addi		t1, \key, 208
	vle32.v		v14, (t1)
	addi		t1, \key, 224
	vle32.v		v15, (t1)
	.endm

/*
 * Encrypt the block or blocks held in \data in place. vl and vtype select
 * how many blocks are done at once.
 */
	.macro aes_encrypt data, rounds
	vaesz.vs	\data, v1
	vaesem.vs	\data, v2
	vaesem.vs	\data, v3
	vaesem.vs	\data, v4
	vaesem.vs	\data, v5
	vaesem.vs	\data, v6
	vaesem.vs	\data, v7
	vaesem.vs	\data, v8
	vaesem.vs	\data, v9
	vaesem.vs	\data, v10
	.if \rounds == 10
	vaesef.vs	\data, v11
	.elseif \rounds == 12
	vaesem.vs	\data, v11
	vaesem.vs	\data, v12
	vaesef.vs	\data, v13
	.else
	vaesem.vs	\data, v11
	vaesem.vs	\data, v12
	vaesem.vs	\data, v13
	vaesem.vs	\data, v14
	vaesef.vs	\data, v15
	.endif
	.endm

/*
 * Decrypt in place. Zvkned's decryption rounds apply InvMixColumns after
 * AddRoundKey, so the encryption schedule is reused in reverse order and
 * no separate inverse schedule is needed.
 */
	.macro aes_decrypt data, rounds
	.if \rounds == 10
	vaesz.vs	\data, v11
	.elseif \rounds == 12
	vaesz.vs	\data, v13
	vaesdm.vs	\data, v12
	vaesdm.vs	\data, v11
	.else
	vaesz.vs	\data, v15
	vaesdm.vs	\data, v14
	vaesdm.vs	\data, v13
	vaesdm.vs	\data, v12
	vaesdm.vs	\data, v11
	.endif
	vaesdm.vs	\data, v10
	vaesdm.vs	\data, v9
	vaesdm.vs	\data, v8
	vaesdm.vs	\data, v7
	vaesdm.vs	\data, v6
	vaesdm.vs	\data, v5
	vaesdm.vs	\data, v4
	vaesdm.vs	\data, v3
	vaesdm.vs	\data, v2
	vaesdf.vs	\data, v1
	.endm
