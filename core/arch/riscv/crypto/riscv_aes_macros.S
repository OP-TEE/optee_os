// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026-2026, RISCStar Solutions Limited
 */

/*
 * AES Key load based on key length
 *   - AES-128, keys are loaded into v1-v11.
 *   - AES-192, keys are loaded into v1-v13.
 *   - AES-256, keys are loaded into v1-v15.
 */
/*
 * Load an OP-TEE AES encryption schedule. ROUNDS is 10, 12, or 14 and
 * KEY points at consecutive 16-byte round keys.
 */
.macro aes_begin key, rounds, label128, label192
	vsetivli zero, 4, e32, m1, ta, ma
	vle32.v v1, 0(\key)
	vle32.v v2, 16(\key)
	vle32.v v3, 32(\key)
	vle32.v v4, 48(\key)
	vle32.v v5, 64(\key)
	vle32.v v6, 80(\key)
	vle32.v v7, 96(\key)
	vle32.v v8, 112(\key)
	vle32.v v9, 128(\key)
	vle32.v v10, 144(\key)
	vle32.v v11, 160(\key)
	li t0, 10
	beq \rounds, t0, \label128 // AES-128, goto label128.
	vle32.v v12, 176(\key)
	vle32.v v13, 192(\key)
	li t0, 12
	beq \rounds, t0, \label192 // AES-192, goto label192.
	// it's AES-256
	vle32.v v14, 208(\key)
	vle32.v v15, 224(\key)
.endm

/*
 * AES Encrypt :  data encrypt using riscv zvkned
 *   in : data to be encrypted
 *   in : rounds to be done
 *
 * Note: vl and vtype must already be set and if vl > 4 then multiple blocks
 * are encrypted..
 */
.macro aes_encrypt data, rounds
	vaesz.vs \data, v1
	vaesem.vs \data, v2
	vaesem.vs \data, v3
	vaesem.vs \data, v4
	vaesem.vs \data, v5
	vaesem.vs \data, v6
	vaesem.vs \data, v7
	vaesem.vs \data, v8
	vaesem.vs \data, v9
	vaesem.vs \data, v10
.if \rounds == 10
	vaesef.vs \data, v11
.elseif \rounds == 12
	vaesem.vs \data, v11
	vaesem.vs \data, v12
	vaesef.vs \data, v13
.else
	vaesem.vs \data, v11
	vaesem.vs \data, v12
	vaesem.vs \data, v13
	vaesem.vs \data, v14
	vaesef.vs \data, v15
.endif
.endm

/*
 * AES Decrypt :  data decrypt using riscv zvkned
 */
.macro aes_decrypt data, rounds
.if \rounds == 10
	vaesz.vs \data, v11
.elseif \rounds == 12
	vaesz.vs \data, v13
	vaesdm.vs \data, v12
	vaesdm.vs \data, v11
.else
	vaesz.vs \data, v15
	vaesdm.vs \data, v14
	vaesdm.vs \data, v13
	vaesdm.vs \data, v12
	vaesdm.vs \data, v11
.endif
	vaesdm.vs \data, v10
	vaesdm.vs \data, v9
	vaesdm.vs \data, v8
	vaesdm.vs \data, v7
	vaesdm.vs \data, v6
	vaesdm.vs \data, v5
	vaesdm.vs \data, v4
	vaesdm.vs \data, v3
	vaesdm.vs \data, v2
	vaesdf.vs \data, v1
.endm

