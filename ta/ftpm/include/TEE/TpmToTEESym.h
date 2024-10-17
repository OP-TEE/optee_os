/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Siemens AG
 * All rights reserved.
 * Copyright (c) 2024, Linaro Limited
 *
 * Based on the original code by Microsoft. Modified to support using
 * TEE functions to provide cryptographic functionality.
 *
 * Portions Copyright Microsoft Corporation, see below for details:
 *
 * The copyright in this software is being made available under the BSD
 * License, included below. This software may be subject to other third
 * party and contributor rights, including patent rights, and no such
 * rights are granted under this license.
 *
 * Copyright (c) 2018 Microsoft Corporation
 *
 * All rights reserved.
 *
 * BSD License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This header file is used to 'splice' the TEE sym code into the TPM code.
 */

#ifndef SYM_LIB_DEFINED
#define SYM_LIB_DEFINED

#define SYM_LIB_TEE

#define SYM_ALIGNMENT RADIX_BYTES

#include <tee_internal_api.h>
#include <stdint.h>

/*
 * The TEE does not export a key schedule, so these structs do not not
 * really represent a key schedule but rather a copy of the key.
 */
typedef struct {
	uint16_t keySizeInBytes;
	uint8_t key[32];
} tpmKeyScheduleAES;

typedef struct {
	uint16_t keySizeInBytes;
	uint8_t key[24];
} tpmKeyScheduleTDES;

typedef struct {
	uint16_t keySizeInBytes;
	uint8_t key[16];
} tpmKeyScheduleSM4;

int TEE_SetKeyAES(tpmKeyScheduleAES *key_schedule, const uint8_t *key,
		  uint16_t keySizeInBytes);
int TEE_SetKeyTDES(tpmKeyScheduleTDES *key_schedule, const uint8_t *key,
		   uint16_t keySizeInBytes);
int TEE_SetKeySM4(tpmKeyScheduleSM4 *key_schedule, const uint8_t *key,
		  uint16_t keySizeInBytes);

void TEE_AESEncrypt(uint8_t *out, const tpmKeyScheduleAES *key_schedule,
		    const uint8_t *in);
void TEE_AESDecrypt(uint8_t *out, const tpmKeyScheduleAES *key_schedule,
		    const uint8_t *in);
void TEE_TDESEncrypt(uint8_t *out, const tpmKeyScheduleTDES *key_schedule,
		     const uint8_t *in);
void TEE_TDESDecrypt(uint8_t *out, const tpmKeyScheduleTDES *key_schedule,
		     const uint8_t *in);
void TEE_SM4Encrypt(uint8_t *out, const tpmKeyScheduleSM4 *key_schedule,
		    const uint8_t *in);
void TEE_SM4Decrypt(uint8_t *out, const tpmKeyScheduleSM4 *key_schedule,
		    const uint8_t *in);

/*
 * Links to the TEE sym code
 */

#if ALG_CAMELLIA
#  undef ALG_CAMELLIA
#  define ALG_CAMELLIA ALG_NO
#endif

/*
 * Define the order of parameters to the library functions that do block
 * encryption and decryption.
 */
typedef void (*TpmCryptSetSymKeyCall_t)(void* keySchedule, BYTE* out, const BYTE* in);

/*
 * The Crypt functions that call the block encryption function use the
 * parameters in the order:
 *  1) keySchedule
 *  2) in buffer
 *  3) out buffer
 * Since the functions TEE_Encrypt* uses a different order, we need to
 * swizzle the values to the order required by the library.
 */
#define SWIZZLE(keySchedule, in, out) \
	(BYTE *)(out), (void *)(keySchedule), (const BYTE *)(in)

/*
 * Macros to set up the encryption/decryption key schedules
 */
/* AES */
#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule) \
	TEE_SetKeyAES((tpmKeyScheduleAES *)(schedule), key,    \
		      BITS_TO_BYTES(keySizeInBits))
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule) \
	TEE_SetKeyAES((tpmKeyScheduleAES *)(schedule), key,    \
		      BITS_TO_BYTES(keySizeInBits))

/* TDES */
#define TpmCryptSetEncryptKeyTDES(key, keySizeInBits, schedule) \
	TEE_SetKeyTDES((tpmKeyScheduleTDES *)(schedule), (key), \
		       BITS_TO_BYTES(keySizeInBits))
#define TpmCryptSetDecryptKeyTDES(key, keySizeInBits, schedule) \
	TEE_SetKeyTDES((tpmKeyScheduleTDES *)(schedule), (key), \
		       BITS_TO_BYTES(keySizeInBits))

/* SM4 */
#define TpmCryptSetEncryptKeySM4(key, keySizeInBits, schedule) \
	TEE_SetKeySM4((tpmKeyScheduleSM4 *)(schedule), (key),  \
		      BITS_TO_BYTES(keySizeInBits))
#define TpmCryptSetDecryptKeySM4(key, keySizeInBits, schedule) \
	TEE_SetKeySM4((tpmKeyScheduleSM4 *)(schedule), (key),  \
		      BITS_TO_BYTES(keySizeInBits))
/*
 * Macros to alias encryption calls to specific algorithms. This should be
 * used sparingly. Currently, only used by CryptRand.c
 *
 * When using these calls, to call the AES block encryption code, the
 * caller should use:
 *      TpmCryptEncryptAES(SWIZZLE(keySchedule, in, out));
 */
#define TpmCryptEncryptAES TEE_AESEncrypt
#define TpmCryptDecryptAES TEE_AESDecrypt

#define TpmCryptEncryptTDES TEE_TDESEncrypt
#define TpmCryptDecryptTDES TEE_TDESDecrypt

#define TpmCryptEncryptSM4 TEE_SM4Encrypt
#define TpmCryptDecryptSM4 TEE_SM4Decrypt

typedef union tpmCryptKeySchedule_t tpmCryptKeySchedule_t;

/* This definition would change if there were something to report */
#define SymLibSimulationEnd()

#endif /*SYM_LIB_DEFINED*/
