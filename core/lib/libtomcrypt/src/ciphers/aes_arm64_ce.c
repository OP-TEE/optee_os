/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 * Copyright (c) 2001-2007, Tom St Denis
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

/*
 * AES cipher for ARMv8 with Crypto Extensions
 *
 * Copyright (C) 2013 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

#include "tomcrypt.h"
#include "tomcrypt_arm_neon.h"

typedef unsigned int u32;
typedef unsigned char u8;

/* Prototypes for assembly functions */
void ce_aes_ecb_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks, int first);
void ce_aes_ecb_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks, int first);
void ce_aes_cbc_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks, u8 iv[], int first);
void ce_aes_cbc_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks, u8 iv[], int first);
void ce_aes_ctr_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks, u8 ctr[], int first);


struct aes_block {
	u8 b[16];
};

/*
 * aes_sub() - use the aese instruction to perform the AES sbox substitution
 *	     on each byte in 'input'
 */
static u32 aes_sub(u32 input)
{
	u32 ret;

	__asm__("dup    v1.4s, %w[in]		;"
		"movi   v0.16b, #0		;"
		"aese   v0.16b, v1.16b		;"
		"umov   %w[out], v0.4s[0]	;"

	:       [out]   "=r"(ret)
	:       [in]    "r"(input)
	:	       "v0", "v1");
	return ret;
}

static inline u32 ror32(u32 val, u32 shift)
{
	return (val >> shift) | (val << (32 - shift));
}

int rijndael_setup(const unsigned char *key, int keylen, int num_rounds,
	      symmetric_key *skey)
{
	/* The AES key schedule round constants */
	static u8 const rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	};
	u32 kwords = keylen / sizeof(u32);
	struct aes_block *key_enc, *key_dec;
	struct tomcrypt_arm_neon_state state;
	unsigned int i, j;
	void *p;

	LTC_ARGCHK(key);
	LTC_ARGCHK(skey);

	if (keylen != 16 && keylen != 24 && keylen != 32)
		return CRYPT_INVALID_KEYSIZE;

	if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2))
		return CRYPT_INVALID_ROUNDS;

	num_rounds = 10 + ((keylen/8)-2)*2;
	skey->rijndael.Nr = num_rounds;

	memcpy(skey->rijndael.eK, key, keylen);

	tomcrypt_arm_neon_enable(&state);

	for (i = 0; i < sizeof(rcon); i++) {
		u32 *rki;
		u32 *rko;

		p = skey->rijndael.eK;
		rki = (u32 *)p + (i * kwords);
		rko = rki + kwords;

		rko[0] = ror32(aes_sub(rki[kwords - 1]), 8) ^ rcon[i] ^ rki[0];
		rko[1] = rko[0] ^ rki[1];
		rko[2] = rko[1] ^ rki[2];
		rko[3] = rko[2] ^ rki[3];

		if (keylen == 24) {
			if (i >= 7)
				break;
			rko[4] = rko[3] ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
		} else if (keylen == 32) {
			if (i >= 6)
				break;
			rko[4] = aes_sub(rko[3]) ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
			rko[6] = rko[5] ^ rki[6];
			rko[7] = rko[6] ^ rki[7];
		}
	}

	/*
	 * Generate the decryption keys for the Equivalent Inverse Cipher.
	 * This involves reversing the order of the round keys, and applying
	 * the Inverse Mix Columns transformation on all but the first and
	 * the last one.
	 */
	p = skey->rijndael.eK;
	key_enc = (struct aes_block *)p;
	p = skey->rijndael.dK;
	key_dec = (struct aes_block *)p;
	j = num_rounds;

	key_dec[0] = key_enc[j];
	for (i = 1, j--; j > 0; i++, j--)
		__asm__("ld1    {v0.16b}, %[in]		;"
			"aesimc v1.16b, v0.16b		;"
			"st1    {v1.16b}, %[out]	;"

		:       [out]   "=Q"(key_dec[i])
		:       [in]    "Q"(key_enc[j])
		:	       "v0", "v1");
	key_dec[i] = key_enc[0];

	tomcrypt_arm_neon_disable(&state);

	return CRYPT_OK;
}

int rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct,
		    symmetric_key *skey)
{
	struct tomcrypt_arm_neon_state state;
	struct aes_block *out = (struct aes_block *)ct;
	struct aes_block const *in = (struct aes_block *)pt;
	void *dummy0;
	int dummy1;

	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(skey);

	tomcrypt_arm_neon_enable(&state);
	__asm__("	ld1     {v0.16b}, %[in]			;"
		"       ld1     {v1.2d}, [%[key]], #16		;"
		"       cmp     %w[rounds], #10			;"
		"       bmi     0f				;"
		"       bne     3f				;"
		"       mov     v3.16b, v1.16b			;"
		"       b       2f				;"
		"0:     mov     v2.16b, v1.16b			;"
		"       ld1     {v3.2d}, [%[key]], #16		;"
		"1:     aese    v0.16b, v2.16b			;"
		"       aesmc   v0.16b, v0.16b			;"
		"2:     ld1     {v1.2d}, [%[key]], #16		;"
		"       aese    v0.16b, v3.16b			;"
		"       aesmc   v0.16b, v0.16b			;"
		"3:     ld1     {v2.2d}, [%[key]], #16		;"
		"       subs    %w[rounds], %w[rounds], #3	;"
		"       aese    v0.16b, v1.16b			;"
		"       aesmc   v0.16b, v0.16b			;"
		"       ld1     {v3.2d}, [%[key]], #16		;"
		"       bpl     1b				;"
		"       aese    v0.16b, v2.16b			;"
		"       eor     v0.16b, v0.16b, v3.16b		;"
		"       st1     {v0.16b}, %[out]		;"

	:	[out]		"=Q"(*out),
		[key]		"=r"(dummy0),
		[rounds]	"=r"(dummy1)
	:	[in]		"Q"(*in),
				"1"(skey->rijndael.eK),
				"2"(skey->rijndael.Nr - 2)
	:       "cc");
	tomcrypt_arm_neon_disable(&state);

	return CRYPT_OK;
}

int rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt,
		    symmetric_key *skey)
{
	struct tomcrypt_arm_neon_state state;
	struct aes_block *out = (struct aes_block *)pt;
	struct aes_block const *in = (struct aes_block *)ct;
	void *dummy0;
	int dummy1;

	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(skey);

	tomcrypt_arm_neon_enable(&state);
	__asm__("       ld1     {v0.16b}, %[in]			;"
		"       ld1     {v1.2d}, [%[key]], #16		;"
		"       cmp     %w[rounds], #10			;"
		"       bmi     0f				;"
		"       bne     3f				;"
		"       mov     v3.16b, v1.16b			;"
		"       b       2f				;"
		"0:     mov     v2.16b, v1.16b			;"
		"       ld1     {v3.2d}, [%[key]], #16		;"
		"1:     aesd    v0.16b, v2.16b			;"
		"       aesimc  v0.16b, v0.16b			;"
		"2:     ld1     {v1.2d}, [%[key]], #16		;"
		"       aesd    v0.16b, v3.16b			;"
		"       aesimc  v0.16b, v0.16b			;"
		"3:     ld1     {v2.2d}, [%[key]], #16		;"
		"       subs    %w[rounds], %w[rounds], #3	;"
		"       aesd    v0.16b, v1.16b			;"
		"       aesimc  v0.16b, v0.16b			;"
		"       ld1     {v3.2d}, [%[key]], #16		;"
		"       bpl     1b				;"
		"       aesd    v0.16b, v2.16b			;"
		"       eor     v0.16b, v0.16b, v3.16b		;"
		"       st1     {v0.16b}, %[out]		;"

	:	[out]		"=Q"(*out),
		[key]		"=r"(dummy0),
		[rounds]	"=r"(dummy1)
	:	[in]		"Q"(*in),
				"1"(skey->rijndael.dK),
				"2"(skey->rijndael.Nr - 2)
	:       "cc");
	tomcrypt_arm_neon_disable(&state);

	return CRYPT_OK;
}

void rijndael_done(symmetric_key *skey)
{
}

int rijndael_keysize(int *keysize)
{
	LTC_ARGCHK(keysize);

	if (*keysize < 16)
		return CRYPT_INVALID_KEYSIZE;
	else if (*keysize < 24)
		*keysize = 16;
	else if (*keysize < 32)
		*keysize = 24;
	else
		*keysize = 32;

	return CRYPT_OK;
}

static int aes_ecb_encrypt_nblocks(const unsigned char *pt, unsigned char *ct,
				   unsigned long blocks, symmetric_key *skey)
{
	struct tomcrypt_arm_neon_state state;
	u8 *rk;
	int Nr;

	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(skey);

	Nr = skey->rijndael.Nr;
	rk = (u8 *)skey->rijndael.eK;

	tomcrypt_arm_neon_enable(&state);
	ce_aes_ecb_encrypt(ct, pt, rk, Nr, blocks, 1);
	tomcrypt_arm_neon_disable(&state);

	return CRYPT_OK;
}

static int aes_ecb_decrypt_nblocks(const unsigned char *ct, unsigned char *pt,
				   unsigned long blocks, symmetric_key *skey)
{
	struct tomcrypt_arm_neon_state state;
	u8 *rk;
	int Nr;

	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(skey);

	Nr = skey->rijndael.Nr;
	rk = (u8 *)skey->rijndael.dK;

	tomcrypt_arm_neon_enable(&state);
	ce_aes_ecb_decrypt(pt, ct, rk, Nr, blocks, 1);
	tomcrypt_arm_neon_disable(&state);

	return CRYPT_OK;
}

static int aes_cbc_encrypt_nblocks(const unsigned char *pt, unsigned char *ct,
				   unsigned long blocks, unsigned char *IV,
				   symmetric_key *skey)
{
	struct tomcrypt_arm_neon_state state;
	u8 *rk;
	int Nr;

	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(IV);
	LTC_ARGCHK(skey);

	Nr = skey->rijndael.Nr;
	rk = (u8 *)skey->rijndael.eK;

	tomcrypt_arm_neon_enable(&state);
	ce_aes_cbc_encrypt(ct, pt, rk, Nr, blocks, IV, 1);
	tomcrypt_arm_neon_disable(&state);

	return CRYPT_OK;
}

static int aes_cbc_decrypt_nblocks(const unsigned char *ct, unsigned char *pt,
				   unsigned long blocks, unsigned char *IV,
				   symmetric_key *skey)
{
	struct tomcrypt_arm_neon_state state;
	u8 *rk;
	int Nr;

	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(IV);
	LTC_ARGCHK(skey);

	Nr = skey->rijndael.Nr;
	rk = (u8 *)skey->rijndael.dK;

	tomcrypt_arm_neon_enable(&state);
	ce_aes_cbc_decrypt(pt, ct, rk, Nr, blocks, IV, 1);
	tomcrypt_arm_neon_disable(&state);

	return CRYPT_OK;
}

/* Increment 128-bit counter */
static void increment_ctr(unsigned char *val)
{
	int i;

	for (i = 15; i >= 0; i--) {
		val[i] = (val[i] + 1) & 0xff;
		if (val[i])
			break;
	}
}

static int aes_ctr_encrypt_nblocks(const unsigned char *pt, unsigned char *ct,
				   unsigned long blocks, unsigned char *IV,
				   int mode, symmetric_key *skey)
{
	struct tomcrypt_arm_neon_state state;
	u8 *rk;
	int Nr;

	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(IV);
	LTC_ARGCHK(skey);

	if (mode == CTR_COUNTER_LITTLE_ENDIAN) {
		/* Accelerated algorithm supports big endian only */
		return CRYPT_ERROR;
	}

	Nr = skey->rijndael.Nr;
	rk = (u8 *)skey->rijndael.eK;

	increment_ctr(IV);
	tomcrypt_arm_neon_enable(&state);
	ce_aes_ctr_encrypt(ct, pt, rk, Nr, blocks, IV, 1);
	tomcrypt_arm_neon_disable(&state);

	return CRYPT_OK;
}

const struct ltc_cipher_descriptor aes_desc = {
	.name = "aes",
	.ID = 6,
	.min_key_length = 16,
	.max_key_length = 32,
	.block_length = 16,
	.default_rounds = 10,
	.setup = rijndael_setup,
	.ecb_encrypt = rijndael_ecb_encrypt,
	.ecb_decrypt = rijndael_ecb_decrypt,
	.done = rijndael_done,
	.keysize = rijndael_keysize,
	.accel_ecb_encrypt = aes_ecb_encrypt_nblocks,
	.accel_ecb_decrypt = aes_ecb_decrypt_nblocks,
	.accel_cbc_encrypt = aes_cbc_encrypt_nblocks,
	.accel_cbc_decrypt = aes_cbc_decrypt_nblocks,
	.accel_ctr_encrypt = aes_ctr_encrypt_nblocks,
};
