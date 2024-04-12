// SPDX-License-Identifier: BSD-2-Clause
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

#include <compiler.h>
#include <crypto/crypto_accel.h>
#include <tomcrypt_private.h>

#define EXPANDED_AES_KEY_WORD_COUNT	60
#define EXPANDED_AES_KEY_LEN		(EXPANDED_AES_KEY_WORD_COUNT * \
					 sizeof(uint32_t))

int rijndael_setup(const unsigned char *key, int keylen, int num_rounds,
	      symmetric_key *skey)
{
	unsigned int round_count = 0;

	LTC_ARGCHK(key);
	LTC_ARGCHK(skey);

	if (keylen != 16 && keylen != 24 && keylen != 32)
		return CRYPT_INVALID_KEYSIZE;

	skey->rijndael.eK = LTC_ALIGN_BUF(skey->rijndael.K, 16);
	skey->rijndael.dK = skey->rijndael.eK + EXPANDED_AES_KEY_WORD_COUNT;

	if (crypto_accel_aes_expand_keys(key, keylen, skey->rijndael.eK,
					 skey->rijndael.dK,
					 EXPANDED_AES_KEY_LEN,
					 &round_count))
		return CRYPT_INVALID_ARG;

	if (num_rounds && (unsigned int)num_rounds != round_count)
		return CRYPT_INVALID_ROUNDS;

	skey->rijndael.Nr = round_count;

	return CRYPT_OK;
}

void rijndael_done(symmetric_key *skey __unused)
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
				   unsigned long blocks,
				   const symmetric_key *skey)
{
	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(skey);

	crypto_accel_aes_ecb_enc(ct, pt, skey->rijndael.eK, skey->rijndael.Nr,
				 blocks);
	return CRYPT_OK;
}

static int aes_ecb_decrypt_nblocks(const unsigned char *ct, unsigned char *pt,
				   unsigned long blocks,
				   const symmetric_key *skey)
{
	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(skey);

	crypto_accel_aes_ecb_dec(pt, ct, skey->rijndael.dK, skey->rijndael.Nr,
				 blocks);

	return CRYPT_OK;
}

int rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct,
			 const symmetric_key *skey)
{
	return aes_ecb_encrypt_nblocks(pt, ct, 1, skey);
}

int rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt,
			 const symmetric_key *skey)
{
	return aes_ecb_decrypt_nblocks(ct, pt, 1, skey);
}

static int aes_cbc_encrypt_nblocks(const unsigned char *pt, unsigned char *ct,
				   unsigned long blocks, unsigned char *IV,
				   symmetric_key *skey)
{
	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(IV);
	LTC_ARGCHK(skey);

	crypto_accel_aes_cbc_enc(ct, pt, skey->rijndael.eK, skey->rijndael.Nr,
				 blocks, IV);

	return CRYPT_OK;
}

static int aes_cbc_decrypt_nblocks(const unsigned char *ct, unsigned char *pt,
				   unsigned long blocks, unsigned char *IV,
				   symmetric_key *skey)
{
	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(IV);
	LTC_ARGCHK(skey);

	crypto_accel_aes_cbc_dec(pt, ct, skey->rijndael.dK, skey->rijndael.Nr,
				 blocks, IV);

	return CRYPT_OK;
}

static int aes_ctr_encrypt_nblocks(const unsigned char *pt, unsigned char *ct,
				   unsigned long blocks, unsigned char *IV,
				   int mode, symmetric_key *skey)
{
	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(IV);
	LTC_ARGCHK(skey);

	if (mode == CTR_COUNTER_LITTLE_ENDIAN) {
		/* Accelerated algorithm supports big endian only */
		return CRYPT_ERROR;
	}

	crypto_accel_aes_ctr_be_enc(ct, pt, skey->rijndael.eK,
				    skey->rijndael.Nr, blocks, IV);

	return CRYPT_OK;
}

static int aes_xts_encrypt_nblocks(const unsigned char *pt, unsigned char *ct,
				   unsigned long blocks, unsigned char *tweak,
				   const symmetric_key *skey1,
				   const symmetric_key *skey2)
{
	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(tweak);
	LTC_ARGCHK(skey1);
	LTC_ARGCHK(skey2);
	LTC_ARGCHK(skey1->rijndael.Nr == skey2->rijndael.Nr);


	crypto_accel_aes_xts_enc(ct, pt, skey1->rijndael.eK,
				 skey1->rijndael.Nr, blocks,
				 skey2->rijndael.eK, tweak);

	return CRYPT_OK;
}

static int aes_xts_decrypt_nblocks(const unsigned char *ct, unsigned char *pt,
				   unsigned long blocks, unsigned char *tweak,
				   const symmetric_key *skey1,
				   const symmetric_key *skey2)
{
	LTC_ARGCHK(pt);
	LTC_ARGCHK(ct);
	LTC_ARGCHK(tweak);
	LTC_ARGCHK(skey1);
	LTC_ARGCHK(skey2);
	LTC_ARGCHK(skey1->rijndael.Nr == skey2->rijndael.Nr);

	crypto_accel_aes_xts_dec(pt, ct, skey1->rijndael.dK,
				 skey1->rijndael.Nr, blocks,
				 skey2->rijndael.eK, tweak);

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
	.accel_xts_encrypt = aes_xts_encrypt_nblocks,
	.accel_xts_decrypt = aes_xts_decrypt_nblocks,
};
