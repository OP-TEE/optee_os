// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, 2020 Linaro Limited
 * Copyright (C) 2013 Linaro Ltd <ard.biesheuvel@linaro.org>
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
 */

#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <string.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#include "aes_armv8a_ce.h"

struct aes_block {
	uint8_t b[TEE_AES_BLOCK_SIZE];
};

static uint32_t ror32(uint32_t val, unsigned int shift)
{
	return (val >> shift) | (val << (32 - shift));
}

static void expand_enc_key(uint32_t *enc_key, size_t key_len)
{
	/* The AES key schedule round constants */
	static uint8_t const rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	};
	unsigned int kwords = key_len / sizeof(uint32_t);
	unsigned int i = 0;

	for (i = 0; i < sizeof(rcon); i++) {
		uint32_t *rki = enc_key + i * kwords;
		uint32_t *rko = rki + kwords;

		rko[0] = ror32(ce_aes_sub(rki[kwords - 1]), 8) ^
			 rcon[i] ^ rki[0];
		rko[1] = rko[0] ^ rki[1];
		rko[2] = rko[1] ^ rki[2];
		rko[3] = rko[2] ^ rki[3];

		if (key_len == 24) {
			if (i >= 7)
				break;
			rko[4] = rko[3] ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
		} else if (key_len == 32) {
			if (i >= 6)
				break;
			rko[4] = ce_aes_sub(rko[3]) ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
			rko[6] = rko[5] ^ rki[6];
			rko[7] = rko[6] ^ rki[7];
		}
	}
}

static void make_dec_key(unsigned int round_count,
			 const struct aes_block *key_enc,
			 struct aes_block *key_dec)
{
	unsigned int i = 0;
	unsigned int j = round_count;

	/*
	 * Generate the decryption keys for the Equivalent Inverse Cipher.
	 * This involves reversing the order of the round keys, and applying
	 * the Inverse Mix Columns transformation on all but the first and
	 * the last ones.
	 */
	j = round_count;

	key_dec[0] = key_enc[j];
	for (i = 1, j--; j > 0; i++, j--)
		ce_aes_invert(key_dec + i, key_enc + j);
	key_dec[i] = key_enc[0];
}

TEE_Result crypto_accel_aes_expand_keys(const void *key, size_t key_len,
					void *enc_key, void *dec_key,
					size_t expanded_key_len,
					unsigned int *round_count)
{
	unsigned int num_rounds = 0;
	uint32_t vfp_state = 0;

	if (!key || !enc_key)
		return TEE_ERROR_BAD_PARAMETERS;
	if (key_len != 16 && key_len != 24 && key_len != 32)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!IS_ALIGNED_WITH_TYPE(enc_key, struct aes_block) ||
	    !IS_ALIGNED_WITH_TYPE(dec_key, struct aes_block))
		return TEE_ERROR_BAD_PARAMETERS;

	num_rounds = 10 + ((key_len / 8) - 2) * 2;

	if (expanded_key_len < (num_rounds + 1) * sizeof(struct aes_block))
		return TEE_ERROR_BAD_PARAMETERS;

	*round_count = num_rounds;
	memset(enc_key, 0, expanded_key_len);
	memcpy(enc_key, key, key_len);

	vfp_state = thread_kernel_enable_vfp();

	expand_enc_key(enc_key, key_len);
	if (dec_key)
		make_dec_key(num_rounds, enc_key, dec_key);

	thread_kernel_disable_vfp(vfp_state);

	return TEE_SUCCESS;
}

void crypto_accel_aes_ecb_enc(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count)
{
	uint32_t vfp_state = 0;

	assert(out && in && key);

	vfp_state = thread_kernel_enable_vfp();
	ce_aes_ecb_encrypt(out, in, key, round_count, block_count, 1);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_aes_ecb_dec(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count)
{
	uint32_t vfp_state = 0;

	assert(out && in && key);

	vfp_state = thread_kernel_enable_vfp();
	ce_aes_ecb_decrypt(out, in, key, round_count, block_count, 1);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_aes_cbc_enc(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count, void *iv)
{
	uint32_t vfp_state = 0;

	assert(out && in && key && iv);

	vfp_state = thread_kernel_enable_vfp();
	ce_aes_cbc_encrypt(out, in, key, round_count, block_count, iv);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_aes_cbc_dec(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count, void *iv)
{
	uint32_t vfp_state = 0;

	assert(out && in && key && iv);

	vfp_state = thread_kernel_enable_vfp();
	ce_aes_cbc_decrypt(out, in, key, round_count, block_count, iv);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_aes_ctr_be_enc(void *out, const void *in, const void *key,
				 unsigned int round_count,
				 unsigned int block_count, void *iv)
{
	uint32_t vfp_state = 0;

	assert(out && in && key && iv);

	vfp_state = thread_kernel_enable_vfp();
	ce_aes_ctr_encrypt(out, in, key, round_count, block_count, iv, 1);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_aes_xts_enc(void *out, const void *in, const void *key1,
			      unsigned int round_count,
			      unsigned int block_count, const void *key2,
			      void *tweak)
{
	uint32_t vfp_state = 0;

	assert(out && in && key1 && key2 && tweak);

	vfp_state = thread_kernel_enable_vfp();
	ce_aes_xts_encrypt(out, in, key1, round_count, block_count, key2,
			   tweak);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_aes_xts_dec(void *out, const void *in, const void *key1,
			      unsigned int round_count,
			      unsigned int block_count, const void *key2,
			      void *tweak)
{
	uint32_t vfp_state = 0;

	assert(out && in && key1 && key2 && tweak);

	vfp_state = thread_kernel_enable_vfp();
	ce_aes_xts_decrypt(out, in, key1, round_count, block_count, key2,
			   tweak);
	thread_kernel_disable_vfp(vfp_state);
}
