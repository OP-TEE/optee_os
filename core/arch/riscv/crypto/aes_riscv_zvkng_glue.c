// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <assert.h>
#include <stdbool.h>
#include "aes_riscv_zvkng.h"
#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <string.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#define AES_EXPANDED_KEY_SIZE	(15 * TEE_AES_BLOCK_SIZE)

/*
 * LibTomCrypt stores the encryption and decryption schedules separately, so
 * the mode wrappers build the Linux vector AES ABI adapter on the stack.
 */

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
	uint8_t product = 0;

	while (b) {
		if (b & 1)
			product ^= a;
		a = (a << 1) ^ ((a >> 7) * 0x1b);
		b >>= 1;
	}

	return product;
}

static uint8_t aes_sbox(uint8_t x)
{
	uint8_t inverse = 1;
	uint8_t power = x;
	uint8_t result = 0;
	unsigned int i = 0;

	if (!x)
		return 0x63;

	/* x^-1 = x^254 in GF(2^8). */
	for (i = 0; i < 8; i++) {
		if ((254 >> i) & 1)
			inverse = gf_mul(inverse, power);
		power = gf_mul(power, power);
	}

	for (i = 0; i < 8; i++)
		result ^= (((inverse >> i) ^ (inverse >> ((i + 4) & 7)) ^
			    (inverse >> ((i + 5) & 7)) ^
			    (inverse >> ((i + 6) & 7)) ^
			    (inverse >> ((i + 7) & 7))) & 1) << i;

	return result ^ 0x63;
}

static uint32_t subword(uint32_t word)
{
	uint32_t result = 0;
	unsigned int i = 0;

	for (i = 0; i < sizeof(word); i++)
		result |= (uint32_t)aes_sbox(word >> (i * 8)) << (i * 8);

	return result;
}

static uint32_t ror32(uint32_t value, unsigned int shift)
{
	return (value >> shift) | (value << (32 - shift));
}

static void expand_enc_key(uint32_t *enc_key, size_t key_len)
{
	static const uint8_t rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	};
	unsigned int key_words = key_len / sizeof(*enc_key);
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(rcon); i++) {
		uint32_t *input = enc_key + i * key_words;
		uint32_t *output = input + key_words;

		output[0] = ror32(subword(input[key_words - 1]), 8) ^
			    rcon[i] ^ input[0];
		output[1] = output[0] ^ input[1];
		output[2] = output[1] ^ input[2];
		output[3] = output[2] ^ input[3];

		if (key_len == 24) {
			if (i >= 7)
				break;
			output[4] = output[3] ^ input[4];
			output[5] = output[4] ^ input[5];
		} else if (key_len == 32) {
			if (i >= 6)
				break;
			output[4] = subword(output[3]) ^ input[4];
			output[5] = output[4] ^ input[5];
			output[6] = output[5] ^ input[6];
			output[7] = output[6] ^ input[7];
		}
	}
}

TEE_Result crypto_accel_aes_expand_keys(const void *key, size_t key_len,
					void *enc_key, void *dec_key,
					size_t expanded_key_len,
					unsigned int *round_count)
{
	unsigned int rounds = 0;

	if (!key || !enc_key || !round_count)
		return TEE_ERROR_BAD_PARAMETERS;
	if (key_len != 16 && key_len != 24 && key_len != 32)
		return TEE_ERROR_BAD_PARAMETERS;
	if (expanded_key_len < AES_EXPANDED_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	rounds = 10 + ((key_len / 8) - 2) * 2;
	memset(enc_key, 0, expanded_key_len);
	memcpy(enc_key, key, key_len);
	expand_enc_key(enc_key, key_len);
	if (dec_key)
		memcpy(dec_key, enc_key, expanded_key_len);
	*round_count = rounds;

	return TEE_SUCCESS;
}

static unsigned int key_len_from_round_count(unsigned int round_count)
{
	switch (round_count) {
	case 10:
		return 16;
	case 12:
		return 24;
	case 14:
		return 32;
	default:
		return 0;
	}
}

static void make_linux_key(struct riscv_aes_key *dst, const void *src,
			   unsigned int round_count)
{
	memset(dst, 0, sizeof(*dst));
	memcpy(dst->enc_key, src, sizeof(dst->enc_key));
	dst->key_len = key_len_from_round_count(round_count);
}

static void aes_xts_crypt(void *out, const void *in, const void *key1,
			  unsigned int round_count, unsigned int block_count,
			  const void *key2, void *tweak, bool decrypt)
{
	struct riscv_aes_key data_key = { };
	struct riscv_aes_key tweak_key = { };
	const struct riscv_aes_key *key = &data_key;
	size_t len = block_count * TEE_AES_BLOCK_SIZE;
	uint32_t vfp_state = 0;

	assert(out && in && key1 && key2 && tweak);
	assert(block_count);
	make_linux_key(&data_key, key1, round_count);
	make_linux_key(&tweak_key, key2, round_count);
	assert(data_key.key_len);

	vfp_state = thread_kernel_enable_vfp();
	aes_ecb_encrypt_zvkned(&tweak_key, tweak, tweak, TEE_AES_BLOCK_SIZE);
	if (decrypt)
		aes_xts_decrypt_zvkned_zvbb_zvkg(key, in, out, len, tweak);
	else
		aes_xts_encrypt_zvkned_zvbb_zvkg(key, in, out, len, tweak);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_aes_xts_enc(void *out, const void *in, const void *key1,
			      unsigned int round_count,
			      unsigned int block_count,
			      const void *key2, void *tweak)
{
	aes_xts_crypt(out, in, key1, round_count, block_count, key2, tweak,
		      false);
}

void crypto_accel_aes_xts_dec(void *out, const void *in, const void *key1,
			      unsigned int round_count,
			      unsigned int block_count,
			      const void *key2, void *tweak)
{
	aes_xts_crypt(out, in, key1, round_count, block_count, key2, tweak,
		      true);
}
