// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <assert.h>
#include <stdbool.h>
#include "aes_rv.h"
#include <crypto/crypto_accel.h>
#include <io.h>
#include <kernel/thread.h>
#include <string.h>
#include <string_ext.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#define AES_EXPANDED_KEY_SIZE	(15 * TEE_AES_BLOCK_SIZE)

/*
 * LibTomCrypt stores the encryption and decryption schedules separately, so
 * the mode wrappers build the Linux vector AES ABI adapter on the stack.
 */

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

		output[0] = ror32(riscv_aes_subword(input[key_words - 1]), 8) ^
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
			output[4] = riscv_aes_subword(output[3]) ^ input[4];
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
	uint32_t schedule[AES_EXPANDED_KEY_SIZE / sizeof(uint32_t)] = { };
	unsigned int rounds = 0;
	uint32_t vfp_state = 0;

	if (!key || !enc_key || !round_count)
		return TEE_ERROR_BAD_PARAMETERS;
	if (key_len != 16 && key_len != 24 && key_len != 32)
		return TEE_ERROR_BAD_PARAMETERS;
	if (expanded_key_len < AES_EXPANDED_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	rounds = 10 + ((key_len / 8) - 2) * 2;
	memcpy(schedule, key, key_len);
	memset(enc_key, 0, expanded_key_len);
	vfp_state = thread_kernel_enable_vfp();
	expand_enc_key(schedule, key_len);
	thread_kernel_disable_vfp(vfp_state);
	memcpy(enc_key, schedule, sizeof(schedule));
	memzero_explicit(schedule, sizeof(schedule));
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

static void init_riscv_aes_key(struct riscv_aes_key *dst, const void *src,
			       unsigned int round_count)
{
	memset(dst, 0, sizeof(*dst));
	memcpy(dst->enc_key, src, sizeof(dst->enc_key));
	dst->key_len = key_len_from_round_count(round_count);
}

typedef void (*aes_block_fn)(const void *key, unsigned int key_len,
			     void *out, const void *in);

static void aes_block_unaligned(aes_block_fn crypt, const void *key,
				unsigned int key_len, void *out, const void *in)
{
	uint32_t schedule[AES_EXPANDED_KEY_SIZE / sizeof(uint32_t)];
	uint32_t block[TEE_AES_BLOCK_SIZE / sizeof(uint32_t)];

	if (!IS_ALIGNED_WITH_TYPE(key, uint32_t)) {
		memcpy(schedule, key, sizeof(schedule));
		key = schedule;
	}
	memcpy(block, in, sizeof(block));
	crypt(key, key_len, block, block);
	memcpy(out, block, sizeof(block));
	memzero_explicit(block, sizeof(block));
	if (key == schedule)
		memzero_explicit(schedule, sizeof(schedule));
}

static void aes_block(aes_block_fn crypt, const void *key,
		      unsigned int key_len, void *out, const void *in)
{
	if (IS_ALIGNED_WITH_TYPE(key, uint32_t) &&
	    IS_ALIGNED_WITH_TYPE(in, uint32_t) &&
	    IS_ALIGNED_WITH_TYPE(out, uint32_t))
		crypt(key, key_len, out, in);
	else
		aes_block_unaligned(crypt, key, key_len, out, in);
}

static void aes_ecb_bulk(void *out, const void *in, const void *key,
			 unsigned int rounds, size_t len, bool decrypt)
{
	struct riscv_aes_key aes_key = { };

	init_riscv_aes_key(&aes_key, key, rounds);
	if (decrypt)
		aes_ecb_decrypt_zvkned(&aes_key, in, out, len);
	else
		aes_ecb_encrypt_zvkned(&aes_key, in, out, len);
	memzero_explicit(&aes_key, sizeof(aes_key));
}

static void aes_ecb_crypt(void *out, const void *in, const void *key,
			  unsigned int rounds, unsigned int block_count,
			  bool decrypt)
{
	aes_block_fn crypt = decrypt ? aes_decrypt_zvkned : aes_encrypt_zvkned;
	unsigned int key_len = key_len_from_round_count(rounds);
	uint32_t state = 0;
	size_t len = (size_t)block_count * TEE_AES_BLOCK_SIZE;
	size_t off = 0;

	assert(out && in && key && key_len && block_count);
	state = thread_kernel_enable_vfp();
	if (block_count > 1 && IS_ALIGNED_WITH_TYPE(in, uint32_t) &&
	    IS_ALIGNED_WITH_TYPE(out, uint32_t)) {
		aes_ecb_bulk(out, in, key, rounds, len, decrypt);
	} else {
		for (off = 0; off < len; off += TEE_AES_BLOCK_SIZE)
			aes_block(crypt, key, key_len, (uint8_t *)out + off,
				  (const uint8_t *)in + off);
	}
	thread_kernel_disable_vfp(state);
}

void crypto_accel_aes_ecb_enc(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count)
{
	aes_ecb_crypt(out, in, key, round_count, block_count, false);
}

void crypto_accel_aes_ecb_dec(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count)
{
	aes_ecb_crypt(out, in, key, round_count, block_count, true);
}

typedef void (*aes_mode_fn)(const struct riscv_aes_key *key, const void *in,
			    void *out, size_t len, void *iv);

static void aes_mode_crypt(aes_mode_fn crypt, const struct riscv_aes_key *key,
			   const void *in, void *out, size_t len, void *iv)
{
	uint32_t chain[TEE_AES_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t block[TEE_AES_BLOCK_SIZE / sizeof(uint32_t)];
	size_t off = 0;

	memcpy(chain, iv, sizeof(chain));
	if (IS_ALIGNED_WITH_TYPE(in, uint32_t) &&
	    IS_ALIGNED_WITH_TYPE(out, uint32_t)) {
		crypt(key, in, out, len, chain);
	} else {
		for (off = 0; off < len; off += sizeof(block)) {
			memcpy(block, (const uint8_t *)in + off, sizeof(block));
			crypt(key, block, block, sizeof(block), chain);
			memcpy((uint8_t *)out + off, block, sizeof(block));
		}
		memzero_explicit(block, sizeof(block));
	}
	memcpy(iv, chain, sizeof(chain));
	memzero_explicit(chain, sizeof(chain));
}

static void aes_cbc_crypt(void *out, const void *in, const void *key,
			  unsigned int round_count, unsigned int block_count,
			  void *iv,
			  bool decrypt)
{
	struct riscv_aes_key aes_key = { };
	uint32_t vfp_state = 0;
	size_t len = block_count * TEE_AES_BLOCK_SIZE;

	assert(out && in && key && iv);
	assert(block_count);
	init_riscv_aes_key(&aes_key, key, round_count);
	assert(aes_key.key_len);

	vfp_state = thread_kernel_enable_vfp();
	aes_mode_crypt(decrypt ? aes_cbc_decrypt_zvkned :
				 aes_cbc_encrypt_zvkned,
		       &aes_key, in, out, len, iv);
	thread_kernel_disable_vfp(vfp_state);
	memzero_explicit(&aes_key, sizeof(aes_key));
}

void crypto_accel_aes_cbc_enc(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count, void *iv)
{
	aes_cbc_crypt(out, in, key, round_count, block_count, iv, false);
}

void crypto_accel_aes_cbc_dec(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count, void *iv)
{
	aes_cbc_crypt(out, in, key, round_count, block_count, iv, true);
}

void crypto_accel_aes_ctr_be_enc(void *out, const void *in, const void *key,
				 unsigned int round_count,
				 unsigned int block_count, void *iv)
{
	struct riscv_aes_key aes_key = { };
	uint8_t counter[TEE_AES_BLOCK_SIZE] __aligned(4);
	uint32_t low = 0;
	uint64_t until_wrap = 0;
	size_t first_len = 0;
	uint32_t vfp_state = 0;
	size_t len = (size_t)block_count * TEE_AES_BLOCK_SIZE;
	int i = 0;

	assert(out && in && key && iv);
	assert(block_count);
	init_riscv_aes_key(&aes_key, key, round_count);
	assert(aes_key.key_len);

	memcpy(counter, iv, sizeof(counter));
	low = get_unaligned_be32(counter + 12);
	until_wrap = (UINT64_C(1) << 32) - low;
	vfp_state = thread_kernel_enable_vfp();
	if ((uint64_t)block_count < until_wrap) {
		aes_ctr32_crypt_zvkned_zvkb(&aes_key, in, out, len, counter);
	} else {
		first_len = (size_t)until_wrap * TEE_AES_BLOCK_SIZE;
		aes_ctr32_crypt_zvkned_zvkb(&aes_key, in, out,
					    first_len, counter);
		/* Carry the low 32-bit wrap into the upper 96 bits. */
		for (i = 11; i >= 0; i--) {
			counter[i]++;
			if (counter[i])
				break;
		}
		if (len > first_len) {
			const uint8_t *next_in = in;
			uint8_t *next_out = out;

			next_in += first_len;
			next_out += first_len;
			aes_ctr32_crypt_zvkned_zvkb(&aes_key, next_in,
						    next_out,
						    len - first_len, counter);
		}
	}
	thread_kernel_disable_vfp(vfp_state);
	memcpy(iv, counter, sizeof(counter));
	memzero_explicit(counter, sizeof(counter));
	memzero_explicit(&aes_key, sizeof(aes_key));
}

static void aes_xts_crypt(void *out, const void *in, const void *key1,
			  unsigned int round_count, unsigned int block_count,
			  const void *key2, void *tweak, bool decrypt)
{
	struct riscv_aes_key data_key = { };
	size_t len = block_count * TEE_AES_BLOCK_SIZE;
	uint32_t vfp_state = 0;

	assert(out && in && key1 && key2 && tweak);
	assert(block_count);
	init_riscv_aes_key(&data_key, key1, round_count);
	assert(data_key.key_len);

	vfp_state = thread_kernel_enable_vfp();
	aes_block(aes_encrypt_zvkned, key2, data_key.key_len, tweak, tweak);
	aes_mode_crypt(decrypt ? aes_xts_decrypt_zvkned_zvbb_zvkg :
				 aes_xts_encrypt_zvkned_zvbb_zvkg,
		       &data_key, in, out, len, tweak);
	thread_kernel_disable_vfp(vfp_state);
	memzero_explicit(&data_key, sizeof(data_key));
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
