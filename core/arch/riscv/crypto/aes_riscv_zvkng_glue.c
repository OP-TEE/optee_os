// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <crypto/crypto_accel.h>
#include "aes_riscv_zvkng.h"
#include <kernel/thread.h>
#include <string.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#define AES_EXPANDED_KEY_SIZE	(15 * TEE_AES_BLOCK_SIZE)

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
	unsigned int rounds = 0;
	uint32_t vfp_state = 0;

	if (!key || !enc_key || !round_count)
		return TEE_ERROR_BAD_PARAMETERS;
	if (key_len != 16 && key_len != 24 && key_len != 32)
		return TEE_ERROR_BAD_PARAMETERS;
	if (expanded_key_len < AES_EXPANDED_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	rounds = 10 + ((key_len / 8) - 2) * 2;
	memset(enc_key, 0, expanded_key_len);
	memcpy(enc_key, key, key_len);
	vfp_state = thread_kernel_enable_vfp();
	expand_enc_key(enc_key, key_len);
	thread_kernel_disable_vfp(vfp_state);
	if (dec_key)
		memcpy(dec_key, enc_key, expanded_key_len);
	*round_count = rounds;

	return TEE_SUCCESS;
}
