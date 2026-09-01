// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 *
 * AES acceleration built on the RISC-V Zvkned vector crypto extension.
 */

#include <assert.h>
#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <utee_defines.h>

#include "riscv_aes_zvkned.h"

static bool aes_accel_args_ok(const void *out, const void *in,
			      const void *key, unsigned int round_count)
{
	assert(out && in && key);
	assert(round_count == 10 || round_count == 12 ||
	       round_count == 14);

	return out && in && key;
}

void crypto_accel_aes_ecb_enc(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count)
{
	uint32_t state = 0;

	if (!aes_accel_args_ok(out, in, key, round_count) || !block_count)
		return;

	state = thread_kernel_enable_vector();
	riscv_aes_ecb_encrypt(key, in, out,
			      (size_t)block_count * TEE_AES_BLOCK_SIZE,
			      round_count);
	thread_kernel_disable_vector(state);
}

void crypto_accel_aes_ecb_dec(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count)
{
	uint32_t state = 0;

	if (!aes_accel_args_ok(out, in, key, round_count) || !block_count)
		return;

	state = thread_kernel_enable_vector();
	riscv_aes_ecb_decrypt(key, in, out,
			      (size_t)block_count * TEE_AES_BLOCK_SIZE,
			      round_count);
	thread_kernel_disable_vector(state);
}
