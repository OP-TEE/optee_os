// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

/* AES CTR acceleration using the RISC-V Zvkned and Zvkb extensions */

#include <assert.h>
#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <utee_defines.h>

#include "aes_riscv_zvkned_zvkb.h"

void crypto_accel_aes_ctr_be_enc(void *out, const void *in, const void *key,
				 unsigned int round_count,
				 unsigned int block_count, void *iv)
{
	uint32_t state = 0;

	assert(out && in && key && iv);
	assert(round_count == 10 || round_count == 12 || round_count == 14);
	if (!block_count)
		return;

	state = thread_kernel_enable_vfp();
	riscv_aes_ctr_encrypt(key, in, out,
				(size_t)block_count * TEE_AES_BLOCK_SIZE, iv,
				round_count);
	thread_kernel_disable_vfp(state);
}
