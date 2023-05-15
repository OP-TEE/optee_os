// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <crypto/crypto_accel.h>
#include <kernel/thread.h>

/* Prototype for assembly function */
void sha256_ce_transform(uint32_t state[8], const void *src,
			 unsigned int block_count);

void crypto_accel_sha256_compress(uint32_t state[8], const void *src,
				  unsigned int block_count)
{
	uint32_t vfp_state = 0;

	vfp_state = thread_kernel_enable_vfp();
	sha256_ce_transform(state, src, block_count);
	thread_kernel_disable_vfp(vfp_state);
}
