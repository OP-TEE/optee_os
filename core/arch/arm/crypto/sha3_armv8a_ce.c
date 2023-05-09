// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Linaro Limited
 */

#include <crypto/crypto_accel.h>
#include <kernel/thread.h>

/* Prototype for assembly function */
int sha3_ce_transform(uint64_t state[25], const void *src,
		      unsigned int block_count, unsigned int digest_size);

void crypto_accel_sha3_compress(uint64_t state[25], const void *src,
				unsigned int block_count,
				unsigned int digest_size)
{
	uint32_t vfp_state = 0;
	int res = 0;

	vfp_state = thread_kernel_enable_vfp();
	res = sha3_ce_transform(state, src, block_count, digest_size);
	thread_kernel_disable_vfp(vfp_state);
	assert(!res);
}

