// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <string.h>
#include <string_ext.h>
#include <util.h>

void sha512_transform_zvknhb_zvkb(uint64_t state[8], const void *src,
				  unsigned int block_count);

void crypto_accel_sha512_compress(uint64_t state[8], const void *src,
				  unsigned int block_count)
{
	uint64_t block[16];
	const uint8_t *data = src;
	uint32_t vfp_state = 0;

	if (!block_count)
		return;
	vfp_state = thread_kernel_enable_vfp();
	if (IS_ALIGNED_WITH_TYPE(src, uint64_t)) {
		sha512_transform_zvknhb_zvkb(state, src, block_count);
	} else {
		while (block_count--) {
			memcpy(block, data, sizeof(block));
			sha512_transform_zvknhb_zvkb(state, block, 1);
			data += sizeof(block);
		}
		memzero_explicit(block, sizeof(block));
	}
	thread_kernel_disable_vfp(vfp_state);
}
