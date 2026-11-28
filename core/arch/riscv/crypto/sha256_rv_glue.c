// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <string.h>
#include <string_ext.h>
#include <util.h>

void sha256_transform_zvknha_or_zvknhb_zvkb(uint32_t state[8],
					    const void *src,
					    unsigned int block_count);

void crypto_accel_sha256_compress(uint32_t state[8], const void *src,
				  unsigned int block_count)
{
	uint32_t block[16];
	const uint8_t *data = src;
	uint32_t vfp_state = 0;

	if (!block_count)
		return;
	vfp_state = thread_kernel_enable_vfp();
	if (IS_ALIGNED_WITH_TYPE(src, uint32_t)) {
		sha256_transform_zvknha_or_zvknhb_zvkb(state, src, block_count);
	} else {
		while (block_count--) {
			memcpy(block, data, sizeof(block));
			sha256_transform_zvknha_or_zvknhb_zvkb(state, block, 1);
			data += sizeof(block);
		}
		memzero_explicit(block, sizeof(block));
	}
	thread_kernel_disable_vfp(vfp_state);
}
