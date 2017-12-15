/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <crypto/internal_aes-gcm.h>
#include <types_ext.h>
#include <utee_defines.h>

static inline void internal_aes_gcm_xor_block(void *dst, const void *src)
{
	uint64_t *d = dst;
	const uint64_t *s = src;

	d[0] ^= s[0];
	d[1] ^= s[1];
}

static inline bool internal_aes_gcm_ptr_is_block_aligned(const void *p)
{
	return !((vaddr_t)p & (TEE_AES_BLOCK_SIZE - 1));
}

void internal_aes_gcm_ghash_gen_tbl(struct internal_aes_gcm_state *state,
				    const struct internal_aes_gcm_key *enc_key);
void internal_aes_gcm_ghash_update_block(struct internal_aes_gcm_state *state,
					 const void *data);
