// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/internal_aes-gcm.h>
#include <string.h>
#include <tee_api_types.h>
#include <types_ext.h>

#include "aes-gcm-private.h"

void __weak internal_aes_gcm_set_key(struct internal_aes_gcm_state *state,
				     const struct internal_aes_gcm_key *ek)
{
#ifdef CFG_AES_GCM_TABLE_BASED
	internal_aes_gcm_ghash_gen_tbl(state, ek);
#else
	internal_aes_gcm_encrypt_block(ek, state->ctr, state->hash_subkey);
#endif
}

void __weak internal_aes_gcm_ghash_update(struct internal_aes_gcm_state *state,
					  const void *head, const void *data,
					  size_t num_blocks)
{
	size_t n;

	if (head)
		internal_aes_gcm_ghash_update_block(state, head);

	for (n = 0; n < num_blocks; n++)
		internal_aes_gcm_ghash_update_block(state, (uint8_t *)data +
						    n * TEE_AES_BLOCK_SIZE);
}

void __weak
internal_aes_gcm_update_payload_block_aligned(
				struct internal_aes_gcm_state *state,
				const struct internal_aes_gcm_key *ek,
				TEE_OperationMode m, const void *src,
				size_t num_blocks, void *dst)
{
	size_t n;
	const uint8_t *s = src;
	uint8_t *d = dst;
	void *ctr = state->ctr;
	void *buf_cryp = state->buf_cryp;

	assert(!state->buf_pos && num_blocks &&
	       internal_aes_gcm_ptr_is_block_aligned(s) &&
	       internal_aes_gcm_ptr_is_block_aligned(d));

	for (n = 0; n < num_blocks; n++) {
		if (m == TEE_MODE_ENCRYPT) {
			internal_aes_gcm_xor_block(buf_cryp, s);
			internal_aes_gcm_ghash_update(state, buf_cryp, NULL, 0);
			memcpy(d, buf_cryp, sizeof(state->buf_cryp));

			internal_aes_gcm_encrypt_block(ek, ctr, buf_cryp);
			internal_aes_gcm_inc_ctr(state);
		} else {
			internal_aes_gcm_encrypt_block(ek, ctr, buf_cryp);

			internal_aes_gcm_xor_block(buf_cryp, s);
			internal_aes_gcm_ghash_update(state, s, NULL, 0);
			memcpy(d, buf_cryp, sizeof(state->buf_cryp));

			internal_aes_gcm_inc_ctr(state);
		}
		s += TEE_AES_BLOCK_SIZE;
		d += TEE_AES_BLOCK_SIZE;
	}
}

void __weak
internal_aes_gcm_encrypt_block(const struct internal_aes_gcm_key *ek,
			       const void *src, void *dst)
{
	size_t ek_len = sizeof(ek->data);

	crypto_aes_enc_block(ek->data, ek_len, ek->rounds, src, dst);
}

TEE_Result __weak
internal_aes_gcm_expand_enc_key(const void *key, size_t key_len,
				struct internal_aes_gcm_key *ek)
{
	size_t ek_len = sizeof(ek->data);

	return crypto_aes_expand_enc_key(key, key_len, ek->data, ek_len,
					&ek->rounds);
}
