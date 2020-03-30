// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/internal_aes-gcm.h>
#include <string.h>
#include <tee_api_types.h>
#include <types_ext.h>

void internal_aes_gcm_set_key(struct internal_aes_gcm_state *state,
			      const struct internal_aes_gcm_key *ek)
{
#ifdef CFG_AES_GCM_TABLE_BASED
	internal_aes_gcm_ghash_gen_tbl(&state->ghash_key, ek);
#else
	crypto_aes_enc_block(ek->data, sizeof(ek->data), ek->rounds,
			     state->ctr, state->ghash_key.hash_subkey);
#endif
}

static void ghash_update_block(struct internal_aes_gcm_state *state,
			       const void *data)
{
	void *y = state->hash_state;

	internal_aes_gcm_xor_block(y, data);
#ifdef CFG_AES_GCM_TABLE_BASED
	internal_aes_gcm_ghash_mult_tbl(&state->ghash_key, y, y);
#else
	internal_aes_gcm_gfmul(state->ghash_key.hash_subkey, y, y);
#endif
}

void internal_aes_gcm_ghash_update(struct internal_aes_gcm_state *state,
				   const void *head, const void *data,
				   size_t num_blocks)
{
	size_t n = 0;

	if (head)
		ghash_update_block(state, head);

	for (n = 0; n < num_blocks; n++)
		ghash_update_block(state,
				   (uint8_t *)data + n * TEE_AES_BLOCK_SIZE);
}

TEE_Result internal_aes_gcm_expand_enc_key(const void *key, size_t key_len,
					   struct internal_aes_gcm_key *ek)
{
	size_t ek_len = sizeof(ek->data);

	return crypto_aes_expand_enc_key(key, key_len, ek->data, ek_len,
					&ek->rounds);
}
