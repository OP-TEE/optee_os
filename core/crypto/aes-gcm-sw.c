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

	if (data)
		for (n = 0; n < num_blocks; n++)
			ghash_update_block(state,
					   (const uint8_t *)data +
					   n * TEE_AES_BLOCK_SIZE);
}

static void encrypt_block(struct internal_aes_gcm_state *state,
			  const struct internal_aes_gcm_key *enc_key,
			  const uint64_t src[2], uint64_t dst[2])
{
	void *buf_cryp = state->buf_cryp;

	internal_aes_gcm_xor_block(buf_cryp, src);
	internal_aes_gcm_ghash_update(state, buf_cryp, NULL, 0);
	memcpy(dst, buf_cryp, sizeof(state->buf_cryp));

	crypto_aes_enc_block(enc_key->data, sizeof(enc_key->data),
			     enc_key->rounds, state->ctr, state->buf_cryp);
	internal_aes_gcm_inc_ctr(state);
}

static void encrypt_pl(struct internal_aes_gcm_state *state,
		       const struct internal_aes_gcm_key *ek,
		       const uint8_t *src, size_t num_blocks, uint8_t *dst)
{
	size_t n = 0;

	if (IS_ALIGNED_WITH_TYPE(src, uint64_t)) {
		for (n = 0; n < num_blocks; n++) {
			const void *s = src + n * TEE_AES_BLOCK_SIZE;
			void *d = dst + n * TEE_AES_BLOCK_SIZE;

			encrypt_block(state, ek, s, d);
		}
	} else {
		for (n = 0; n < num_blocks; n++) {
			uint64_t tmp[2] = { 0 };
			void *d = dst + n * TEE_AES_BLOCK_SIZE;

			memcpy(tmp, src + n * TEE_AES_BLOCK_SIZE, sizeof(tmp));
			encrypt_block(state, ek, tmp, d);
		}
	}
}

static void decrypt_block(struct internal_aes_gcm_state *state,
			  const struct internal_aes_gcm_key *enc_key,
			  const uint64_t src[2], uint64_t dst[2])
{
	void *buf_cryp = state->buf_cryp;

	crypto_aes_enc_block(enc_key->data, sizeof(enc_key->data),
			     enc_key->rounds, state->ctr, buf_cryp);
	internal_aes_gcm_inc_ctr(state);

	internal_aes_gcm_xor_block(buf_cryp, src);
	internal_aes_gcm_ghash_update(state, src, NULL, 0);
	memcpy(dst, buf_cryp, sizeof(state->buf_cryp));
}

static void decrypt_pl(struct internal_aes_gcm_state *state,
		       const struct internal_aes_gcm_key *ek,
		       const uint8_t *src, size_t num_blocks, uint8_t *dst)
{
	size_t n = 0;

	if (IS_ALIGNED_WITH_TYPE(src, uint64_t)) {
		for (n = 0; n < num_blocks; n++) {
			const void *s = src + n * TEE_AES_BLOCK_SIZE;
			void *d = dst + n * TEE_AES_BLOCK_SIZE;

			decrypt_block(state, ek, s, d);
		}
	} else {
		for (n = 0; n < num_blocks; n++) {
			uint64_t tmp[2] = { 0 };
			void *d = dst + n * TEE_AES_BLOCK_SIZE;

			memcpy(tmp, src + n * TEE_AES_BLOCK_SIZE, sizeof(tmp));
			decrypt_block(state, ek, tmp, d);
		}
	}
}

void
internal_aes_gcm_update_payload_blocks(struct internal_aes_gcm_state *state,
				       const struct internal_aes_gcm_key *ek,
				       TEE_OperationMode m, const void *src,
				       size_t num_blocks, void *dst)
{
	assert(!state->buf_pos && num_blocks);

	if (m == TEE_MODE_ENCRYPT)
		encrypt_pl(state, ek, src, num_blocks, dst);
	else
		decrypt_pl(state, ek, src, num_blocks, dst);
}
