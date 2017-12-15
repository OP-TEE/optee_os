/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 *
 */

#ifndef __CRYPTO_INTERNAL_AES_GCM_H
#define __CRYPTO_INTERNAL_AES_GCM_H

#include <tee_api_types.h>
#include <utee_defines.h>

struct internal_aes_gcm_key {
	/* AES (CTR) encryption key and number of rounds */
	uint64_t data[30];
	unsigned int rounds;
};

struct internal_aes_gcm_state {
	uint64_t ctr[2];

#ifdef CFG_AES_GCM_TABLE_BASED
	uint64_t HL[16];
	uint64_t HH[16];
#else
	uint8_t hash_subkey[TEE_AES_BLOCK_SIZE];
#endif
	uint8_t hash_state[TEE_AES_BLOCK_SIZE];

	uint8_t buf_tag[TEE_AES_BLOCK_SIZE];
	uint8_t buf_hash[TEE_AES_BLOCK_SIZE];
	uint8_t buf_cryp[TEE_AES_BLOCK_SIZE];

	unsigned int tag_len;
	unsigned int aad_bytes;
	unsigned int payload_bytes;
	unsigned int buf_pos;
};

struct internal_aes_gcm_ctx {
	struct internal_aes_gcm_state state;
	struct internal_aes_gcm_key key;
};

TEE_Result internal_aes_gcm_init(struct internal_aes_gcm_ctx *ctx,
				 TEE_OperationMode mode, const void *key,
				 size_t key_len, const void *nonce,
				 size_t nonce_len, size_t tag_len);
TEE_Result internal_aes_gcm_update_aad(struct internal_aes_gcm_ctx *ctx,
				       const void *data, size_t len);
TEE_Result internal_aes_gcm_update_payload(struct internal_aes_gcm_ctx *ctx,
					   TEE_OperationMode mode,
					   const void *src, size_t len,
					   void *dst);
TEE_Result internal_aes_gcm_enc_final(struct internal_aes_gcm_ctx *ctx,
				      const void *src, size_t len, void *dst,
				      void *tag, size_t *tag_len);
TEE_Result internal_aes_gcm_dec_final(struct internal_aes_gcm_ctx *ctx,
				      const void *src, size_t len, void *dst,
				      const void *tag, size_t tag_len);

void internal_aes_gcm_inc_ctr(struct internal_aes_gcm_state *state);

TEE_Result internal_aes_gcm_enc(const struct internal_aes_gcm_key *enc_key,
				const void *nonce, size_t nonce_len,
				const void *aad, size_t aad_len,
				const void *src, size_t len, void *dst,
				void *tag, size_t *tag_len);

TEE_Result internal_aes_gcm_dec(const struct internal_aes_gcm_key *enc_key,
				const void *nonce, size_t nonce_len,
				const void *aad, size_t aad_len,
				const void *src, size_t len, void *dst,
				const void *tag, size_t tag_len);

TEE_Result
internal_aes_gcm_expand_enc_key(const void *key, size_t key_len,
				struct internal_aes_gcm_key *enc_key);

/*
 * Internal weak functions that can be overridden with hardware specific
 * implementations.
 */
void internal_aes_gcm_set_key(struct internal_aes_gcm_state *state,
			      const struct internal_aes_gcm_key *enc_key);

void internal_aes_gcm_ghash_update(struct internal_aes_gcm_state *state,
				   const void *head, const void *data,
				   size_t num_blocks);

void internal_aes_gcm_update_payload_block_aligned(
				struct internal_aes_gcm_state *state,
				const struct internal_aes_gcm_key *enc_key,
				TEE_OperationMode mode, const void *src,
				size_t num_blocks, void *dst);



void internal_aes_gcm_encrypt_block(const struct internal_aes_gcm_key *enc_key,
				    const void *src, void *dst);
#endif /*__CRYPTO_INTERNAL_AES_GCM_H*/
