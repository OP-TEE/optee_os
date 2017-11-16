/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __CRYPTO_INTERNAL_AES_GCM_H
#define __CRYPTO_INTERNAL_AES_GCM_H

#include <tee_api_types.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <tomcrypt.h>

struct internal_aes_gcm_ctx {
	uint64_t ctr[2];

	uint8_t hash_subkey[TEE_AES_BLOCK_SIZE];
	uint8_t hash_state[TEE_AES_BLOCK_SIZE];

	uint8_t buf_tag[TEE_AES_BLOCK_SIZE];
	uint8_t buf_hash[TEE_AES_BLOCK_SIZE];
	uint8_t buf_cryp[TEE_AES_BLOCK_SIZE];

	symmetric_key skey;

	unsigned int tag_len;
	unsigned int aad_bytes;
	unsigned int payload_bytes;
	unsigned int buf_pos;
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

void internal_aes_gcm_inc_ctr(struct internal_aes_gcm_ctx *ctx);

/*
 * Internal weak functions that can be overridden with hardware specific
 * implementations.
 */
void internal_aes_gcm_encrypt_block(struct internal_aes_gcm_ctx *ctx,
				    const void *src, void *dst);

TEE_Result internal_aes_gcm_set_key(struct internal_aes_gcm_ctx *ctx,
				    const void *key, size_t key_len);

void internal_aes_gcm_ghash_update(struct internal_aes_gcm_ctx *ctx,
				   const void *head, const void *data,
				   size_t num_blocks);

void
internal_aes_gcm_update_payload_block_aligned(struct internal_aes_gcm_ctx *ctx,
					      TEE_OperationMode mode,
					      const void *src,
					      size_t num_blocks, void *dst);
#endif /*__CRYPTO_INTERNAL_AES_GCM_H*/
