/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __CRYPTO_AES_GCM_H
#define __CRYPTO_AES_GCM_H

#include <tee_api_types.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <tomcrypt.h>

struct crypto_aes_gcm_ctx {
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

static inline size_t crypto_aes_gcm_get_ctx_size(void)
{
	return sizeof(struct crypto_aes_gcm_ctx);
}

TEE_Result crypto_aes_gcm_init(struct crypto_aes_gcm_ctx *ctx,
			       TEE_OperationMode mode, const void *key,
			       size_t key_len, const void *nonce,
			       size_t nonce_len, size_t tag_len);
TEE_Result crypto_aes_gcm_update_aad(struct crypto_aes_gcm_ctx *ctx,
				     const void *data, size_t len);
TEE_Result crypto_aes_gcm_update_payload(struct crypto_aes_gcm_ctx *ctx,
					 TEE_OperationMode mode,
					 const void *src, size_t len,
					 void *dst);
TEE_Result crypto_aes_gcm_enc_final(struct crypto_aes_gcm_ctx *ctx,
				    const void *src, size_t len, void *dst,
				    void *tag, size_t *tag_len);
TEE_Result crypto_aes_gcm_dec_final(struct crypto_aes_gcm_ctx *ctx,
				    const void *src, size_t len, void *dst,
				    const void *tag, size_t tag_len);
void crypto_aes_gcm_final(struct crypto_aes_gcm_ctx *ctx);

void crypto_aes_gcm_inc_ctr(struct crypto_aes_gcm_ctx *ctx);

/*
 * Internal weak functions that can be overridden with hardware specific
 * implementations.
 */
void crypto_aes_gcm_next_ctr(struct crypto_aes_gcm_ctx *ctx);

void crypto_aes_gcm_encrypt_block(struct crypto_aes_gcm_ctx *ctx,
				  const void *src, void *dst);

TEE_Result crypto_aes_gcm_set_key(struct crypto_aes_gcm_ctx *ctx,
				  const void *key, size_t key_len);

void crypto_aes_gcm_ghash_update(struct crypto_aes_gcm_ctx *ctx,
				 const void *head, const void *data,
				 size_t num_blocks);

void crypto_aes_gcm_update_payload_block_aligned(struct crypto_aes_gcm_ctx *ctx,
						 TEE_OperationMode m,
						 const void *src,
						 size_t num_blocks, void *dst);


#endif /*__CRYPTO_AES_GCM_H*/
