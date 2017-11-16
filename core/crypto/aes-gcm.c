/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <crypto/internal_aes-gcm.h>
#include <io.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

static void xor_buf(uint8_t *dst, const uint8_t *src, size_t len)
{
	size_t n;

	for (n = 0; n < len; n++)
		dst[n] ^= src[n];
}

static bool ptr_is_block_aligned(const void *p)
{
	return !((vaddr_t)p & (TEE_AES_BLOCK_SIZE - 1));
}

static void ghash_update_pad_zero(struct internal_aes_gcm_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	size_t n = len / TEE_AES_BLOCK_SIZE;
	uint64_t block[2];

	if (n) {
		if (ptr_is_block_aligned(data)) {
			internal_aes_gcm_ghash_update(ctx, NULL, data, n);
		} else {
			size_t m;

			for (m = 0; m < n; m++) {

				memcpy(block, data + m * sizeof(block),
				       sizeof(block));
				internal_aes_gcm_ghash_update(ctx, NULL,
							      (void *)block, 1);
			}
		}
	}

	if (len - n * TEE_AES_BLOCK_SIZE) {
		memset(block, 0, sizeof(block));
		memcpy(block, data + n * TEE_AES_BLOCK_SIZE,
		       len - n * TEE_AES_BLOCK_SIZE);
		internal_aes_gcm_ghash_update(ctx, block, NULL, 0);
	}
}

static void ghash_update_lengths(struct internal_aes_gcm_ctx *ctx, uint32_t l1,
				 uint32_t l2)
{
	uint64_t len_fields[2] = {
		TEE_U64_TO_BIG_ENDIAN(l1 * 8),
		TEE_U64_TO_BIG_ENDIAN(l2 * 8)
	};

	COMPILE_TIME_ASSERT(sizeof(len_fields) == TEE_AES_BLOCK_SIZE);
	internal_aes_gcm_ghash_update(ctx, (uint8_t *)len_fields, NULL, 0);
}

TEE_Result internal_aes_gcm_init(struct internal_aes_gcm_ctx *ctx,
				 TEE_OperationMode mode, const void *key,
				 size_t key_len, const void *nonce,
				 size_t nonce_len, size_t tag_len)
{
	TEE_Result res;

	COMPILE_TIME_ASSERT(sizeof(ctx->ctr) == TEE_AES_BLOCK_SIZE);

	if (tag_len > sizeof(ctx->buf_tag))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(ctx, 0, sizeof(*ctx));

	ctx->tag_len = tag_len;
	res = internal_aes_gcm_set_key(ctx, key, key_len);
	if (res)
		return res;

	if (nonce_len == (96 / 8)) {
		memcpy(ctx->ctr, nonce, nonce_len);
		internal_aes_gcm_inc_ctr(ctx);
	} else {
		ghash_update_pad_zero(ctx, nonce, nonce_len);
		ghash_update_lengths(ctx, 0, nonce_len);

		memcpy(ctx->ctr, ctx->hash_state, sizeof(ctx->ctr));
		memset(ctx->hash_state, 0, sizeof(ctx->hash_state));
	}

	internal_aes_gcm_encrypt_block(ctx, ctx->ctr, ctx->buf_tag);
	internal_aes_gcm_inc_ctr(ctx);
	if (mode == TEE_MODE_ENCRYPT) {
		/*
		 * Encryption uses the pre-encrypted xor-buffer to encrypt
		 * while decryption encrypts the xor-buffer when needed
		 * instead.
		 *
		 * The reason for this is that the combined encryption and
		 * ghash implementation does both operations intertwined.
		 * In the decrypt case the xor-buffer is needed at the end
		 * of processing each block, while the encryption case
		 * needs xor-buffer before processing each block.
		 *
		 * In a pure software implementation we wouldn't have any
		 * use for this kind of optimization, but since this
		 * AES-GCM implementation is aimed at being combined with
		 * accelerated routines it's more convenient to always have
		 * this optimization activated.
		 */
		internal_aes_gcm_encrypt_block(ctx, ctx->ctr, ctx->buf_cryp);
		internal_aes_gcm_inc_ctr(ctx);
	}

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_update_aad(struct internal_aes_gcm_ctx *ctx,
				       const void *data, size_t len)
{
	const uint8_t *d = data;
	size_t l = len;
	const uint8_t *head = NULL;
	size_t n;

	if (ctx->payload_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx->aad_bytes += len;

	while (l) {
		if (ctx->buf_pos || !ptr_is_block_aligned(d) ||
		    l < TEE_AES_BLOCK_SIZE) {
			n = MIN(TEE_AES_BLOCK_SIZE - ctx->buf_pos, l);
			memcpy(ctx->buf_hash + ctx->buf_pos, d, n);
			ctx->buf_pos += n;

			if (ctx->buf_pos != TEE_AES_BLOCK_SIZE)
				return TEE_SUCCESS;

			ctx->buf_pos = 0;
			head = ctx->buf_hash;
			d += n;
			l -= n;
		}

		if (ptr_is_block_aligned(d))
			n = l / TEE_AES_BLOCK_SIZE;
		else
			n = 0;

		internal_aes_gcm_ghash_update(ctx, head, d, n);
		l -= n * TEE_AES_BLOCK_SIZE;
		d += n * TEE_AES_BLOCK_SIZE;
	}

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_update_payload(struct internal_aes_gcm_ctx *ctx,
					   TEE_OperationMode mode,
					   const void *src, size_t len,
					   void *dst)
{
	size_t n;
	const uint8_t *s = src;
	uint8_t *d = dst;
	size_t l = len;

	if (!ctx->payload_bytes && ctx->buf_pos) {
		/* AAD part done, finish up the last bits. */
		memset(ctx->buf_hash + ctx->buf_pos, 0,
		       TEE_AES_BLOCK_SIZE - ctx->buf_pos);
		internal_aes_gcm_ghash_update(ctx, ctx->buf_hash, NULL, 0);
		ctx->buf_pos = 0;
	}

	ctx->payload_bytes += len;

	while (l) {
		if (ctx->buf_pos || !ptr_is_block_aligned(s) ||
		    !ptr_is_block_aligned(d) || l < TEE_AES_BLOCK_SIZE) {
			n = MIN(TEE_AES_BLOCK_SIZE - ctx->buf_pos, l);

			if (!ctx->buf_pos && mode == TEE_MODE_DECRYPT) {
				internal_aes_gcm_encrypt_block(ctx, ctx->ctr,
							       ctx->buf_cryp);
			}

			xor_buf(ctx->buf_cryp + ctx->buf_pos, s, n);
			memcpy(d, ctx->buf_cryp + ctx->buf_pos, n);
			if (mode == TEE_MODE_ENCRYPT)
				memcpy(ctx->buf_hash + ctx->buf_pos,
				       ctx->buf_cryp + ctx->buf_pos, n);
			else
				memcpy(ctx->buf_hash + ctx->buf_pos, s, n);

			ctx->buf_pos += n;

			if (ctx->buf_pos != TEE_AES_BLOCK_SIZE)
				return TEE_SUCCESS;

			internal_aes_gcm_ghash_update(ctx, ctx->buf_hash,
						      NULL, 0);
			ctx->buf_pos = 0;
			d += n;
			s += n;
			l -= n;

			if (mode == TEE_MODE_ENCRYPT)
				internal_aes_gcm_encrypt_block(ctx, ctx->ctr,
							       ctx->buf_cryp);
			internal_aes_gcm_inc_ctr(ctx);
		} else {
			n = l / TEE_AES_BLOCK_SIZE;
			internal_aes_gcm_update_payload_block_aligned(ctx, mode,
								      s, n, d);
			s += n * TEE_AES_BLOCK_SIZE;
			d += n * TEE_AES_BLOCK_SIZE;
			l -= n * TEE_AES_BLOCK_SIZE;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result operation_final(struct internal_aes_gcm_ctx *ctx,
				  TEE_OperationMode m, const uint8_t *src,
				  size_t len, uint8_t *dst)
{
	TEE_Result res;

	res = internal_aes_gcm_update_payload(ctx, m, src, len, dst);
	if (res)
		return res;

	if (ctx->buf_pos) {
		memset(ctx->buf_hash + ctx->buf_pos, 0,
		       sizeof(ctx->buf_hash) - ctx->buf_pos);
		internal_aes_gcm_ghash_update(ctx, ctx->buf_hash, NULL, 0);
	}

	ghash_update_lengths(ctx, ctx->aad_bytes, ctx->payload_bytes);
	/* buf_tag was filled in with the first counter block aes_gcm_init() */
	xor_buf(ctx->buf_tag, ctx->hash_state, ctx->tag_len);

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_enc_final(struct internal_aes_gcm_ctx *ctx,
				      const void *src, size_t len, void *dst,
				      void *tag, size_t *tag_len)
{
	TEE_Result res;

	if (*tag_len < ctx->tag_len)
		return TEE_ERROR_SHORT_BUFFER;

	res = operation_final(ctx, TEE_MODE_ENCRYPT, src, len, dst);
	if (res)
		return res;

	memcpy(tag, ctx->buf_tag, ctx->tag_len);
	*tag_len = ctx->tag_len;

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_dec_final(struct internal_aes_gcm_ctx *ctx,
				      const void *src, size_t len, void *dst,
				      const void *tag, size_t tag_len)
{
	TEE_Result res;

	if (tag_len != ctx->tag_len)
		return TEE_ERROR_MAC_INVALID;

	res = operation_final(ctx, TEE_MODE_DECRYPT, src, len, dst);
	if (res)
		return res;

	if (buf_compare_ct(ctx->buf_tag, tag, tag_len))
		return TEE_ERROR_MAC_INVALID;

	return TEE_SUCCESS;
}

void internal_aes_gcm_inc_ctr(struct internal_aes_gcm_ctx *ctx)
{
	uint64_t c;

	c = TEE_U64_FROM_BIG_ENDIAN(ctx->ctr[1]) + 1;
	ctx->ctr[1] = TEE_U64_TO_BIG_ENDIAN(c);
	if (!c) {
		c = TEE_U64_FROM_BIG_ENDIAN(ctx->ctr[0]) + 1;
		ctx->ctr[0] = TEE_U64_TO_BIG_ENDIAN(c);
	}
}

#ifndef CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB
#include <crypto/aes-gcm.h>

size_t crypto_aes_gcm_get_ctx_size(void)
{
	return sizeof(struct internal_aes_gcm_ctx);
}

TEE_Result crypto_aes_gcm_init(void *c, TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len)
{
	return internal_aes_gcm_init(c, mode, key, key_len, nonce, nonce_len,
				     tag_len);
}

TEE_Result crypto_aes_gcm_update_aad(void *c, const uint8_t *data, size_t len)
{
	return internal_aes_gcm_update_aad(c, data, len);
}

TEE_Result crypto_aes_gcm_update_payload(void *c, TEE_OperationMode m,
					 const uint8_t *src, size_t len,
					 uint8_t *dst)
{
	return internal_aes_gcm_update_payload(c, m, src, len, dst);
}

TEE_Result crypto_aes_gcm_enc_final(void *c, const uint8_t *src, size_t len,
				    uint8_t *dst, uint8_t *tag, size_t *tag_len)
{
	return internal_aes_gcm_enc_final(c, src, len, dst, tag, tag_len);
}

TEE_Result crypto_aes_gcm_dec_final(void *c, const uint8_t *src, size_t len,
				    uint8_t *dst, const uint8_t *tag,
				    size_t tag_len)
{
	return internal_aes_gcm_dec_final(c, src, len, dst, tag, tag_len);
}

void crypto_aes_gcm_final(void *c __unused)
{
}
#endif /*!CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB*/
