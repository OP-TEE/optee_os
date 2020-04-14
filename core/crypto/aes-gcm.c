// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
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


static void ghash_update_pad_zero(struct internal_aes_gcm_state *state,
				  const uint8_t *data, size_t len)
{
	size_t n = len / TEE_AES_BLOCK_SIZE;
	uint64_t block[2];

	if (n) {
		if (internal_aes_gcm_ptr_is_block_aligned(data)) {
			internal_aes_gcm_ghash_update(state, NULL, data, n);
		} else {
			size_t m;

			for (m = 0; m < n; m++) {

				memcpy(block, data + m * sizeof(block),
				       sizeof(block));
				internal_aes_gcm_ghash_update(state, NULL,
							      (void *)block, 1);
			}
		}
	}

	if (len - n * TEE_AES_BLOCK_SIZE) {
		memset(block, 0, sizeof(block));
		memcpy(block, data + n * TEE_AES_BLOCK_SIZE,
		       len - n * TEE_AES_BLOCK_SIZE);
		internal_aes_gcm_ghash_update(state, block, NULL, 0);
	}
}

static void ghash_update_lengths(struct internal_aes_gcm_state *state,
				 uint32_t l1, uint32_t l2)
{
	uint64_t len_fields[2] = {
		TEE_U64_TO_BIG_ENDIAN(l1 * 8),
		TEE_U64_TO_BIG_ENDIAN(l2 * 8)
	};

	COMPILE_TIME_ASSERT(sizeof(len_fields) == TEE_AES_BLOCK_SIZE);
	internal_aes_gcm_ghash_update(state, (uint8_t *)len_fields, NULL, 0);
}

static TEE_Result __gcm_init(struct internal_aes_gcm_state *state,
			     const struct internal_aes_gcm_key *ek,
			     TEE_OperationMode mode, const void *nonce,
			     size_t nonce_len, size_t tag_len)
{
	COMPILE_TIME_ASSERT(sizeof(state->ctr) == TEE_AES_BLOCK_SIZE);

	if (tag_len > sizeof(state->buf_tag))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(state, 0, sizeof(*state));

	state->tag_len = tag_len;
	internal_aes_gcm_set_key(state, ek);

	if (nonce_len == (96 / 8)) {
		memcpy(state->ctr, nonce, nonce_len);
		internal_aes_gcm_inc_ctr(state);
	} else {
		ghash_update_pad_zero(state, nonce, nonce_len);
		ghash_update_lengths(state, 0, nonce_len);

		memcpy(state->ctr, state->hash_state, sizeof(state->ctr));
		memset(state->hash_state, 0, sizeof(state->hash_state));
	}

	crypto_aes_enc_block(ek->data, sizeof(ek->data), ek->rounds,
			     state->ctr, state->buf_tag);
	internal_aes_gcm_inc_ctr(state);
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
		crypto_aes_enc_block(ek->data, sizeof(ek->data), ek->rounds,
				     state->ctr, state->buf_cryp);
		internal_aes_gcm_inc_ctr(state);
	}

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_init(struct internal_aes_gcm_ctx *ctx,
				 TEE_OperationMode mode, const void *key,
				 size_t key_len, const void *nonce,
				 size_t nonce_len, size_t tag_len)
{
	TEE_Result res = TEE_SUCCESS;
	struct internal_aes_gcm_key *ek = &ctx->key;

	res = crypto_aes_expand_enc_key(key, key_len, ek->data,
					sizeof(ek->data), &ek->rounds);
	if (res)
		return res;

	return __gcm_init(&ctx->state, ek, mode, nonce, nonce_len, tag_len);
}

static TEE_Result __gcm_update_aad(struct internal_aes_gcm_state *state,
				   const void *data, size_t len)
{
	const uint8_t *d = data;
	size_t l = len;
	const uint8_t *head = NULL;
	size_t n;

	if (state->payload_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	state->aad_bytes += len;

	while (l) {
		if (state->buf_pos ||
		    !internal_aes_gcm_ptr_is_block_aligned(d) ||
		    l < TEE_AES_BLOCK_SIZE) {
			n = MIN(TEE_AES_BLOCK_SIZE - state->buf_pos, l);
			memcpy(state->buf_hash + state->buf_pos, d, n);
			state->buf_pos += n;

			if (state->buf_pos != TEE_AES_BLOCK_SIZE)
				return TEE_SUCCESS;

			state->buf_pos = 0;
			head = state->buf_hash;
			d += n;
			l -= n;
		}

		if (internal_aes_gcm_ptr_is_block_aligned(d))
			n = l / TEE_AES_BLOCK_SIZE;
		else
			n = 0;

		internal_aes_gcm_ghash_update(state, head, d, n);
		l -= n * TEE_AES_BLOCK_SIZE;
		d += n * TEE_AES_BLOCK_SIZE;
	}

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_update_aad(struct internal_aes_gcm_ctx *ctx,
				       const void *data, size_t len)
{
	return __gcm_update_aad(&ctx->state, data, len);
}

static TEE_Result
__gcm_update_payload(struct internal_aes_gcm_state *state,
		     const struct internal_aes_gcm_key *ek,
		     TEE_OperationMode mode, const void *src,
		     size_t len, void *dst)
{
	size_t n;
	const uint8_t *s = src;
	uint8_t *d = dst;
	size_t l = len;

	if (!state->payload_bytes && state->buf_pos) {
		/* AAD part done, finish up the last bits. */
		memset(state->buf_hash + state->buf_pos, 0,
		       TEE_AES_BLOCK_SIZE - state->buf_pos);
		internal_aes_gcm_ghash_update(state, state->buf_hash, NULL, 0);
		state->buf_pos = 0;
	}

	state->payload_bytes += len;

	while (l) {
		if (state->buf_pos || l < TEE_AES_BLOCK_SIZE) {
			n = MIN(TEE_AES_BLOCK_SIZE - state->buf_pos, l);

			if (!state->buf_pos && mode == TEE_MODE_DECRYPT)
				crypto_aes_enc_block(ek->data, sizeof(ek->data),
						     ek->rounds, state->ctr,
						     state->buf_cryp);

			xor_buf(state->buf_cryp + state->buf_pos, s, n);
			memcpy(d, state->buf_cryp + state->buf_pos, n);
			if (mode == TEE_MODE_ENCRYPT)
				memcpy(state->buf_hash + state->buf_pos,
				       state->buf_cryp + state->buf_pos, n);
			else
				memcpy(state->buf_hash + state->buf_pos, s, n);

			state->buf_pos += n;

			if (state->buf_pos != TEE_AES_BLOCK_SIZE)
				return TEE_SUCCESS;

			internal_aes_gcm_ghash_update(state, state->buf_hash,
						      NULL, 0);
			state->buf_pos = 0;
			d += n;
			s += n;
			l -= n;

			if (mode == TEE_MODE_ENCRYPT)
				crypto_aes_enc_block(ek->data, sizeof(ek->data),
						     ek->rounds, state->ctr,
						     state->buf_cryp);
			internal_aes_gcm_inc_ctr(state);
		} else {
			n = l / TEE_AES_BLOCK_SIZE;
			internal_aes_gcm_update_payload_blocks(state, ek, mode,
							       s, n, d);
			s += n * TEE_AES_BLOCK_SIZE;
			d += n * TEE_AES_BLOCK_SIZE;
			l -= n * TEE_AES_BLOCK_SIZE;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_update_payload(struct internal_aes_gcm_ctx *ctx,
					   TEE_OperationMode mode,
					   const void *src, size_t len,
					   void *dst)
{
	return __gcm_update_payload(&ctx->state, &ctx->key, mode, src, len,
				    dst);
}

static TEE_Result operation_final(struct internal_aes_gcm_state *state,
				  const struct internal_aes_gcm_key *enc_key,
				  TEE_OperationMode m, const uint8_t *src,
				  size_t len, uint8_t *dst)
{
	TEE_Result res;

	res = __gcm_update_payload(state, enc_key, m, src, len, dst);
	if (res)
		return res;

	if (state->buf_pos) {
		memset(state->buf_hash + state->buf_pos, 0,
		       sizeof(state->buf_hash) - state->buf_pos);
		internal_aes_gcm_ghash_update(state, state->buf_hash, NULL, 0);
	}

	ghash_update_lengths(state, state->aad_bytes, state->payload_bytes);
	/* buf_tag was filled in with the first counter block aes_gcm_init() */
	xor_buf(state->buf_tag, state->hash_state, state->tag_len);

	return TEE_SUCCESS;
}

static TEE_Result __gcm_enc_final(struct internal_aes_gcm_state *state,
				  const struct internal_aes_gcm_key *enc_key,
				  const void *src, size_t len, void *dst,
				  void *tag, size_t *tag_len)
{
	TEE_Result res;

	if (*tag_len < state->tag_len)
		return TEE_ERROR_SHORT_BUFFER;

	res = operation_final(state, enc_key, TEE_MODE_ENCRYPT, src, len, dst);
	if (res)
		return res;

	memcpy(tag, state->buf_tag, state->tag_len);
	*tag_len = state->tag_len;

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_enc_final(struct internal_aes_gcm_ctx *ctx,
				      const void *src, size_t len, void *dst,
				      void *tag, size_t *tag_len)
{
	return __gcm_enc_final(&ctx->state, &ctx->key, src, len, dst, tag,
			       tag_len);
}

static TEE_Result __gcm_dec_final(struct internal_aes_gcm_state *state,
				  const struct internal_aes_gcm_key *enc_key,
				  const void *src, size_t len, void *dst,
				  const void *tag, size_t tag_len)
{
	TEE_Result res;

	if (tag_len != state->tag_len)
		return TEE_ERROR_MAC_INVALID;

	res = operation_final(state, enc_key, TEE_MODE_DECRYPT, src, len, dst);
	if (res)
		return res;

	if (consttime_memcmp(state->buf_tag, tag, tag_len))
		return TEE_ERROR_MAC_INVALID;

	return TEE_SUCCESS;
}

TEE_Result internal_aes_gcm_dec_final(struct internal_aes_gcm_ctx *ctx,
				      const void *src, size_t len, void *dst,
				      const void *tag, size_t tag_len)
{
	return __gcm_dec_final(&ctx->state, &ctx->key, src, len, dst, tag,
			       tag_len);
}

void internal_aes_gcm_inc_ctr(struct internal_aes_gcm_state *state)
{
	uint64_t c = 0;

	c = TEE_U64_FROM_BIG_ENDIAN(state->ctr[1]) + 1;
	state->ctr[1] = TEE_U64_TO_BIG_ENDIAN(c);
	if (!c) {
		c = TEE_U64_FROM_BIG_ENDIAN(state->ctr[0]) + 1;
		state->ctr[0] = TEE_U64_TO_BIG_ENDIAN(c);
	}
}

void internal_aes_gcm_dec_ctr(struct internal_aes_gcm_state *state)
{
	uint64_t c = 0;

	c = TEE_U64_FROM_BIG_ENDIAN(state->ctr[1]) - 1;
	state->ctr[1] = TEE_U64_TO_BIG_ENDIAN(c);
	if (c == UINT64_MAX) {
		c = TEE_U64_FROM_BIG_ENDIAN(state->ctr[0]) - 1;
		state->ctr[0] = TEE_U64_TO_BIG_ENDIAN(c);
	}
}

TEE_Result internal_aes_gcm_enc(const struct internal_aes_gcm_key *enc_key,
				const void *nonce, size_t nonce_len,
				const void *aad, size_t aad_len,
				const void *src, size_t len, void *dst,
				void *tag, size_t *tag_len)
{
	TEE_Result res;
	struct internal_aes_gcm_state state;

	res = __gcm_init(&state, enc_key, TEE_MODE_ENCRYPT, nonce, nonce_len,
			 *tag_len);
	if (res)
		return res;

	if (aad) {
		res = __gcm_update_aad(&state, aad, aad_len);
		if (res)
			return res;
	}

	return __gcm_enc_final(&state, enc_key, src, len, dst, tag, tag_len);
}

TEE_Result internal_aes_gcm_dec(const struct internal_aes_gcm_key *enc_key,
				const void *nonce, size_t nonce_len,
				const void *aad, size_t aad_len,
				const void *src, size_t len, void *dst,
				const void *tag, size_t tag_len)
{
	TEE_Result res;
	struct internal_aes_gcm_state state;

	res = __gcm_init(&state, enc_key, TEE_MODE_DECRYPT, nonce, nonce_len,
			 tag_len);
	if (res)
		return res;

	if (aad) {
		res = __gcm_update_aad(&state, aad, aad_len);
		if (res)
			return res;
	}

	return __gcm_dec_final(&state, enc_key, src, len, dst, tag, tag_len);
}


#ifndef CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB
#include <stdlib.h>
#include <crypto/crypto.h>

struct aes_gcm_ctx {
	struct crypto_authenc_ctx aec;
	struct internal_aes_gcm_ctx ctx;
};

static const struct crypto_authenc_ops aes_gcm_ops;

static struct aes_gcm_ctx *
to_aes_gcm_ctx(struct crypto_authenc_ctx *aec)
{
	assert(aec->ops == &aes_gcm_ops);

	return container_of(aec, struct aes_gcm_ctx, aec);
}

TEE_Result crypto_aes_gcm_alloc_ctx(struct crypto_authenc_ctx **ctx_ret)
{
	struct aes_gcm_ctx *ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;
	ctx->aec.ops = &aes_gcm_ops;

	*ctx_ret = &ctx->aec;

	return TEE_SUCCESS;
}

static void aes_gcm_free_ctx(struct crypto_authenc_ctx *aec)
{
	free(to_aes_gcm_ctx(aec));
}

static void aes_gcm_copy_state(struct crypto_authenc_ctx *dst_ctx,
			       struct crypto_authenc_ctx *src_ctx)
{
	to_aes_gcm_ctx(dst_ctx)->ctx = to_aes_gcm_ctx(src_ctx)->ctx;
}

static TEE_Result aes_gcm_init(struct crypto_authenc_ctx *aec,
			       TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len __unused,
			       size_t payload_len __unused)
{
	return internal_aes_gcm_init(&to_aes_gcm_ctx(aec)->ctx, mode, key,
				     key_len, nonce, nonce_len, tag_len);
}

static TEE_Result aes_gcm_update_aad(struct crypto_authenc_ctx *aec,
				     const uint8_t *data, size_t len)
{
	return internal_aes_gcm_update_aad(&to_aes_gcm_ctx(aec)->ctx, data,
					   len);
}

static TEE_Result aes_gcm_update_payload(struct crypto_authenc_ctx *aec,
					 TEE_OperationMode m,
					 const uint8_t *src, size_t len,
					 uint8_t *dst)
{
	return internal_aes_gcm_update_payload(&to_aes_gcm_ctx(aec)->ctx,
					       m, src, len, dst);
}

static TEE_Result aes_gcm_enc_final(struct crypto_authenc_ctx *aec,
				    const uint8_t *src, size_t len,
				    uint8_t *dst, uint8_t *tag, size_t *tag_len)
{
	return internal_aes_gcm_enc_final(&to_aes_gcm_ctx(aec)->ctx, src, len,
					  dst, tag, tag_len);
}

static TEE_Result aes_gcm_dec_final(struct crypto_authenc_ctx *aec,
				    const uint8_t *src, size_t len,
				    uint8_t *dst, const uint8_t *tag,
				    size_t tag_len)
{
	return internal_aes_gcm_dec_final(&to_aes_gcm_ctx(aec)->ctx, src, len,
					  dst, tag, tag_len);
}

static void aes_gcm_final(struct crypto_authenc_ctx *aec __unused)
{
}

static const struct crypto_authenc_ops aes_gcm_ops = {
	.init = aes_gcm_init,
	.update_aad = aes_gcm_update_aad,
	.update_payload = aes_gcm_update_payload,
	.enc_final = aes_gcm_enc_final,
	.dec_final = aes_gcm_dec_final,
	.final = aes_gcm_final,
	.free_ctx = aes_gcm_free_ctx,
	.copy_state = aes_gcm_copy_state,
};

/*
 * internal_aes_gcm_gfmul() is based on ghash_gfmul() from
 * https://github.com/openbsd/src/blob/master/sys/crypto/gmac.c
 */
void internal_aes_gcm_gfmul(const uint64_t X[2], const uint64_t Y[2],
			    uint64_t product[2])
{
	uint64_t y[2] = { 0 };
	uint64_t z[2] = { 0 };
	const uint8_t *x = (const uint8_t *)X;
	uint32_t mul = 0;
	size_t n = 0;

	y[0] = TEE_U64_FROM_BIG_ENDIAN(Y[0]);
	y[1] = TEE_U64_FROM_BIG_ENDIAN(Y[1]);

	for (n = 0; n < TEE_AES_BLOCK_SIZE * 8; n++) {
		/* update Z */
		if (x[n >> 3] & (1 << (~n & 7)))
			internal_aes_gcm_xor_block(z, y);

		/* update Y */
		mul = y[1] & 1;
		y[1] = (y[0] << 63) | (y[1] >> 1);
		y[0] = (y[0] >> 1) ^ (0xe100000000000000 * mul);
	}

	product[0] = TEE_U64_TO_BIG_ENDIAN(z[0]);
	product[1] = TEE_U64_TO_BIG_ENDIAN(z[1]);
}
#endif /*!CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB*/
