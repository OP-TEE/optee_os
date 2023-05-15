// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <util.h>


/* From libtomcrypt doc:
 *	Ciphertext stealing is a method of dealing with messages
 *	in CBC mode which are not a multiple of the block
 *	length.  This is accomplished by encrypting the last
 *	ciphertext block in ECB mode, and XOR'ing the output
 *	against the last partial block of plaintext. LibTomCrypt
 *	does not support this mode directly but it is fairly
 *	easy to emulate with a call to the cipher's
 *	ecb encrypt() callback function.
 *	The more sane way to deal with partial blocks is to pad
 *	them with zeroes, and then use CBC normally
 */

/*
 * From Global Platform: CTS = CBC-CS3
 */

struct cts_ctx {
	struct crypto_cipher_ctx ctx;
	struct crypto_cipher_ctx *ecb;
	struct crypto_cipher_ctx *cbc;
	TEE_OperationMode mode;
};

static const struct crypto_cipher_ops cts_ops;

static struct cts_ctx *to_cts_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &cts_ops);

	return container_of(ctx, struct cts_ctx, ctx);
}

static TEE_Result cts_init(struct crypto_cipher_ctx *ctx,
			   TEE_OperationMode mode, const uint8_t *key1,
			   size_t key1_len, const uint8_t *key2,
			   size_t key2_len, const uint8_t *iv, size_t iv_len)
{
	TEE_Result res = TEE_SUCCESS;
	struct cts_ctx *c = to_cts_ctx(ctx);

	c->mode = mode;

	res = crypto_cipher_init(c->ecb, mode, key1, key1_len, key2, key2_len,
				 iv, iv_len);
	if (res)
		return res;

	return crypto_cipher_init(c->cbc, mode, key1, key1_len, key2, key2_len,
				  iv, iv_len);
}

/*
 * From http://en.wikipedia.org/wiki/Ciphertext_stealing
 * CBC ciphertext stealing encryption using a standard
 * CBC interface:
 *	1. Pad the last partial plaintext block with 0.
 *	2. Encrypt the whole padded plaintext using the
 *	   standard CBC mode.
 *	3. Swap the last two ciphertext blocks.
 *	4. Truncate the ciphertext to the length of the
 *	   original plaintext.
 *
 * CBC ciphertext stealing decryption using a standard
 * CBC interface
 *	1. Dn = Decrypt (K, Cn-1). Decrypt the second to last
 *	   ciphertext block.
 *	2. Cn = Cn || Tail (Dn, B-M). Pad the ciphertext to the
 *	   nearest multiple of the block size using the last
 *	   B-M bits of block cipher decryption of the
 *	   second-to-last ciphertext block.
 *	3. Swap the last two ciphertext blocks.
 *	4. Decrypt the (modified) ciphertext using the standard
 *	   CBC mode.
 *	5. Truncate the plaintext to the length of the original
 *	   ciphertext.
 */
static TEE_Result cbc_cts_update(void *cbc_ctx, void *ecb_ctx,
				 TEE_OperationMode mode, bool last_block,
				 const uint8_t *data, size_t len, uint8_t *dst)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t  tmp2_block[64] = { 0 };
	uint8_t tmp_block[64] = { 0 };
	int len_last_block = 0;
	int block_size = 16;
	int nb_blocks = 0;

	if (!last_block)
		return tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					    mode, last_block, data, len, dst);

	/* Compute the last block length and check constraints */
	nb_blocks = (len + block_size - 1) / block_size;
	if (nb_blocks < 2)
		return TEE_ERROR_BAD_STATE;
	len_last_block = len % block_size;
	if (len_last_block == 0)
		len_last_block = block_size;

	if (mode == TEE_MODE_ENCRYPT) {
		memcpy(tmp_block,
		       data + ((nb_blocks - 1) * block_size),
		       len_last_block);
		memset(tmp_block + len_last_block,
		       0,
		       block_size - len_last_block);

		res = tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					   mode, 0, data,
					   (nb_blocks - 1) * block_size, dst);
		if (res != TEE_SUCCESS)
			return res;

		memcpy(dst + (nb_blocks - 1) * block_size,
		       dst + (nb_blocks - 2) * block_size,
		       len_last_block);

		res = tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					   mode, 0, tmp_block, block_size,
					   dst + (nb_blocks - 2) * block_size);
		if (res != TEE_SUCCESS)
			return res;
	} else {
		/* 1. Decrypt the second to last ciphertext block */
		res = tee_do_cipher_update(ecb_ctx, TEE_ALG_AES_ECB_NOPAD,
					   mode, 0,
					   data + (nb_blocks - 2) * block_size,
					   block_size, tmp2_block);
		if (res != TEE_SUCCESS)
			return res;

		/* 2. Cn = Cn || Tail (Dn, B-M) */
		memcpy(tmp_block, data + ((nb_blocks - 1) * block_size),
		       len_last_block);
		memcpy(tmp_block + len_last_block, tmp2_block + len_last_block,
		       block_size - len_last_block);

		/* 3. Swap the last two ciphertext blocks */
		/* done by passing the correct buffers in step 4. */

		/* 4. Decrypt the (modified) ciphertext */
		if (nb_blocks > 2) {
			res = tee_do_cipher_update(cbc_ctx,
						   TEE_ALG_AES_CBC_NOPAD, mode,
						   0, data,
						   (nb_blocks - 2) *
						   block_size, dst);
			if (res != TEE_SUCCESS)
				return res;
		}

		res = tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					   mode, 0, tmp_block, block_size,
					   dst +
					   ((nb_blocks - 2) * block_size));
		if (res != TEE_SUCCESS)
			return res;

		res = tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					   mode, 0, data +
					   ((nb_blocks - 2) * block_size),
					   block_size, tmp_block);
		if (res != TEE_SUCCESS)
			return res;

		/* 5. Truncate the plaintext */
		memcpy(dst + (nb_blocks - 1) * block_size, tmp_block,
		       len_last_block);
	}
	return TEE_SUCCESS;
}

static TEE_Result cts_update(struct crypto_cipher_ctx *ctx, bool last_block,
			     const uint8_t *data, size_t len, uint8_t *dst)
{
	struct cts_ctx *c = to_cts_ctx(ctx);

	return cbc_cts_update(c->cbc, c->ecb, c->mode, last_block, data, len,
			      dst);
}

static void cts_final(struct crypto_cipher_ctx *ctx)
{
	struct cts_ctx *c = to_cts_ctx(ctx);

	crypto_cipher_final(c->cbc);
	crypto_cipher_final(c->ecb);
}

static void cts_free_ctx(struct crypto_cipher_ctx *ctx)
{
	struct cts_ctx *c = to_cts_ctx(ctx);

	crypto_cipher_free_ctx(c->cbc);
	crypto_cipher_free_ctx(c->ecb);
	free(c);
}

static void cts_copy_state(struct crypto_cipher_ctx *dst_ctx,
			   struct crypto_cipher_ctx *src_ctx)
{
	struct cts_ctx *src = to_cts_ctx(src_ctx);
	struct cts_ctx *dst = to_cts_ctx(dst_ctx);

	crypto_cipher_copy_state(dst->cbc, src->cbc);
	crypto_cipher_copy_state(dst->ecb, src->ecb);
	dst->mode = src->mode;
}

static const struct crypto_cipher_ops cts_ops = {
	.init = cts_init,
	.update = cts_update,
	.final = cts_final,
	.free_ctx = cts_free_ctx,
	.copy_state = cts_copy_state,
};

TEE_Result crypto_aes_cts_alloc_ctx(struct crypto_cipher_ctx **ctx)
{
	TEE_Result res = TEE_SUCCESS;
	struct cts_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_aes_ecb_alloc_ctx(&c->ecb);
	if (res)
		goto err;
	res = crypto_aes_cbc_alloc_ctx(&c->cbc);
	if (res)
		goto err;

	c->ctx.ops = &cts_ops;
	*ctx = &c->ctx;

	return TEE_SUCCESS;
err:
	crypto_cipher_free_ctx(c->ecb);
	free(c);

	return res;
}
