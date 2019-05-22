// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
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

	res = crypto_cipher_init(c->ecb, TEE_ALG_AES_ECB_NOPAD, mode, key1,
				 key1_len, key2, key2_len, iv, iv_len);
	if (res)
		return res;

	return crypto_cipher_init(c->cbc, TEE_ALG_AES_CBC_NOPAD, mode, key1,
				  key1_len, key2, key2_len, iv, iv_len);
}

static TEE_Result cts_update(struct crypto_cipher_ctx *ctx, bool last_block,
			     const uint8_t *data, size_t len, uint8_t *dst)
{
	struct cts_ctx *c = to_cts_ctx(ctx);

	return tee_aes_cbc_cts_update(c->cbc, c->ecb, c->mode, last_block,
				      data, len, dst);
}

static void cts_final(struct crypto_cipher_ctx *ctx)
{
	struct cts_ctx *c = to_cts_ctx(ctx);

	crypto_cipher_final(c->cbc, TEE_ALG_AES_CBC_NOPAD);
	crypto_cipher_final(c->ecb, TEE_ALG_AES_ECB_NOPAD);
}

static void cts_free_ctx(struct crypto_cipher_ctx *ctx)
{
	struct cts_ctx *c = to_cts_ctx(ctx);

	crypto_cipher_free_ctx(c->cbc, TEE_ALG_AES_CBC_NOPAD);
	crypto_cipher_free_ctx(c->ecb, TEE_ALG_AES_ECB_NOPAD);
	free(c);
}

static void cts_copy_state(struct crypto_cipher_ctx *dst_ctx,
			   struct crypto_cipher_ctx *src_ctx)
{
	struct cts_ctx *src = to_cts_ctx(src_ctx);
	struct cts_ctx *dst = to_cts_ctx(dst_ctx);

	crypto_cipher_copy_state(dst->cbc, src->cbc, TEE_ALG_AES_CBC_NOPAD);
	crypto_cipher_copy_state(dst->ecb, src->ecb, TEE_ALG_AES_ECB_NOPAD);
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
	crypto_cipher_free_ctx(c->ecb, TEE_ALG_AES_ECB_NOPAD);
	free(c);

	return res;
}
