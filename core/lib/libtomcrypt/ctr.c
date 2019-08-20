// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <tomcrypt_private.h>
#include <util.h>

struct ltc_ctr_ctx {
	struct crypto_cipher_ctx ctx;
	int cipher_idx;
	int (*update)(const unsigned char *src, unsigned char *dst,
		      unsigned long len, symmetric_CTR *ctr);
	symmetric_CTR state;
};

static const struct crypto_cipher_ops ltc_ctr_ops;

static struct ltc_ctr_ctx *to_ctr_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &ltc_ctr_ops);

	return container_of(ctx, struct ltc_ctr_ctx, ctx);
}

static TEE_Result ltc_ctr_init(struct crypto_cipher_ctx *ctx,
			       TEE_OperationMode mode, const uint8_t *key1,
			       size_t key1_len, const uint8_t *key2 __unused,
			       size_t key2_len __unused,
			       const uint8_t *iv __unused,
			       size_t iv_len __unused)
{
	struct ltc_ctr_ctx *c = to_ctr_ctx(ctx);

	if ((int)iv_len != cipher_descriptor[c->cipher_idx]->block_length)
		return TEE_ERROR_BAD_PARAMETERS;

	if (mode == TEE_MODE_ENCRYPT)
		c->update = ctr_encrypt;
	else
		c->update = ctr_decrypt;

	if (ctr_start(c->cipher_idx, iv, key1, key1_len, 0,
		      CTR_COUNTER_BIG_ENDIAN, &c->state) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result ltc_ctr_update(struct crypto_cipher_ctx *ctx,
				 bool last_block __unused,
				 const uint8_t *data, size_t len, uint8_t *dst)
{
	struct ltc_ctr_ctx *c = to_ctr_ctx(ctx);

	if (c->update && c->update(data, dst, len, &c->state) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static void ltc_ctr_final(struct crypto_cipher_ctx *ctx)
{
	ctr_done(&to_ctr_ctx(ctx)->state);
}

static void ltc_ctr_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_ctr_ctx(ctx));
}

static void ltc_ctr_copy_state(struct crypto_cipher_ctx *dst_ctx,
			       struct crypto_cipher_ctx *src_ctx)
{
	struct ltc_ctr_ctx *src = to_ctr_ctx(src_ctx);
	struct ltc_ctr_ctx *dst = to_ctr_ctx(dst_ctx);

	assert(src->cipher_idx == dst->cipher_idx);
	dst->update = src->update;
	dst->state = src->state;
}

static const struct crypto_cipher_ops ltc_ctr_ops = {
	.init = ltc_ctr_init,
	.update = ltc_ctr_update,
	.final = ltc_ctr_final,
	.free_ctx = ltc_ctr_free_ctx,
	.copy_state = ltc_ctr_copy_state,
};

TEE_Result crypto_aes_ctr_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct ltc_ctr_ctx *c = NULL;
	int cipher_idx = find_cipher("aes");

	if (cipher_idx < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &ltc_ctr_ops;
	c->cipher_idx = cipher_idx;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}
