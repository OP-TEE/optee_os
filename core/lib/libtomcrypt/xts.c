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
#include <tomcrypt_private.h>
#include <utee_defines.h>
#include <util.h>

struct ltc_xts_ctx {
	struct crypto_cipher_ctx ctx;
	int cipher_idx;
	int (*update)(const unsigned char *src, unsigned long len,
		      unsigned char *dst, unsigned char *tweak,
		      const symmetric_xts *xts);
	symmetric_xts state;
	uint8_t tweak[TEE_AES_BLOCK_SIZE];
};

static const struct crypto_cipher_ops ltc_xts_ops;

static struct ltc_xts_ctx *to_xts_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &ltc_xts_ops);

	return container_of(ctx, struct ltc_xts_ctx, ctx);
}

static TEE_Result ltc_xts_init(struct crypto_cipher_ctx *ctx,
			       TEE_OperationMode mode, const uint8_t *key1,
			       size_t key1_len, const uint8_t *key2 __unused,
			       size_t key2_len __unused,
			       const uint8_t *iv __unused,
			       size_t iv_len __unused)
{
	struct ltc_xts_ctx *c = to_xts_ctx(ctx);

	if (key1_len != key2_len)
		return TEE_ERROR_BAD_PARAMETERS;
	if (iv) {
		if (iv_len != sizeof(c->tweak))
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(c->tweak, iv, sizeof(c->tweak));
	} else {
		memset(c->tweak, 0, sizeof(c->tweak));
	}

	if ((int)iv_len != cipher_descriptor[c->cipher_idx]->block_length)
		return TEE_ERROR_BAD_PARAMETERS;

	if (mode == TEE_MODE_ENCRYPT)
		c->update = xts_encrypt;
	else
		c->update = xts_decrypt;


	if (xts_start(c->cipher_idx, key1, key2, key1_len, 0,
		      &c->state) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result ltc_xts_update(struct crypto_cipher_ctx *ctx,
				 bool last_block __unused,
				 const uint8_t *data, size_t len, uint8_t *dst)
{
	struct ltc_xts_ctx *c = to_xts_ctx(ctx);

	if (c->update && c->update(data, len, dst, c->tweak,
				   &c->state) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static void ltc_xts_final(struct crypto_cipher_ctx *ctx)
{
	xts_done(&to_xts_ctx(ctx)->state);
}

static void ltc_xts_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_xts_ctx(ctx));
}

static void ltc_xts_copy_state(struct crypto_cipher_ctx *dst_ctx,
			       struct crypto_cipher_ctx *src_ctx)
{
	struct ltc_xts_ctx *src = to_xts_ctx(src_ctx);
	struct ltc_xts_ctx *dst = to_xts_ctx(dst_ctx);

	assert(src->cipher_idx == dst->cipher_idx);
	dst->update = src->update;
	memcpy(dst->tweak, src->tweak, sizeof(src->tweak));
	dst->state = src->state;
}

static const struct crypto_cipher_ops ltc_xts_ops = {
	.init = ltc_xts_init,
	.update = ltc_xts_update,
	.final = ltc_xts_final,
	.free_ctx = ltc_xts_free_ctx,
	.copy_state = ltc_xts_copy_state,
};

TEE_Result crypto_aes_xts_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct ltc_xts_ctx *c = NULL;
	int cipher_idx = find_cipher("aes");

	if (cipher_idx < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &ltc_xts_ops;
	c->cipher_idx = cipher_idx;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}
