// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 * Copyright (c) 2021, SumUp Services GmbH
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

struct ltc_omac_ctx {
	struct crypto_mac_ctx ctx;
	int cipher_idx;
	omac_state state;
};

static const struct crypto_mac_ops ltc_omac_ops;

static struct ltc_omac_ctx *to_omac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &ltc_omac_ops);

	return container_of(ctx, struct ltc_omac_ctx, ctx);
}

static TEE_Result ltc_omac_init(struct crypto_mac_ctx *ctx, const uint8_t *key,
				size_t len)
{
	struct ltc_omac_ctx *hc = to_omac_ctx(ctx);

	if (omac_init(&hc->state, hc->cipher_idx, key, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result ltc_omac_update(struct crypto_mac_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	if (omac_process(&to_omac_ctx(ctx)->state, data, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result ltc_omac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				 size_t len)
{
	unsigned long l = len;

	if (omac_done(&to_omac_ctx(ctx)->state, digest, &l) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static void ltc_omac_free_ctx(struct crypto_mac_ctx *ctx)
{
	free(to_omac_ctx(ctx));
}

static void ltc_omac_copy_state(struct crypto_mac_ctx *dst_ctx,
				struct crypto_mac_ctx *src_ctx)
{
	struct ltc_omac_ctx *src = to_omac_ctx(src_ctx);
	struct ltc_omac_ctx *dst = to_omac_ctx(dst_ctx);

	assert(src->cipher_idx == dst->cipher_idx);
	dst->state = src->state;
}

static const struct crypto_mac_ops ltc_omac_ops = {
	.init = ltc_omac_init,
	.update = ltc_omac_update,
	.final = ltc_omac_final,
	.free_ctx = ltc_omac_free_ctx,
	.copy_state = ltc_omac_copy_state,
};

static TEE_Result crypto_common_cmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret,
		const char *cipher)
{
	struct ltc_omac_ctx *ctx = NULL;
	int cipher_idx = find_cipher(cipher);

	if (!ctx_ret)
		return TEE_ERROR_BAD_PARAMETERS;

	if (cipher_idx < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ctx->ctx.ops = &ltc_omac_ops;
	ctx->cipher_idx = cipher_idx;
	*ctx_ret = &ctx->ctx;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_cmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret)
{
	return crypto_common_cmac_alloc_ctx(ctx_ret, "aes");
}

TEE_Result crypto_des3_cmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret)
{
	return crypto_common_cmac_alloc_ctx(ctx_ret, "3des");
}
