// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <se050.h>
#include <string.h>
#include <utee_defines.h>
#include <util.h>

struct se050_hmac_ctx {
	struct crypto_mac_ctx mac_ctx;
	sss_se05x_mac_t md_ctx;
	sss_algorithm_t algorithm;
	size_t digest_len;
	sss_se05x_object_t key_obj;
	uint8_t *cnt;
};

static const struct crypto_mac_ops se050_hmac_ops;

static struct se050_hmac_ctx *to_hmac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &se050_hmac_ops);

	return container_of(ctx, struct se050_hmac_ctx, mac_ctx);
}

static TEE_Result se050_hmac_init(struct crypto_mac_ctx *ctx,
				  const uint8_t *key, size_t len)
{
	struct se050_hmac_ctx *c = to_hmac_ctx(ctx);
	sss_status_t stat = kStatus_SSS_Fail;
	uint32_t oid = 0;

	if (c->key_obj.keyId)
		return TEE_SUCCESS;

	stat = sss_se05x_key_object_init(&c->key_obj, se050_kstore);
	if (stat != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	stat = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (stat != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	stat = sss_se05x_key_object_allocate_handle(&c->key_obj, oid,
						    kSSS_KeyPart_Default,
						    kSSS_CipherType_HMAC,
						    len,
						    kKeyObject_Mode_Transient);
	if (stat != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	stat = sss_se05x_key_store_set_key(se050_kstore,
					   &c->key_obj, key, len, (len * 8),
					   NULL, 0);
	if (stat != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	stat = sss_se05x_mac_context_init(&c->md_ctx, se050_session,
					  &c->key_obj, c->algorithm,
					  kMode_SSS_Mac);
	if (stat != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	stat = sss_se05x_mac_init(&c->md_ctx);
	if (stat != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result se050_hmac_update(struct crypto_mac_ctx *ctx,
				    const uint8_t *data, size_t len)
{
	struct se050_hmac_ctx *c = to_hmac_ctx(ctx);
	sss_status_t status = kStatus_SSS_Fail;

	status = sss_se05x_mac_update(&c->md_ctx, data, len);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result se050_hmac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				   size_t len)
{
	uint8_t block_digest[TEE_MAX_HASH_SIZE] = { 0 };
	struct se050_hmac_ctx *c = to_hmac_ctx(ctx);
	size_t hmac_size = c->digest_len;
	uint8_t *tmp_digest = digest;
	size_t tmp_len = len;
	sss_status_t status = kStatus_SSS_Fail;

	if (!len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hmac_size > len) {
		if (hmac_size > sizeof(block_digest))
			return TEE_ERROR_BAD_STATE;

		tmp_digest = block_digest;
		tmp_len = hmac_size;
	}

	status = sss_se05x_mac_finish(&c->md_ctx, tmp_digest, &tmp_len);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	if (hmac_size > len)
		memcpy(digest, tmp_digest, len);

	return TEE_SUCCESS;
}

static void se050_hmac_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct se050_hmac_ctx *c = to_hmac_ctx(ctx);
	int val = 0;

	val = se050_refcount_final_ctx(c->cnt);
	if (!val)
		goto exit;

	if (c->key_obj.keyId)
		sss_se05x_key_store_erase_key(se050_kstore, &c->key_obj);

	sss_se05x_mac_context_free(&c->md_ctx);
exit:
	free(c);
}

static void se050_hmac_copy_state(struct crypto_mac_ctx *dst_ctx,
				  struct crypto_mac_ctx *src_ctx)
{
	struct se050_hmac_ctx *src = to_hmac_ctx(src_ctx);
	struct se050_hmac_ctx *dst = to_hmac_ctx(dst_ctx);

	se050_refcount_init_ctx(&src->cnt);
	memcpy(dst, src, sizeof(*dst));
}

static const struct crypto_mac_ops se050_hmac_ops = {
	.init = se050_hmac_init,
	.update = se050_hmac_update,
	.final = se050_hmac_final,
	.free_ctx = se050_hmac_free_ctx,
	.copy_state = se050_hmac_copy_state,
};

static TEE_Result se050_hmac_alloc_ctx(struct crypto_mac_ctx **ctx_ret,
				       sss_algorithm_t algorithm,
				       size_t len)
{
	struct se050_hmac_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->mac_ctx.ops = &se050_hmac_ops;
	c->algorithm = algorithm;
	c->digest_len = len;
	*ctx_ret = &c->mac_ctx;

	return TEE_SUCCESS;
}

#if defined(CFG_CRYPTO_SHA1)
TEE_Result crypto_hmac_sha1_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return se050_hmac_alloc_ctx(ctx, kAlgorithm_SSS_HMAC_SHA1,
				    TEE_SHA1_HASH_SIZE);
}
#endif

#if defined(CFG_CRYPTO_SHA256)
TEE_Result crypto_hmac_sha256_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return se050_hmac_alloc_ctx(ctx, kAlgorithm_SSS_HMAC_SHA256,
				    TEE_SHA256_HASH_SIZE);
}
#endif

#if defined(CFG_CRYPTO_SHA384)
TEE_Result crypto_hmac_sha384_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return se050_hmac_alloc_ctx(ctx, kAlgorithm_SSS_HMAC_SHA384,
				    TEE_SHA384_HASH_SIZE);
}
#endif

#if defined(CFG_CRYPTO_SHA512)
TEE_Result crypto_hmac_sha512_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return se050_hmac_alloc_ctx(ctx, kAlgorithm_SSS_HMAC_SHA512,
				    TEE_SHA512_HASH_SIZE);
}
#endif
