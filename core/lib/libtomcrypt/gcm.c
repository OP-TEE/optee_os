// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <tomcrypt_private.h>
#include <util.h>

#define TEE_GCM_TAG_MAX_LENGTH		16

struct tee_gcm_state {
	struct crypto_authenc_ctx aectx;
	gcm_state ctx;			/* the gcm state as defined by LTC */
	size_t tag_len;			/* tag length */
};

static const struct crypto_authenc_ops aes_gcm_ops;

static struct tee_gcm_state *to_tee_gcm_state(struct crypto_authenc_ctx *aectx)
{
	assert(aectx && aectx->ops == &aes_gcm_ops);

	return container_of(aectx, struct tee_gcm_state, aectx);
}

TEE_Result crypto_aes_gcm_alloc_ctx(struct crypto_authenc_ctx **ctx_ret)
{
	struct tee_gcm_state *ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;
	ctx->aectx.ops = &aes_gcm_ops;

	*ctx_ret = &ctx->aectx;

	return TEE_SUCCESS;
}

static void crypto_aes_gcm_free_ctx(struct crypto_authenc_ctx *aectx)
{
	free(to_tee_gcm_state(aectx));
}

static void crypto_aes_gcm_copy_state(struct crypto_authenc_ctx *dst_aectx,
				      struct crypto_authenc_ctx *src_aectx)
{
	struct tee_gcm_state *dst_ctx = to_tee_gcm_state(dst_aectx);
	struct tee_gcm_state *src_ctx = to_tee_gcm_state(src_aectx);

	dst_ctx->ctx = src_ctx->ctx;
	dst_ctx->tag_len = src_ctx->tag_len;
}

static TEE_Result crypto_aes_gcm_init(struct crypto_authenc_ctx *aectx,
				      TEE_OperationMode mode __unused,
				      const uint8_t *key, size_t key_len,
				      const uint8_t *nonce, size_t nonce_len,
				      size_t tag_len, size_t aad_len __unused,
				      size_t payload_len __unused)
{
	int ltc_res = 0;
	int ltc_cipherindex = find_cipher("aes");
	struct tee_gcm_state *gcm = to_tee_gcm_state(aectx);

	if (ltc_cipherindex < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	/* reset the state */
	memset(&gcm->ctx, 0, sizeof(gcm->ctx));
	gcm->tag_len = tag_len;

	ltc_res = gcm_init(&gcm->ctx, ltc_cipherindex, key, key_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	/* Add the IV */
	ltc_res = gcm_add_iv(&gcm->ctx, nonce, nonce_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result crypto_aes_gcm_update_aad(struct crypto_authenc_ctx *aectx,
					    const uint8_t *data, size_t len)
{
	struct tee_gcm_state *gcm = to_tee_gcm_state(aectx);
	int ltc_res = 0;

	/* Add the AAD (note: aad can be NULL if aadlen == 0) */
	ltc_res = gcm_add_aad(&gcm->ctx, data, len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result
crypto_aes_gcm_update_payload(struct crypto_authenc_ctx *aectx,
			      TEE_OperationMode mode, const uint8_t *src_data,
			      size_t len, uint8_t *dst_data)
{
	TEE_Result res = TEE_SUCCESS;
	int ltc_res = 0;
	int dir = 0;
	struct tee_gcm_state *gcm = to_tee_gcm_state(aectx);
	unsigned char *pt = NULL;
	unsigned char *ct = NULL;

	if (mode == TEE_MODE_ENCRYPT) {
		pt = (unsigned char *)src_data;
		ct = dst_data;
		dir = GCM_ENCRYPT;
	} else {
		pt = dst_data;
		ct = (unsigned char *)src_data;
		dir = GCM_DECRYPT;
	}

	/* aad is optional ==> add one without length */
	if (gcm->ctx.mode == LTC_GCM_MODE_IV) {
		res = crypto_aes_gcm_update_aad(aectx, NULL, 0);
		if (res != TEE_SUCCESS)
			return res;
	}

	/* process the data */
	ltc_res = gcm_process(&gcm->ctx, pt, len, ct, dir);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result crypto_aes_gcm_enc_final(struct crypto_authenc_ctx *aectx,
					   const uint8_t *src_data, size_t len,
					   uint8_t *dst_data, uint8_t *dst_tag,
					   size_t *dst_tag_len)
{
	TEE_Result res = TEE_SUCCESS;
	struct tee_gcm_state *gcm = to_tee_gcm_state(aectx);
	int ltc_res = 0;

	/* Finalize the remaining buffer */
	res = crypto_aes_gcm_update_payload(aectx, TEE_MODE_ENCRYPT, src_data,
					    len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Check the tag length */
	if (*dst_tag_len < gcm->tag_len) {
		*dst_tag_len = gcm->tag_len;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*dst_tag_len = gcm->tag_len;

	/* Compute the tag */
	ltc_res = gcm_done(&gcm->ctx, dst_tag, (unsigned long *)dst_tag_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result crypto_aes_gcm_dec_final(struct crypto_authenc_ctx *aectx,
					   const uint8_t *src_data, size_t len,
					   uint8_t *dst_data,
					   const uint8_t *tag, size_t tag_len)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct tee_gcm_state *gcm = to_tee_gcm_state(aectx);
	int ltc_res = 0;
	uint8_t dst_tag[TEE_GCM_TAG_MAX_LENGTH] = { 0 };
	unsigned long ltc_tag_len = tag_len;

	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	if (tag_len > TEE_GCM_TAG_MAX_LENGTH)
		return TEE_ERROR_BAD_STATE;

	/* Process the last buffer, if any */
	res = crypto_aes_gcm_update_payload(aectx, TEE_MODE_DECRYPT, src_data,
					    len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Finalize the authentication */
	ltc_res = gcm_done(&gcm->ctx, dst_tag, &ltc_tag_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	if (consttime_memcmp(dst_tag, tag, tag_len) != 0)
		res = TEE_ERROR_MAC_INVALID;
	else
		res = TEE_SUCCESS;
	return res;
}

static void crypto_aes_gcm_final(struct crypto_authenc_ctx *aectx)
{
	gcm_reset(&to_tee_gcm_state(aectx)->ctx);
}

static const struct crypto_authenc_ops aes_gcm_ops = {
	.init = crypto_aes_gcm_init,
	.update_aad = crypto_aes_gcm_update_aad,
	.update_payload = crypto_aes_gcm_update_payload,
	.enc_final = crypto_aes_gcm_enc_final,
	.dec_final = crypto_aes_gcm_dec_final,
	.final = crypto_aes_gcm_final,
	.free_ctx = crypto_aes_gcm_free_ctx,
	.copy_state = crypto_aes_gcm_copy_state,
};
