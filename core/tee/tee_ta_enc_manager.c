// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <kernel/tee_common_otp.h>
#include <string_ext.h>
#include <tee/tee_ta_enc_manager.h>
#include <trace.h>

TEE_Result tee_ta_decrypt_init(void **enc_ctx, struct shdr_encrypted_ta *ehdr,
			       size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t key[TEE_TA_ENC_KEY_SIZE] = {0};

	res = crypto_authenc_alloc_ctx(enc_ctx, ehdr->enc_algo);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_otp_get_ta_enc_key(ehdr->flags & SHDR_ENC_KEY_TYPE_MASK,
				     key, sizeof(key));
	if (res != TEE_SUCCESS)
		goto out_init;

	res = crypto_authenc_init(*enc_ctx, TEE_MODE_DECRYPT, key, sizeof(key),
				  SHDR_ENC_GET_IV(ehdr), ehdr->iv_size,
				  ehdr->tag_size, 0, len);

out_init:
	if (res != TEE_SUCCESS)
		crypto_authenc_free_ctx(*enc_ctx);

	memzero_explicit(key, sizeof(key));
	return res;
}

TEE_Result tee_ta_decrypt_update(void *enc_ctx, uint8_t *dst, uint8_t *src,
				 size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	size_t dlen = len;

	res = crypto_authenc_update_payload(enc_ctx, TEE_MODE_DECRYPT, src, len,
					    dst, &dlen);
	if (res != TEE_SUCCESS)
		crypto_authenc_free_ctx(enc_ctx);

	return res;
}

TEE_Result tee_ta_decrypt_final(void *enc_ctx, struct shdr_encrypted_ta *ehdr,
				uint8_t *dst, uint8_t *src, size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	size_t dlen = len;

	res = crypto_authenc_dec_final(enc_ctx, src, len, dst, &dlen,
				       SHDR_ENC_GET_TAG(ehdr), ehdr->tag_size);

	crypto_authenc_free_ctx(enc_ctx);

	return res;
}
