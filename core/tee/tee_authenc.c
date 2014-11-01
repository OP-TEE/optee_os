/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string_ext.h>
#include <tee/tee_authenc.h>
#include <tee/tee_cipher.h>
#include <tee/tee_mac.h>
#include "tee_ltc_wrapper.h"
#include <kernel/tee_core_trace.h>

#define TEE_CCM_KEY_MAX_LENGTH		32
#define TEE_CCM_NONCE_MAX_LENGTH	13
#define TEE_CCM_TAG_MAX_LENGTH		16
#define TEE_GCM_TAG_MAX_LENGTH		16
#define TEE_xCM_TAG_MAX_LENGTH		16

struct tee_ccm_state {
	ccm_state ctx;			/* the ccm state as defined by LTC */
	size_t tag_len;			/* tag length */
};

struct tee_gcm_state {
	gcm_state ctx;			/* the gcm state as defined by LTC */
	size_t tag_len;			/* tag length */
};

TEE_Result tee_authenc_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_AES_CCM:
		*size = sizeof(struct tee_ccm_state);
		break;
	case TEE_ALG_AES_GCM:
		*size = sizeof(struct tee_gcm_state);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

TEE_Result tee_authenc_init(
	void *ctx, uint32_t algo, TEE_OperationMode mode, const uint8_t *key,
	size_t key_len, const uint8_t *nonce,
	size_t nonce_len, size_t tag_len, size_t aad_len, size_t payload_len)
{
	TEE_Result res;
	int ltc_res;
	int ltc_cipherindex;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;
	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* reset the state */
		ccm = ctx;
		memset(ccm, 0, sizeof(struct tee_ccm_state));
		ccm->tag_len = tag_len;

		/* Check the key length */
		if ((!key) || (key_len > TEE_CCM_KEY_MAX_LENGTH))
			return TEE_ERROR_BAD_PARAMETERS;

		/* check the nonce */
		if (nonce_len > TEE_CCM_NONCE_MAX_LENGTH)
			return TEE_ERROR_BAD_PARAMETERS;

		/* check the tag len */
		if ((tag_len < 4) ||
		    (tag_len > TEE_CCM_TAG_MAX_LENGTH) ||
		    (tag_len % 2 != 0))
			return TEE_ERROR_NOT_SUPPORTED;

		ltc_res = ccm_init(
			&ccm->ctx, ltc_cipherindex,
			key, key_len, payload_len, tag_len, aad_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;

		/* Add the IV */
		ltc_res = ccm_add_nonce(&ccm->ctx, nonce, nonce_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* reset the state */
		gcm = ctx;
		memset(gcm, 0, sizeof(struct tee_gcm_state));
		gcm->tag_len = tag_len;

		ltc_res = gcm_init(
			&gcm->ctx, ltc_cipherindex, key, key_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;

		/* Add the IV */
		ltc_res = gcm_add_iv(&gcm->ctx, nonce, nonce_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_authenc_update_aad(
	void *ctx, uint32_t algo, TEE_OperationMode mode,
	  const uint8_t *data, size_t len)
{
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	int ltc_res;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* Add the AAD (note: aad can be NULL if aadlen == 0) */
		ccm = ctx;
		ltc_res = ccm_add_aad(&ccm->ctx, data, len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* Add the AAD (note: aad can be NULL if aadlen == 0) */
		gcm = ctx;
		ltc_res = gcm_add_aad(&gcm->ctx, data, len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_authenc_update_payload(
	void *ctx, uint32_t algo, TEE_OperationMode mode,
	const uint8_t *src_data, size_t src_len, uint8_t *dst_data)
{
	TEE_Result res;
	int ltc_res, dir;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	unsigned char *pt, *ct;	/* the plain and the cipher text */

	if (mode == TEE_MODE_ENCRYPT) {
		pt = (unsigned char *)src_data;
		ct = dst_data;
	} else {
		pt = dst_data;
		ct = (unsigned char *)src_data;
	}

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = ctx;
		dir = (mode == TEE_MODE_ENCRYPT ? CCM_ENCRYPT : CCM_DECRYPT);
		ltc_res = ccm_process(&ccm->ctx, pt, src_len, ct, dir);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* aad is optional ==> add one without length */
		gcm = ctx;
		if (gcm->ctx.mode == LTC_GCM_MODE_IV) {
			res = tee_authenc_update_aad(gcm, algo, mode, 0, 0);
			if (res != TEE_SUCCESS)
				return res;
		}

		/* process the data */
		dir = (mode == TEE_MODE_ENCRYPT ? GCM_ENCRYPT : GCM_DECRYPT);
		ltc_res = gcm_process(&gcm->ctx, pt, src_len, ct, dir);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_authenc_enc_final(
	void *ctx, uint32_t algo, const uint8_t *src_data,
	size_t src_len, uint8_t *dst_data,
	uint8_t *dst_tag, size_t *dst_tag_len)
{
	TEE_Result res;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	size_t digest_size;
	int ltc_res;

	/* Check the resulting buffer is not too short */
	res = tee_cipher_get_block_size(algo, &digest_size);
	if (res != TEE_SUCCESS)
		return res;

	/* Finalize the remaining buffer */
	res = tee_authenc_update_payload(
		ctx, algo, TEE_MODE_ENCRYPT,
		src_data, src_len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* Check the tag length */
		ccm = ctx;
		if (*dst_tag_len < ccm->tag_len) {
			*dst_tag_len = ccm->tag_len;
			return TEE_ERROR_SHORT_BUFFER;
		}
		*dst_tag_len = ccm->tag_len;

		/* Compute the tag */
		ltc_res = ccm_done(
			&ccm->ctx, dst_tag, (unsigned long *)dst_tag_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* Check the tag length */
		gcm = ctx;
		if (*dst_tag_len < gcm->tag_len) {
			*dst_tag_len = gcm->tag_len;
			return TEE_ERROR_SHORT_BUFFER;
		}
		*dst_tag_len = gcm->tag_len;

		/* Compute the tag */
		ltc_res = gcm_done(
			&gcm->ctx, dst_tag, (unsigned long *)dst_tag_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_authenc_dec_final(
	void *ctx, uint32_t algo, const uint8_t *src_data,
	size_t src_len, uint8_t *dst_data, const uint8_t *tag, size_t tag_len)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	int ltc_res;
	uint8_t dst_tag[TEE_xCM_TAG_MAX_LENGTH];
	size_t dst_len;
	unsigned long ltc_tag_len = tag_len;

	res = tee_cipher_get_block_size(algo, &dst_len);
	if (res != TEE_SUCCESS)
		return res;
	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	if (tag_len > TEE_xCM_TAG_MAX_LENGTH)
		return TEE_ERROR_BAD_STATE;

	/* Process the last buffer, if any */
	res = tee_authenc_update_payload(
			ctx, algo, TEE_MODE_DECRYPT,
			src_data, src_len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* Finalize the authentication */
		ccm = ctx;
		ltc_res = ccm_done(&ccm->ctx, dst_tag, &ltc_tag_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* Finalize the authentication */
		gcm = ctx;
		ltc_res = gcm_done(&gcm->ctx, dst_tag, &ltc_tag_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (buf_compare_ct(dst_tag, tag, tag_len) != 0)
		res = TEE_ERROR_MAC_INVALID;
	else
		res = TEE_SUCCESS;
	return res;
}

void tee_authenc_final(void *ctx, uint32_t algo)
{
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = ctx;
		ccm_reset(&ccm->ctx);
		break;

	case TEE_ALG_AES_GCM:
		gcm = ctx;
		gcm_reset(&gcm->ctx);
		break;
	default:
		break;
	}
}
