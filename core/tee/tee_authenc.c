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

/*
 * From Libtomcrypt documentation
 * CCM is a NIST proposal for encrypt + authenticate that is centered around
 * using AES (or any 16-byte cipher) as a primitive.  Unlike EAX and OCB mode,
 * it is only meant for packet  mode where the length of the input is known in
 * advance. Since it is a packet mode function, CCM only has one function that
 * performs the protocol
 */

#define TEE_CCM_KEY_MAX_LENGTH		32
#define TEE_CCM_NONCE_MAX_LENGTH	13
#define TEE_CCM_TAG_MAX_LENGTH		16
#define TEE_GCM_TAG_MAX_LENGTH		16
#define TEE_xCM_TAG_MAX_LENGTH		16

struct tee_ccm_state {
	uint8_t key[TEE_CCM_KEY_MAX_LENGTH];		/* the key */
	size_t key_len;					/* the key length */
	uint8_t nonce[TEE_CCM_NONCE_MAX_LENGTH];	/* the nonce */
	size_t nonce_len;			/* nonce length */
	uint8_t tag[TEE_CCM_TAG_MAX_LENGTH];	/* computed tag on last data */
	size_t tag_len;			/* tag length */
	size_t aad_len;
	size_t payload_len;		/* final expected payload length */
	uint8_t *payload;		/* the payload */
	size_t current_payload_len;	/* the current payload length */
	uint8_t *res_payload;		/* result with the whole payload */
	int ltc_cipherindex;		/* the libtomcrypt cipher index */
	uint8_t *header;		/* the header (aad) */
	size_t header_len;		/* header length */
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
	unsigned char *payload, *res_payload;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;
	switch (algo) {
	case TEE_ALG_AES_CCM:
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

		/* allocate payload */
		payload = malloc(payload_len + TEE_CCM_KEY_MAX_LENGTH);
		if (!payload)
			return TEE_ERROR_OUT_OF_MEMORY;
		res_payload = malloc(payload_len + TEE_CCM_KEY_MAX_LENGTH);
		if (!res_payload) {
			free(payload);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		/* initialize the structure */
		ccm = ctx;
		memset(ccm, 0, sizeof(struct tee_ccm_state));
		memcpy(ccm->key, key, key_len);
		ccm->key_len = key_len;			/* the key length */
		if (nonce && nonce_len) {
			memcpy(ccm->nonce, nonce, nonce_len);
			ccm->nonce_len = nonce_len;
		} else {
			ccm->nonce_len = 0;
		}
		ccm->tag_len = tag_len;
		ccm->aad_len = aad_len;
		ccm->payload_len = payload_len;
		ccm->payload = payload;
		ccm->res_payload = res_payload;
		ccm->ltc_cipherindex = ltc_cipherindex;

		if (ccm->aad_len) {
			ccm->header = malloc(ccm->aad_len);
			if (!ccm->header) {
				free(payload);
				free(res_payload);
				return TEE_ERROR_OUT_OF_MEMORY;
			}
		}

		/* memset the payload to 0 that will be used for padding */
		memset(ccm->payload, 0, payload_len + TEE_CCM_KEY_MAX_LENGTH);
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
		ccm = ctx;
		if (ccm->aad_len < ccm->header_len + len)
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(ccm->header + ccm->header_len, data, len);
		ccm->header_len += len;
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
		/* Check aad has been correctly added */
		ccm = ctx;
		if (ccm->aad_len != ccm->header_len)
			return TEE_ERROR_BAD_STATE;

		/*
		 * check we do not add more data than what was defined at
		 * the init
		 */
		if (ccm->current_payload_len + src_len > ccm->payload_len)
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(ccm->payload + ccm->current_payload_len,
		       src_data, src_len);
		ccm->current_payload_len += src_len;

		dir = (mode == TEE_MODE_ENCRYPT ? CCM_ENCRYPT : CCM_DECRYPT);
		ltc_res = ccm_memory(
			ccm->ltc_cipherindex,
			ccm->key, ccm->key_len,
			0,	/* not presecheduled */
			ccm->nonce,  ccm->nonce_len,
			ccm->header, ccm->header_len,
			pt, src_len, ct,
			ccm->tag, (unsigned long *)&ccm->tag_len, dir);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* aad is optional ==> add one without length */
		gcm = ctx;
		if (gcm->ctx.mode == LTC_GCM_MODE_IV) {
			res = tee_authenc_update_aad(
					&gcm->ctx, algo, mode, 0, 0);
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
	TEE_Result res, final_res = TEE_ERROR_MAC_INVALID;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	size_t digest_size;
	int ltc_res;
	int init_len;

	/* Check the resulting buffer is not too short */
	res = tee_cipher_get_block_size(algo, &digest_size);
	if (res != TEE_SUCCESS) {
		final_res = res;
		goto out;
	}

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = ctx;

		init_len = ccm->current_payload_len;
		if (src_len) {
			memcpy(ccm->payload + ccm->current_payload_len,
			       src_data, src_len);
			ccm->current_payload_len += src_len;
		}

		if (ccm->payload_len != ccm->current_payload_len)
			return TEE_ERROR_BAD_PARAMETERS;

		if (*dst_tag_len < ccm->tag_len) {
			*dst_tag_len = ccm->tag_len;
			return TEE_ERROR_SHORT_BUFFER;
		}
		*dst_tag_len = ccm->tag_len;

		ltc_res = ccm_memory(
			ccm->ltc_cipherindex,
			ccm->key, ccm->key_len,
			0,	/* not previously scheduled */
			ccm->nonce,  ccm->nonce_len,
			ccm->header, ccm->header_len,
			ccm->payload, ccm->current_payload_len,
			ccm->res_payload,
			dst_tag, (unsigned long *)dst_tag_len, CCM_ENCRYPT);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		if (src_len)
			memcpy(dst_data, ccm->res_payload + init_len, src_len);
		break;

	case TEE_ALG_AES_GCM:
		/* Finalize the remaining buffer */
		gcm = ctx;
		res = tee_authenc_update_payload(
			&gcm->ctx, algo, TEE_MODE_ENCRYPT,
			src_data, src_len, dst_data);
		if (res != TEE_SUCCESS) {
			final_res = res;
			goto out;
		}

		if (*dst_tag_len < gcm->tag_len) {
			*dst_tag_len = gcm->tag_len;
			return TEE_ERROR_SHORT_BUFFER;
		}
		*dst_tag_len = gcm->tag_len;

		/* Process the last buffer, if any */
		ltc_res = gcm_done(
			&gcm->ctx,
			dst_tag, (unsigned long *)dst_tag_len);
		if (ltc_res != CRYPT_OK)
			goto out;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	final_res = TEE_SUCCESS;

out:
	return final_res;
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
	size_t dst_len, init_len;

	res = tee_cipher_get_block_size(algo, &dst_len);
	if (res != TEE_SUCCESS)
		return res;
	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	if (tag_len > TEE_xCM_TAG_MAX_LENGTH)
		return TEE_ERROR_BAD_STATE;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = ctx;

		init_len = ccm->current_payload_len;
		if (src_len) {
			memcpy(ccm->payload + ccm->current_payload_len,
			       src_data, src_len);
			ccm->current_payload_len += src_len;
		}

		if (ccm->payload_len != ccm->current_payload_len)
			return TEE_ERROR_BAD_PARAMETERS;

		ltc_res = ccm_memory(
			ccm->ltc_cipherindex,
			ccm->key, ccm->key_len,
			0,	/* not previously scheduled */
			ccm->nonce,  ccm->nonce_len,
			ccm->header, ccm->header_len,
			ccm->res_payload,
			ccm->current_payload_len, ccm->payload,
			dst_tag, (unsigned long *)&tag_len, CCM_DECRYPT);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;

		if (src_len)
			memcpy(dst_data, ccm->res_payload + init_len, src_len);
		break;


	case TEE_ALG_AES_GCM:
		/* Process the last buffer, if any */
		gcm = ctx;
		res = tee_authenc_update_payload(
			&gcm->ctx, algo, TEE_MODE_DECRYPT,
			src_data, src_len, dst_data);
		if (res != TEE_SUCCESS)
			return res;

		/* Finalize the authentication */
		ltc_res = gcm_done(
				&gcm->ctx, dst_tag, (unsigned long *)&tag_len);
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
		free(ccm->payload);
		free(ccm->res_payload);
		free(ccm->header);
		memset(ccm, 0, sizeof(struct tee_ccm_state));
		break;
	case TEE_ALG_AES_GCM:
		gcm = ctx;
		gcm_reset(&gcm->ctx);
		break;
	default:
		break;
	}
}
