/*
 * Copyright (c) 2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <compiler.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"
#include "sks_helpers.h"

uint32_t tee_init_ctr_operation(struct pkcs11_session *session,
				    void *proc_params, size_t params_size)
{
	struct serialargs args;
	uint32_t rv;
	/* CTR parameters */
	uint32_t incr_counter;
	void *counter_bits;

	serialargs_init(&args, proc_params, params_size);

	rv = serialargs_get(&args, &incr_counter, sizeof(uint32_t));
	if (rv)
		goto bail;

	rv = serialargs_get_ptr(&args, &counter_bits, 16);
	if (rv)
		goto bail;

	if (incr_counter != 1) {
		DMSG("Supports only 1 bit increment counter: %d",
						incr_counter);
		rv = SKS_INVALID_PROC_PARAM;
		goto bail;
	}

	TEE_CipherInit(session->tee_op_handle, counter_bits, 16);

	rv = SKS_OK;

bail:
	return rv;
}

void tee_release_ctr_operation(struct pkcs11_session *session __unused)
{
	return;
}

/*
 * Authenticated ciphering: (CCM / GCM)
 *
 * As per PKCS#11, CCM/GCM decrypt shall not revealed the data until the
 * decryption is completed and the mac verified. The SKS TA must retain the
 * ciphered data until the CCM finalization. To do so, arrays of decrypted
 * data are allocated during AE update processing and copied into client
 * buffer at AE finalization.
 *
 * As per PKCS#11, CCM/GCM decrypt expect the tag/mac data to be provided
 * inside the input data for DecryptUpdate() and friends. But the DecryptFinal
 * API does not provide input data reference hence we do not know which is the
 * last call to DecryptUpdate() where last bytes are not ciphered data but the
 * requested tag/mac byte. To handle this, the TA saves the last input data
 * bytes (length is defined by the tag byte size) in the AE context and
 * waits the DecryptFinal() to either treat these as data bytes or tag/mac
 * bytes. Refer to pending_tag and pending_size in struct ae_aes_context.
 */

/*
 * @size - byte size of the allocated buffer
 * @data - pointer to allocated data
 */
struct out_data_ref {
	size_t size;
	void *data;
};

/*
 * @tag_byte_len - tag size in byte
 * @pending_tag - Input data that could be the appended tag
 * @pending_size - Size of pending input data that could be the tag
 * @out_data - Pointer to an array of output data references.
 * @out_count - Number of buffer references in out_data
 */
struct ae_aes_context {
	size_t tag_byte_len;
	char *pending_tag;
	size_t pending_size;
	struct out_data_ref *out_data;
	size_t out_count;
};

static void release_ae_aes_context(struct ae_aes_context *ctx)
{
	size_t n;

	for (n = 0; n < ctx->out_count; n++)
		TEE_Free(ctx->out_data[n].data);

	TEE_Free(ctx->out_data);
	ctx->out_data = NULL;
	ctx->out_count = 0;
}

uint32_t tee_ae_decrypt_update(struct pkcs11_session *session,
			       void *in, size_t in_size)
{
	struct ae_aes_context *ctx = session->proc_params;
	size_t data_len;
	size_t size;
	TEE_Result res;
	uint32_t rv;
	char *ct = NULL;
	size_t ct_size = 0;
	void *ptr;

	if (!in_size)
		return SKS_OK;

	/*
	 * Save the last input bytes in case they are the tag
	 * instead of ciphered data
	 */

	if (ctx->pending_size + in_size <= ctx->tag_byte_len) {
		/*
		 * Data bytes are all potential tag bytes.
		 * We only need to update the pending_tag buffer.
		 */
		TEE_MemMove(ctx->pending_tag + ctx->pending_size, in, in_size);

		ctx->pending_size += in_size;

		return SKS_OK;
	}

	/* Size of data that are not potential tag in pendings and input data */
	data_len = in_size + ctx->pending_size - ctx->tag_byte_len;

	if (ctx->pending_size &&
	    (ctx->pending_size + in_size) >= ctx->tag_byte_len) {
		/* Process pending tag bytes that are effective data byte */
		uint32_t len = MIN(data_len, ctx->pending_size);

		res = TEE_AEUpdate(session->tee_op_handle,
				   ctx->pending_tag, len, NULL, &ct_size);

		assert(res == TEE_ERROR_SHORT_BUFFER ||
		       (res == TEE_SUCCESS && !ct_size));

		if (ct_size) {
			ct = TEE_Malloc(ct_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
			if (!ct) {
				rv = SKS_MEMORY;
				goto bail;
			}

			res = TEE_AEUpdate(session->tee_op_handle,
					   ctx->pending_tag, len, ct, &ct_size);
			if (res) {
				rv = tee2sks_error(res);
				goto bail;
			}
		}

		TEE_MemMove(ctx->pending_tag, ctx->pending_tag + len,
			    ctx->pending_size - len);

		ctx->pending_size -= len;
		data_len -= len;
	}

	if (data_len) {
		/* Process input data that are not potential tag bytes */
		size = 0;
		res = TEE_AEUpdate(session->tee_op_handle,
				   in, data_len, NULL, &size);
		assert(res == TEE_ERROR_SHORT_BUFFER ||
		       (res == TEE_SUCCESS && !size));

		if (size) {
			ptr = TEE_Realloc(ct, ct_size + size);
			if (!ptr) {
				rv = SKS_MEMORY;
				goto bail;
			}
			ct = ptr;

			res = TEE_AEUpdate(session->tee_op_handle,
					   in, data_len, ct + ct_size, &size);
			if (res) {
				rv = tee2sks_error(res);
				goto bail;
			}

			ct_size += size;
		}
	}

	/* Update pending tag in context if any */
	data_len = in_size - data_len;
	assert(data_len <= (ctx->tag_byte_len - ctx->pending_size));

	if (data_len) {
		TEE_MemMove(ctx->pending_tag + ctx->pending_size,
			    (char *)in + in_size - data_len, data_len);

		ctx->pending_size += data_len;
	}

	/* Save output data refernce in the context */
	if (ct_size) {
		ptr = TEE_Realloc(ctx->out_data, (ctx->out_count + 1) *
				  sizeof(struct out_data_ref));
		if (!ptr) {
			rv = SKS_MEMORY;
			goto bail;
		}
		ctx->out_data = ptr;
		ctx->out_data[ctx->out_count].size = ct_size;
		ctx->out_data[ctx->out_count].data = ct;
		ctx->out_count++;
	}

	rv = SKS_OK;

bail:
	if (rv)
		TEE_Free(ct);

	return rv;
}

uint32_t tee_ae_decrypt_final(struct pkcs11_session *session,
			      void *out, size_t *out_size)
{
	struct ae_aes_context *ctx = (struct ae_aes_context *)session->proc_params;
	uint32_t rv;
	TEE_Result res;
	size_t n;
	size_t size;
	void *ptr = NULL;
	size_t out_offs = 0;

	if (!out) {
		DMSG("Expect at least a buffer for the output data");
		return SKS_BAD_PARAM;
	}

	if (ctx->pending_size != ctx->tag_byte_len) {
		DMSG("Not enougth samples: %u/%u",
			ctx->pending_size, ctx->tag_byte_len);
		return SKS_FAILED;	// FIXME: CKR_ENCRYPTED_DATA_LEN_RANGE
	}

	size = 0;
	res = TEE_AEDecryptFinal(session->tee_op_handle,
				 NULL, 0, NULL, &size,
				 ctx->pending_tag, ctx->tag_byte_len);

	if (res == TEE_ERROR_SHORT_BUFFER && size) {
		ptr = TEE_Malloc(size, 0);
		if (!ptr) {
			rv = SKS_MEMORY;
			goto bail;
		}

		res = TEE_AEDecryptFinal(session->tee_op_handle,
					 NULL, 0, ptr, &size,
					 ctx->pending_tag, ctx->tag_byte_len);
	}

	rv = tee2sks_error(res);
	if (rv)
		goto bail;

	for (n = 0; n < ctx->out_count; n++) {
		TEE_MemMove((char *)out + out_offs,
			    ctx->out_data[n].data, ctx->out_data[n].size);

		out_offs += ctx->out_data[n].size;
	}
	TEE_MemMove((char *)out + out_offs, ptr, size);
	out_offs += size;

	*out_size = out_offs;

bail:
	TEE_Free(ptr);

	return rv;
}

uint32_t tee_ae_encrypt_final(struct pkcs11_session *session,
			      void *out, size_t *out_size)
{
	struct ae_aes_context *ctx = (struct ae_aes_context *)session->proc_params;
	TEE_Result res;
	size_t tag_len = 0;
	uint8_t *tag = out;
	size_t size = 0;

	assert(out && out_size);
	if (!out || !out_size)
		TEE_Panic(0);

	/* Check the required sizes (warning: 2 output len: data + tag) */
	res = TEE_AEEncryptFinal(session->tee_op_handle,
				 NULL, 0, NULL, &size,
				 tag, &tag_len);

	if (res != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(0);

	assert(tag_len == ctx->tag_byte_len);

	if (!out && size)
		return SKS_BAD_PARAM;

	if (out && *out_size < (size + tag_len)) {
		*out_size = size + tag_len;
		return SKS_SHORT_BUFFER;
	}

	/* Process data and tag input the client output buffer */
	tag = (uint8_t *)out + size;

	res = TEE_AEEncryptFinal(session->tee_op_handle,
				 NULL, 0, out, &size, tag, &tag_len);

	if (tag_len != ctx->tag_byte_len)
		TEE_Panic(0);

	if (!res)
		*out_size = size + tag_len;

	return tee2sks_error(res);
}

uint32_t tee_init_ccm_operation(struct pkcs11_session *session,
				void *proc_params, size_t params_size)
{
	uint32_t rv;
	struct ae_aes_context *params;
	struct serialargs args;
	/* CCM parameters */
	uint32_t data_len;
	uint32_t nonce_len;
	void *nonce = NULL;
	uint32_t aad_len;
	void *aad = NULL;
	uint32_t mac_len;

	serialargs_init(&args, proc_params, params_size);

	rv = serialargs_get(&args, &data_len, sizeof(uint32_t));
	if (rv)
		goto bail;

	rv = serialargs_get(&args, &nonce_len, sizeof(uint32_t));
	if (rv)
		goto bail;

	// TODO: no need to copy nonce into secure world
	rv = serialargs_alloc_and_get(&args, &nonce, nonce_len);
	if (rv)
		goto bail;

	rv = serialargs_get(&args, &aad_len, sizeof(uint32_t));
	if (rv)
		goto bail;

	// TODO: no need to copy aad into secure world
	rv = serialargs_alloc_and_get(&args, &aad, aad_len);
	if (rv)
		goto bail;

	rv = serialargs_get(&args, &mac_len, sizeof(uint32_t));
	if (rv)
		goto bail;

	params = TEE_Malloc(sizeof(struct ae_aes_context),
			    TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!params) {
		rv = SKS_MEMORY;
		goto bail;
	}

	/* TODO: check data_len in [0 28] */
	/* TODO: check nonce_len in [1 15-L ???] */
	/* TODO: check aad_len: can be null [1 256] */
	/* TODO: check mac_len in {4, 6, 8, 10, 12, 14, 16} */

	params->tag_byte_len = mac_len;
	params->out_data = NULL;
	params->out_count = 0;
	params->pending_size = 0;
	params->pending_tag = TEE_Malloc(mac_len,
					 TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!params->pending_tag) {
		rv = SKS_MEMORY;
		goto bail;
	}

	TEE_AEInit(session->tee_op_handle, nonce, nonce_len, mac_len * 8,
					   aad_len, data_len);
	if (aad_len)
		TEE_AEUpdateAAD(session->tee_op_handle, aad, aad_len);

	/* session owns the active processing params */
	assert(!session->proc_params);
	session->proc_params = params;

	rv = SKS_OK;

bail:
	TEE_Free(nonce);
	TEE_Free(aad);
	if (rv && params) {
		TEE_Free(params->pending_tag);
		TEE_Free(params);
	}
	return rv;
}

void tee_release_ccm_operation(struct pkcs11_session *session)
{
	struct ae_aes_context *ctx = session->proc_params;

	release_ae_aes_context(ctx);
	TEE_Free(session->proc_params);
	session->proc_params = NULL;
}

/*
 * GCM
 */
uint32_t tee_init_gcm_operation(struct pkcs11_session *session,
				    void *proc_params, size_t params_size)
{
	struct serialargs args;
	uint32_t rv;
	uint32_t tag_len;
	struct ae_aes_context *params;
	/* GCM parameters */
	uint32_t iv_len;
	void *iv = NULL;
	uint32_t aad_len;
	void *aad = NULL;
	uint32_t tag_bitlen;

	serialargs_init(&args, proc_params, params_size);

	rv = serialargs_get(&args, &iv_len, sizeof(uint32_t));
	if (rv)
		goto bail;

	// TODO: no need to copy iv into secure world
	rv = serialargs_alloc_and_get(&args, &iv, iv_len);
	if (rv)
		goto bail;

	rv = serialargs_get(&args, &aad_len, sizeof(uint32_t));
	if (rv)
		goto bail;

	// TODO: no need to copy aad into secure world
	rv = serialargs_alloc_and_get(&args, &aad, aad_len);
	if (rv)
		goto bail;

	rv = serialargs_get(&args, &tag_bitlen, sizeof(uint32_t));
	if (rv)
		goto bail;

	tag_len = ROUNDUP(tag_bitlen, 8) / 8;

	params = TEE_Malloc(sizeof(struct ae_aes_context),
			    TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!params) {
		rv = SKS_MEMORY;
		goto bail;
	}

	/* TODO: check tag_bitlen in [0 128] */
	/* TODO: check iv_len in [1 256] */

	/* Store the byte round up byte length for the tag */
	params->tag_byte_len = tag_len;
	params->out_data = NULL;
	params->out_count = 0;
	params->pending_size = 0;
	params->pending_tag = TEE_Malloc(tag_len,
					 TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!params->pending_tag) {
		rv = SKS_MEMORY;
		goto bail;
	}

	/* session owns the active processing params */
	assert(!session->proc_params);
	session->proc_params = params;

	TEE_AEInit(session->tee_op_handle, iv, iv_len, tag_bitlen, 0, 0);

	if (aad_len)
		TEE_AEUpdateAAD(session->tee_op_handle, aad, aad_len);

	rv = SKS_OK;

bail:
	TEE_Free(iv);
	TEE_Free(aad);
	if (rv && params) {
		TEE_Free(params->out_data);
		TEE_Free(params);
	}

	return rv;
}

void tee_release_gcm_operation(struct pkcs11_session *session)
{
	struct ae_aes_context *ctx = session->proc_params;

	release_ae_aes_context(ctx);
	TEE_Free(session->proc_params);
	session->proc_params = NULL;
}
