// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <util.h>

#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

/*
 * Authenticated ciphering: (AES GCM)
 *
 * As per PKCS#11, GCM decryption shall not reveal the data until the
 * decryption is completed and the MAC verified. The pkcs11 TA retains the
 * ciphered data until the operation is completed. Therefore every chunk of
 * decrypted data is saved in a allocated buffer during AE update processing
 * and only copied into the client's output buffer at AE finalization when
 * tag is authenticated.
 *
 * As per PKCS#11, GCM decryption expect the tag data to be provided
 * inside the input data for C_DecryptUpdate() and friends, appended to the
 * input encyprted data hence we do not know which is the last call to
 * C_DecryptUpdate() where last bytes are not ciphered data but the requested
 * tag bytes for message autehntication. To handle this, the TA saves
 * the last input data bytes (length is defined by the tag byte size) in the
 * AE context and waits the C_DecryptFinal() to either treat these as data
 * bytes or tag/MAC bytes. Refer to pending_tag and pending_size in struct
 * ae_aes_context.
 */

/*
 * struct out_data_ref - AE decyrption output data chunks
 * @size - byte size of the allocated buffer
 * @data - pointer to allocated data
 */
struct out_data_ref {
	size_t size;
	void *data;
};

/*
 * struct ae_aes_context - Extra context data got AE operations
 * @tag_byte_len - Tag size in byte
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

static enum pkcs11_rc init_ae_aes_context(struct ae_aes_context *ctx)
{
	struct out_data_ref *out_data = NULL;
	char *pending_tag = NULL;

	assert(!ctx->out_data && !ctx->out_count &&
	       !ctx->pending_tag && !ctx->pending_size);

	out_data = TEE_Malloc(sizeof(*out_data), TEE_MALLOC_FILL_ZERO);
	pending_tag = TEE_Malloc(ctx->tag_byte_len, TEE_MALLOC_FILL_ZERO);

	if (!out_data || !pending_tag) {
		TEE_Free(out_data);
		TEE_Free(pending_tag);
		return PKCS11_CKR_DEVICE_MEMORY;
	}

	ctx->pending_tag = pending_tag;
	ctx->out_data = out_data;

	return PKCS11_CKR_OK;
}

static void release_ae_aes_context(struct ae_aes_context *ctx)
{
	size_t n = 0;

	for (n = 0; n < ctx->out_count; n++)
		TEE_Free(ctx->out_data[n].data);

	TEE_Free(ctx->out_data);
	ctx->out_data = NULL;
	ctx->out_count = 0;

	TEE_Free(ctx->pending_tag);
	ctx->pending_tag = NULL;
	ctx->pending_size = 0;
}

/*
 * This function feeds the AE decryption processing with client
 * input data. There are 2 constraints to consider.
 *
 * Firstly we don't know yet which are the ciphered data and which are
 * the tag data. GP TEE Internal API function requires we split data and
 * tag when TEE_AEDecryptFinal() will be called.
 *
 * Secondly any generated data must be kept in the TA and only revealed
 * once tag if succefully processed.
 */
enum pkcs11_rc tee_ae_decrypt_update(struct pkcs11_session *session,
				     void *in, size_t in_size)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;
	TEE_Result res = TEE_ERROR_GENERIC;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t data_len = 0;
	size_t ct_size = 0;
	void *ptr = NULL;
	char *ct = NULL;

	if (!in_size)
		return PKCS11_CKR_OK;

	if (!in)
		return PKCS11_CKR_ARGUMENTS_BAD;

	/*
	 * Save the last input bytes in case they are the tag
	 * bytes and not ciphered data bytes to be decrypted.
	 */

	if (ctx->pending_size + in_size <= ctx->tag_byte_len) {
		/*
		 * Data bytes are all potential tag bytes.
		 * We only need to update the pending_tag buffer,
		 * and cannot treat any byte as data byte.
		 */
		TEE_MemMove(ctx->pending_tag + ctx->pending_size, in, in_size);

		ctx->pending_size += in_size;

		return PKCS11_CKR_OK;
	}

	/* Size of data that are not potential tag in pending and input data */
	data_len = in_size + ctx->pending_size - ctx->tag_byte_len;

	/* Process pending bytes that are effective data byte */
	if (ctx->pending_size &&
	    (ctx->pending_size + in_size) >= ctx->tag_byte_len) {
		uint32_t len = MIN(data_len, ctx->pending_size);

		res = TEE_AEUpdate(session->processing->tee_op_handle,
				   ctx->pending_tag, len, NULL, &ct_size);
		if (res && res != TEE_ERROR_SHORT_BUFFER) {
			rc = tee2pkcs_error(res);
			goto out;
		}
		assert(res == TEE_ERROR_SHORT_BUFFER || !ct_size);

		/*
		 * If output data to store (not revealed yet), redo with
		 * an allocated temporary reference.
		 */
		if (ct_size) {
			ct = TEE_Malloc(ct_size, TEE_MALLOC_FILL_ZERO);
			if (!ct) {
				rc = PKCS11_CKR_DEVICE_MEMORY;
				goto out;
			}

			res = TEE_AEUpdate(session->processing->tee_op_handle,
					   ctx->pending_tag, len, ct, &ct_size);
			if (res) {
				rc = tee2pkcs_error(res);
				goto out;
			}
			assert(ct_size);
		}

		/* Save potential tag bytes for later */
		TEE_MemMove(ctx->pending_tag, ctx->pending_tag + len,
			    ctx->pending_size - len);

		ctx->pending_size -= len;
		data_len -= len;
	}

	/* Process input data that are not potential tag bytes */
	if (data_len) {
		size_t size = 0;

		res = TEE_AEUpdate(session->processing->tee_op_handle,
				   in, data_len, NULL, &size);
		if (res != TEE_ERROR_SHORT_BUFFER &&
		    (res != TEE_SUCCESS || size)) {
			/* This is not expected */
			rc = PKCS11_CKR_GENERAL_ERROR;
			goto out;
		}

		if (size) {
			ptr = TEE_Realloc(ct, ct_size + size);
			if (!ptr) {
				rc = PKCS11_CKR_DEVICE_MEMORY;
				goto out;
			}
			ct = ptr;

			res = TEE_AEUpdate(session->processing->tee_op_handle,
					   in, data_len, ct + ct_size, &size);
			if (res) {
				rc = tee2pkcs_error(res);
				goto out;
			}

			ct_size += size;
		}
	}

	/* Update pending tag in context if any */
	data_len = in_size - data_len;
	if (data_len > (ctx->tag_byte_len - ctx->pending_size)) {
		/* This is not expected */
		rc = PKCS11_CKR_GENERAL_ERROR;
		goto out;
	}

	if (data_len) {
		TEE_MemMove(ctx->pending_tag + ctx->pending_size,
			    (char *)in + in_size - data_len, data_len);

		ctx->pending_size += data_len;
	}

	/* Save output data reference in the context */
	if (ct_size) {
		ptr = TEE_Realloc(ctx->out_data, (ctx->out_count + 1) *
				  sizeof(struct out_data_ref));
		if (!ptr) {
			rc = PKCS11_CKR_DEVICE_MEMORY;
			goto out;
		}
		ctx->out_data = ptr;
		ctx->out_data[ctx->out_count].size = ct_size;
		ctx->out_data[ctx->out_count].data = ct;
		ctx->out_count++;
	}

	rc = PKCS11_CKR_OK;

out:
	if (rc)
		TEE_Free(ct);

	return rc;
}

static enum pkcs11_rc reveal_ae_data(struct ae_aes_context *ctx,
				     void *out, size_t *out_size)
{
	uint32_t req_size = 0;
	char *out_ptr = out;
	size_t n = 0;

	for (req_size = 0, n = 0; n < ctx->out_count; n++)
		req_size += ctx->out_data[n].size;

	if (*out_size < req_size) {
		*out_size = req_size;
		return PKCS11_CKR_BUFFER_TOO_SMALL;
	}

	if (!out_ptr)
		return PKCS11_CKR_ARGUMENTS_BAD;

	for (n = 0; n < ctx->out_count; n++) {
		TEE_MemMove(out_ptr, ctx->out_data[n].data,
			    ctx->out_data[n].size);
		out_ptr += ctx->out_data[n].size;
	}

	release_ae_aes_context(ctx);

	*out_size = req_size;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc tee_ae_decrypt_final(struct pkcs11_session *session,
				    void *out, size_t *out_size)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;
	TEE_Result res = TEE_ERROR_GENERIC;
	enum pkcs11_rc rc = 0;
	void *data_ptr = NULL;
	size_t data_size = 0;

	if (!out_size) {
		DMSG("Expect at least a buffer for the output data");
		return PKCS11_CKR_ARGUMENTS_BAD;
	}

	/* Final is already completed, only need to output the data */
	if (!ctx->pending_tag)
		return reveal_ae_data(ctx, out, out_size);

	if (ctx->pending_size != ctx->tag_byte_len) {
		DMSG("Not enough samples: %zu/%zu",
		     ctx->pending_size, ctx->tag_byte_len);
		return PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	/* Query tag size if any */
	data_size = 0;
	res = TEE_AEDecryptFinal(session->processing->tee_op_handle,
				 NULL, 0, NULL, &data_size,
				 ctx->pending_tag, ctx->tag_byte_len);

	if (res == TEE_ERROR_SHORT_BUFFER) {
		data_ptr = TEE_Malloc(data_size, TEE_MALLOC_FILL_ZERO);
		if (!data_ptr) {
			rc = PKCS11_CKR_DEVICE_MEMORY;
			goto out;
		}

		res = TEE_AEDecryptFinal(session->processing->tee_op_handle,
					 NULL, 0, data_ptr, &data_size,
					 ctx->pending_tag, ctx->tag_byte_len);
		assert(res || data_size);
	}

	/* AE decryption is completed */
	TEE_Free(ctx->pending_tag);
	ctx->pending_tag = NULL;

	rc = tee2pkcs_error(res);
	if (rc)
		goto out;

	if (data_ptr) {
		void *tmp_ptr = NULL;

		tmp_ptr = TEE_Realloc(ctx->out_data, (ctx->out_count + 1) *
				sizeof(struct out_data_ref));
		if (!tmp_ptr) {
			rc = PKCS11_CKR_DEVICE_MEMORY;
			goto out;
		}
		ctx->out_data = tmp_ptr;
		ctx->out_data[ctx->out_count].size = data_size;
		ctx->out_data[ctx->out_count].data = data_ptr;
		ctx->out_count++;

		data_ptr = NULL;
	}

	rc = reveal_ae_data(ctx, out, out_size);

out:
	TEE_Free(data_ptr);

	return rc;
}

enum pkcs11_rc tee_ae_encrypt_final(struct pkcs11_session *session,
				    void *out, size_t *out_size)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tag = NULL;
	size_t tag_len = 0;
	size_t size = 0;

	if (!out || !out_size)
		return PKCS11_CKR_ARGUMENTS_BAD;

	/* Check the required sizes (warning: 2 output len: data + tag) */
	res = TEE_AEEncryptFinal(session->processing->tee_op_handle,
				 NULL, 0, NULL, &size,
				 &tag, &tag_len);

	if (tag_len != ctx->tag_byte_len ||
	    (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER)) {
		EMSG("Unexpected tag length %zu/%zu or rc 0x%" PRIx32,
		     tag_len, ctx->tag_byte_len, res);
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (*out_size < size + tag_len) {
		*out_size = size + tag_len;
		return PKCS11_CKR_BUFFER_TOO_SMALL;
	}

	/* Process data and tag input the client output buffer */
	tag = (uint8_t *)out + size;

	res = TEE_AEEncryptFinal(session->processing->tee_op_handle,
				 NULL, 0, out, &size, tag, &tag_len);

	if (tag_len != ctx->tag_byte_len) {
		EMSG("Unexpected tag length");
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (!res)
		*out_size = size + tag_len;

	return tee2pkcs_error(res);
}

enum pkcs11_rc tee_init_ctr_operation(struct active_processing *processing,
				      void *proc_params, size_t params_size)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	/* CTR parameters */
	uint32_t incr_counter = 0;
	void *counter_bits = NULL;

	if (!proc_params)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&args, proc_params, params_size);

	rc = serialargs_get(&args, &incr_counter, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &counter_bits, 16);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (incr_counter != 1) {
		DMSG("Supports only 1 bit increment counter: %"PRIu32,
		     incr_counter);

		return PKCS11_CKR_MECHANISM_PARAM_INVALID;
	}

	TEE_CipherInit(processing->tee_op_handle, counter_bits, 16);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc tee_init_gcm_operation(struct pkcs11_session *session,
				      void *proc_params, size_t params_size)
{
	struct ae_aes_context *params = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs args = { };
	/* GCM parameters */
	uint32_t tag_bitlen = 0;
	uint32_t tag_len = 0;
	uint32_t iv_len = 0;
	void *iv = NULL;
	uint32_t aad_len = 0;
	void *aad = NULL;

	TEE_MemFill(&args, 0, sizeof(args));

	if (!proc_params)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&args, proc_params, params_size);

	rc = serialargs_get(&args, &iv_len, sizeof(uint32_t));
	if (rc)
		goto out;

	rc = serialargs_get_ptr(&args, &iv, iv_len);
	if (rc)
		goto out;

	rc = serialargs_get(&args, &aad_len, sizeof(uint32_t));
	if (rc)
		goto out;

	rc = serialargs_get_ptr(&args, &aad, aad_len);
	if (rc)
		goto out;

	rc = serialargs_get(&args, &tag_bitlen, sizeof(uint32_t));
	if (rc)
		goto out;

	tag_len = ROUNDUP(tag_bitlen, 8) / 8;

	/* As per pkcs#11 mechanism specification */
	if (tag_bitlen > 128 || !iv_len || iv_len > 256) {
		DMSG("Invalid parameters: tag_bit_len %"PRIu32
		     ", iv_len %"PRIu32, tag_bitlen, iv_len);
		rc = PKCS11_CKR_MECHANISM_PARAM_INVALID;
		goto out;
	}

	params = TEE_Malloc(sizeof(*params), TEE_MALLOC_FILL_ZERO);
	if (!params) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto out;
	}

	/* Store the byte round up byte length for the tag */
	params->tag_byte_len = tag_len;
	rc = init_ae_aes_context(params);
	if (rc)
		goto out;

	/* Session processing owns the active processing params */
	assert(!session->processing->extra_ctx);
	session->processing->extra_ctx = params;

	TEE_AEInit(session->processing->tee_op_handle,
		   iv, iv_len, tag_bitlen, 0, 0);

	if (aad_len)
		TEE_AEUpdateAAD(session->processing->tee_op_handle,
				aad, aad_len);

	/*
	 * Save initialized operation state to reset to this state
	 * on one-shot AE request that queries its output buffer size.
	 */
	TEE_CopyOperation(session->processing->tee_op_handle2,
			  session->processing->tee_op_handle);

	rc = PKCS11_CKR_OK;

out:
	if (rc && params) {
		release_ae_aes_context(params);
		TEE_Free(params);
	}

	return rc;
}

/* Release extra resources related to the GCM processing*/
void tee_release_gcm_operation(struct pkcs11_session *session)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;

	release_ae_aes_context(ctx);
	TEE_Free(session->processing->extra_ctx);
	session->processing->extra_ctx = NULL;
}

/* Reset processing state to the state it was after initialization */
enum pkcs11_rc tee_ae_reinit_gcm_operation(struct pkcs11_session *session)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;

	TEE_CopyOperation(session->processing->tee_op_handle,
			  session->processing->tee_op_handle2);

	release_ae_aes_context(ctx);

	return init_ae_aes_context(ctx);
}
