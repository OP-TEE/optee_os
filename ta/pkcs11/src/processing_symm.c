// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>
#include <util.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

bool processing_is_tee_symm(enum pkcs11_mechanism_id proc_id)
{
	switch (proc_id) {
	/* Authentication */
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	/* Cipherering */
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
		return true;
	default:
		return false;
	}
}

static enum pkcs11_rc
pkcs2tee_algorithm(uint32_t *tee_id, struct pkcs11_attribute_head *proc_params)
{
	static const struct {
		enum pkcs11_mechanism_id mech_id;
		uint32_t tee_id;
	} pkcs2tee_algo[] = {
		/* AES flavors */
		{ PKCS11_CKM_AES_ECB, TEE_ALG_AES_ECB_NOPAD },
		{ PKCS11_CKM_AES_CBC, TEE_ALG_AES_CBC_NOPAD },
		{ PKCS11_CKM_AES_CBC_PAD, TEE_ALG_AES_CBC_NOPAD },
		{ PKCS11_CKM_AES_CTR, TEE_ALG_AES_CTR },
		{ PKCS11_CKM_AES_CTS, TEE_ALG_AES_CTS },
		/* HMAC flavors */
		{ PKCS11_CKM_MD5_HMAC, TEE_ALG_HMAC_MD5 },
		{ PKCS11_CKM_SHA_1_HMAC, TEE_ALG_HMAC_SHA1 },
		{ PKCS11_CKM_SHA224_HMAC, TEE_ALG_HMAC_SHA224 },
		{ PKCS11_CKM_SHA256_HMAC, TEE_ALG_HMAC_SHA256 },
		{ PKCS11_CKM_SHA384_HMAC, TEE_ALG_HMAC_SHA384 },
		{ PKCS11_CKM_SHA512_HMAC, TEE_ALG_HMAC_SHA512 },
	};
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(pkcs2tee_algo); n++) {
		if (proc_params->id == pkcs2tee_algo[n].mech_id) {
			*tee_id = pkcs2tee_algo[n].tee_id;
			return PKCS11_CKR_OK;
		}
	}

	return PKCS11_RV_NOT_IMPLEMENTED;
}

static enum pkcs11_rc pkcs2tee_key_type(uint32_t *tee_type,
					struct pkcs11_object *obj)
{
	static const struct {
		enum pkcs11_key_type key_type;
		uint32_t tee_id;
	} pkcs2tee_key_type[] = {
		{ PKCS11_CKK_AES, TEE_TYPE_AES },
		{ PKCS11_CKK_GENERIC_SECRET, TEE_TYPE_GENERIC_SECRET },
		{ PKCS11_CKK_MD5_HMAC, TEE_TYPE_HMAC_MD5 },
		{ PKCS11_CKK_SHA_1_HMAC, TEE_TYPE_HMAC_SHA1 },
		{ PKCS11_CKK_SHA224_HMAC, TEE_TYPE_HMAC_SHA224 },
		{ PKCS11_CKK_SHA256_HMAC, TEE_TYPE_HMAC_SHA256 },
		{ PKCS11_CKK_SHA384_HMAC, TEE_TYPE_HMAC_SHA384 },
		{ PKCS11_CKK_SHA512_HMAC, TEE_TYPE_HMAC_SHA512 },
	};
	size_t n = 0;
	enum pkcs11_key_type key_type = get_key_type(obj->attributes);

	assert(get_class(obj->attributes) == PKCS11_CKO_SECRET_KEY);

	for (n = 0; n < ARRAY_SIZE(pkcs2tee_key_type); n++) {
		if (pkcs2tee_key_type[n].key_type == key_type) {
			*tee_type = pkcs2tee_key_type[n].tee_id;
			return PKCS11_CKR_OK;
		}
	}

	return PKCS11_RV_NOT_FOUND;
}

static enum pkcs11_rc pkcsmech2tee_key_type(uint32_t *tee_type,
					    enum pkcs11_mechanism_id mech_id)
{
	static const struct {
		enum pkcs11_mechanism_id mech;
		uint32_t tee_id;
	} pkcs2tee_key_type[] = {
		{ PKCS11_CKM_MD5_HMAC, TEE_TYPE_HMAC_MD5 },
		{ PKCS11_CKM_SHA_1_HMAC, TEE_TYPE_HMAC_SHA1 },
		{ PKCS11_CKM_SHA224_HMAC, TEE_TYPE_HMAC_SHA224 },
		{ PKCS11_CKM_SHA256_HMAC, TEE_TYPE_HMAC_SHA256 },
		{ PKCS11_CKM_SHA384_HMAC, TEE_TYPE_HMAC_SHA384 },
		{ PKCS11_CKM_SHA512_HMAC, TEE_TYPE_HMAC_SHA512 },
	};
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(pkcs2tee_key_type); n++) {
		if (pkcs2tee_key_type[n].mech == mech_id) {
			*tee_type = pkcs2tee_key_type[n].tee_id;
			return PKCS11_CKR_OK;
		}
	}

	return PKCS11_RV_NOT_FOUND;
}

static enum pkcs11_rc
allocate_tee_operation(struct pkcs11_session *session,
		       enum processing_func function,
		       struct pkcs11_attribute_head *params,
		       struct pkcs11_object *obj)
{
	uint32_t size = (uint32_t)get_object_key_bit_size(obj);
	uint32_t algo = 0;
	uint32_t mode = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(session->processing->tee_op_handle == TEE_HANDLE_NULL);

	if (pkcs2tee_algorithm(&algo, params))
		return PKCS11_CKR_FUNCTION_FAILED;

	/* Sign/Verify with AES or generic key relate to TEE MAC operation */
	switch (params->id) {
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
		mode = TEE_MODE_MAC;
		break;
	default:
		pkcs2tee_mode(&mode, function);
		break;
	}

	res = TEE_AllocateOperation(&session->processing->tee_op_handle,
				    algo, mode, size);
	if (res)
		EMSG("TEE_AllocateOp. failed %#"PRIx32" %#"PRIx32" %#"PRIx32,
		     algo, mode, size);

	if (res == TEE_ERROR_NOT_SUPPORTED)
		return PKCS11_CKR_MECHANISM_INVALID;

	return tee2pkcs_error(res);
}

static enum pkcs11_rc load_tee_key(struct pkcs11_session *session,
				   struct pkcs11_object *obj,
				   struct pkcs11_attribute_head *proc_params)
{
	TEE_Attribute tee_attr = { };
	size_t object_size = 0;
	uint32_t tee_key_type = 0;
	enum pkcs11_key_type key_type = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (obj->key_handle != TEE_HANDLE_NULL) {
		/* Key was already loaded and fits current need */
		goto key_ready;
	}

	if (!pkcs2tee_load_attr(&tee_attr, TEE_ATTR_SECRET_VALUE,
				obj, PKCS11_CKA_VALUE)) {
		EMSG("No secret found");
		return PKCS11_CKR_FUNCTION_FAILED;
	}

	switch (proc_params->id) {
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
		key_type = get_key_type(obj->attributes);
		/*
		 * If Object Key type is PKCS11_CKK_GENERIC_SECRET,
		 * determine the tee_key_type using the
		 * mechanism instead of object key_type.
		 */
		if (key_type == PKCS11_CKK_GENERIC_SECRET)
			rc = pkcsmech2tee_key_type(&tee_key_type,
						   proc_params->id);
		else
			rc = pkcs2tee_key_type(&tee_key_type, obj);

		break;
	default:
		/*
		 * For all other mechanisms, use object key_type
		 * to determine the corresponding tee_key_type
		 */
		rc = pkcs2tee_key_type(&tee_key_type, obj);
		break;
	}

	if (rc)
		return rc;

	object_size = get_object_key_bit_size(obj);
	if (!object_size)
		return PKCS11_CKR_GENERAL_ERROR;

	res = TEE_AllocateTransientObject(tee_key_type, object_size,
					  &obj->key_handle);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed, %#"PRIx32, res);
		return tee2pkcs_error(res);
	}

	res = TEE_PopulateTransientObject(obj->key_handle, &tee_attr, 1);
	if (res) {
		DMSG("TEE_PopulateTransientObject failed, %#"PRIx32, res);
		goto error;
	}

key_ready:
	res = TEE_SetOperationKey(session->processing->tee_op_handle,
				  obj->key_handle);
	if (res) {
		DMSG("TEE_SetOperationKey failed, %#"PRIx32, res);
		goto error;
	}

	return PKCS11_CKR_OK;

error:
	TEE_FreeTransientObject(obj->key_handle);
	obj->key_handle = TEE_HANDLE_NULL;

	return tee2pkcs_error(res);
}

static enum pkcs11_rc
init_tee_operation(struct pkcs11_session *session,
		   struct pkcs11_attribute_head *proc_params)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	switch (proc_params->id) {
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
		if (proc_params->size)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;

		TEE_MACInit(session->processing->tee_op_handle, NULL, 0);
		rc = PKCS11_CKR_OK;
		break;
	case PKCS11_CKM_AES_ECB:
		if (proc_params->size)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;

		TEE_CipherInit(session->processing->tee_op_handle, NULL, 0);
		rc = PKCS11_CKR_OK;
		break;
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
		if (proc_params->size != 16)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;

		TEE_CipherInit(session->processing->tee_op_handle,
			       proc_params->data, 16);
		rc = PKCS11_CKR_OK;
		break;
	case PKCS11_CKM_AES_CTR:
		rc = tee_init_ctr_operation(session->processing,
					    proc_params->data,
					    proc_params->size);
		break;
	default:
		TEE_Panic(proc_params->id);
		break;
	}

	return rc;
}

enum pkcs11_rc init_symm_operation(struct pkcs11_session *session,
				   enum processing_func function,
				   struct pkcs11_attribute_head *proc_params,
				   struct pkcs11_object *obj)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(processing_is_tee_symm(proc_params->id));

	rc = allocate_tee_operation(session, function, proc_params, obj);
	if (rc)
		return rc;

	rc = load_tee_key(session, obj, proc_params);
	if (rc)
		return rc;

	return init_tee_operation(session, proc_params);
}

/* Validate input buffer size as per PKCS#11 constraints */
static enum pkcs11_rc input_data_size_is_valid(struct active_processing *proc,
					       enum processing_func function,
					       size_t in_size)
{
	switch (proc->mecha_type) {
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
		if (function == PKCS11_FUNCTION_ENCRYPT &&
		    in_size % TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_DATA_LEN_RANGE;
		if (function == PKCS11_FUNCTION_DECRYPT &&
		    in_size % TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE;
		break;
	case PKCS11_CKM_AES_CBC_PAD:
		if (function == PKCS11_FUNCTION_DECRYPT &&
		    in_size % TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE;
		break;
	case PKCS11_CKM_AES_CTS:
		if (function == PKCS11_FUNCTION_ENCRYPT &&
		    in_size < TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_DATA_LEN_RANGE;
		if (function == PKCS11_FUNCTION_DECRYPT &&
		    in_size < TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE;
		break;
	default:
		break;
	}

	return PKCS11_CKR_OK;
}

/* Validate input buffer size as per PKCS#11 constraints */
static enum pkcs11_rc input_sign_size_is_valid(struct active_processing *proc,
					       size_t in_size)
{
	size_t sign_sz = 0;

	switch (proc->mecha_type) {
	case PKCS11_CKM_MD5_HMAC:
		sign_sz = TEE_MD5_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA_1_HMAC:
		sign_sz = TEE_SHA1_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA224_HMAC:
		sign_sz = TEE_SHA224_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA256_HMAC:
		sign_sz = TEE_SHA256_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA384_HMAC:
		sign_sz = TEE_SHA384_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA512_HMAC:
		sign_sz = TEE_SHA512_HASH_SIZE;
		break;
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (in_size < sign_sz)
		return PKCS11_CKR_SIGNATURE_LEN_RANGE;

	return PKCS11_CKR_OK;
}

/*
 * step_sym_cipher - processing symmetric (and related) cipher operation step
 *
 * @session - current session
 * @function - processing function (encrypt, decrypt, sign, ...)
 * @step - step ID in the processing (oneshot, update, final)
 * @ptype - invocation parameter types
 * @params - invocation parameter references
 */
enum pkcs11_rc step_symm_operation(struct pkcs11_session *session,
				   enum processing_func function,
				   enum processing_step step,
				   uint32_t ptypes, TEE_Param *params)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	void *in_buf = NULL;
	size_t in_size = 0;
	void *out_buf = NULL;
	uint32_t out_size = 0;
	void *in2_buf = NULL;
	uint32_t in2_size = 0;
	bool output_data = false;
	struct active_processing *proc = session->processing;

	if (TEE_PARAM_TYPE_GET(ptypes, 1) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		in_buf = params[1].memref.buffer;
		in_size = params[1].memref.size;
		if (in_size && !in_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		in2_buf = params[2].memref.buffer;
		in2_size = params[2].memref.size;
		if (in2_size && !in2_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		out_buf = params[2].memref.buffer;
		out_size = params[2].memref.size;
		if (out_size && !out_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 3) != TEE_PARAM_TYPE_NONE)
		return PKCS11_CKR_ARGUMENTS_BAD;

	switch (step) {
	case PKCS11_FUNC_STEP_ONESHOT:
	case PKCS11_FUNC_STEP_UPDATE:
	case PKCS11_FUNC_STEP_FINAL:
		break;
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (step != PKCS11_FUNC_STEP_FINAL) {
		rc = input_data_size_is_valid(proc, function, in_size);
		if (rc)
			return rc;
	}

	/*
	 * Feed active operation with data
	 */
	switch (proc->mecha_type) {
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
		if (step == PKCS11_FUNC_STEP_FINAL ||
		    step == PKCS11_FUNC_STEP_ONESHOT)
			break;

		if (!in_buf) {
			DMSG("No input data");
			return PKCS11_CKR_ARGUMENTS_BAD;
		}

		switch (function) {
		case PKCS11_FUNCTION_SIGN:
		case PKCS11_FUNCTION_VERIFY:
			TEE_MACUpdate(proc->tee_op_handle, in_buf, in_size);
			rc = PKCS11_CKR_OK;
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
		if (step == PKCS11_FUNC_STEP_FINAL ||
		    step == PKCS11_FUNC_STEP_ONESHOT)
			break;

		if (!in_buf) {
			EMSG("No input data");
			return PKCS11_CKR_ARGUMENTS_BAD;
		}

		switch (function) {
		case PKCS11_FUNCTION_ENCRYPT:
		case PKCS11_FUNCTION_DECRYPT:
			res = TEE_CipherUpdate(proc->tee_op_handle,
					       in_buf, in_size,
						out_buf, &out_size);
			output_data = true;
			rc = tee2pkcs_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	default:
		TEE_Panic(proc->mecha_type);
		break;
	}

	if (step == PKCS11_FUNC_STEP_UPDATE)
		goto out;

	/*
	 * Finalize (PKCS11_FUNC_STEP_ONESHOT/_FINAL) operation
	 */
	switch (session->processing->mecha_type) {
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
		switch (function) {
		case PKCS11_FUNCTION_SIGN:
			res = TEE_MACComputeFinal(proc->tee_op_handle,
						  in_buf, in_size, out_buf,
						  &out_size);
			output_data = true;
			rc = tee2pkcs_error(res);
			break;
		case PKCS11_FUNCTION_VERIFY:
			rc = input_sign_size_is_valid(proc, in2_size);
			if (rc)
				return rc;
			res = TEE_MACCompareFinal(proc->tee_op_handle,
						  in_buf, in_size, in2_buf,
						  in2_size);
			rc = tee2pkcs_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
		if (step == PKCS11_FUNC_STEP_ONESHOT && !in_buf) {
			EMSG("No input data");
			return PKCS11_CKR_ARGUMENTS_BAD;
		}

		switch (function) {
		case PKCS11_FUNCTION_ENCRYPT:
		case PKCS11_FUNCTION_DECRYPT:
			res = TEE_CipherDoFinal(proc->tee_op_handle,
						in_buf, in_size,
						out_buf, &out_size);
			output_data = true;
			rc = tee2pkcs_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;
	default:
		TEE_Panic(proc->mecha_type);
		break;
	}

out:
	if (output_data &&
	    (rc == PKCS11_CKR_OK || rc == PKCS11_CKR_BUFFER_TOO_SMALL)) {
		switch (TEE_PARAM_TYPE_GET(ptypes, 2)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[2].memref.size = out_size;
			break;
		default:
			rc = PKCS11_CKR_ARGUMENTS_BAD;
			break;
		}
	}

	return rc;
}
