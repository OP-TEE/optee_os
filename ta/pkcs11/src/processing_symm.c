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

struct input_data_ref {
	size_t size;
	void *data;
};

bool processing_is_tee_symm(enum pkcs11_mechanism_id proc_id)
{
	switch (proc_id) {
	/* Authentication */
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_MD5_HMAC_GENERAL:
	case PKCS11_CKM_SHA_1_HMAC_GENERAL:
	case PKCS11_CKM_SHA224_HMAC_GENERAL:
	case PKCS11_CKM_SHA256_HMAC_GENERAL:
	case PKCS11_CKM_SHA384_HMAC_GENERAL:
	case PKCS11_CKM_SHA512_HMAC_GENERAL:
	/* Ciphering */
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
	case PKCS11_CKM_AES_ECB_ENCRYPT_DATA:
	case PKCS11_CKM_AES_CBC_ENCRYPT_DATA:
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
		{ PKCS11_CKM_AES_ECB_ENCRYPT_DATA, TEE_ALG_AES_ECB_NOPAD },
		{ PKCS11_CKM_AES_CBC_ENCRYPT_DATA, TEE_ALG_AES_CBC_NOPAD },
		{ PKCS11_CKM_AES_CTR, TEE_ALG_AES_CTR },
		{ PKCS11_CKM_AES_CTS, TEE_ALG_AES_CTS },
		{ PKCS11_CKM_AES_CMAC, TEE_ALG_AES_CMAC },
		{ PKCS11_CKM_AES_CMAC_GENERAL, TEE_ALG_AES_CMAC },
		/* HMAC flavors */
		{ PKCS11_CKM_MD5_HMAC, TEE_ALG_HMAC_MD5 },
		{ PKCS11_CKM_SHA_1_HMAC, TEE_ALG_HMAC_SHA1 },
		{ PKCS11_CKM_SHA224_HMAC, TEE_ALG_HMAC_SHA224 },
		{ PKCS11_CKM_SHA256_HMAC, TEE_ALG_HMAC_SHA256 },
		{ PKCS11_CKM_SHA384_HMAC, TEE_ALG_HMAC_SHA384 },
		{ PKCS11_CKM_SHA512_HMAC, TEE_ALG_HMAC_SHA512 },
		{ PKCS11_CKM_MD5_HMAC_GENERAL, TEE_ALG_HMAC_MD5 },
		{ PKCS11_CKM_SHA_1_HMAC_GENERAL, TEE_ALG_HMAC_SHA1 },
		{ PKCS11_CKM_SHA224_HMAC_GENERAL, TEE_ALG_HMAC_SHA224 },
		{ PKCS11_CKM_SHA256_HMAC_GENERAL, TEE_ALG_HMAC_SHA256 },
		{ PKCS11_CKM_SHA384_HMAC_GENERAL, TEE_ALG_HMAC_SHA384 },
		{ PKCS11_CKM_SHA512_HMAC_GENERAL, TEE_ALG_HMAC_SHA512 },
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
		{ PKCS11_CKM_MD5_HMAC_GENERAL, TEE_TYPE_HMAC_MD5 },
		{ PKCS11_CKM_SHA_1_HMAC_GENERAL, TEE_TYPE_HMAC_SHA1 },
		{ PKCS11_CKM_SHA224_HMAC_GENERAL, TEE_TYPE_HMAC_SHA224 },
		{ PKCS11_CKM_SHA256_HMAC_GENERAL, TEE_TYPE_HMAC_SHA256 },
		{ PKCS11_CKM_SHA384_HMAC_GENERAL, TEE_TYPE_HMAC_SHA384 },
		{ PKCS11_CKM_SHA512_HMAC_GENERAL, TEE_TYPE_HMAC_SHA512 },
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

static enum pkcs11_rc hmac_to_tee_hash(uint32_t *algo,
				       enum pkcs11_mechanism_id mech_id)
{
	static const struct {
		enum pkcs11_mechanism_id mech;
		uint32_t tee_id;
	} hmac_hash[] = {
		{ PKCS11_CKM_MD5_HMAC, TEE_ALG_MD5 },
		{ PKCS11_CKM_SHA_1_HMAC, TEE_ALG_SHA1 },
		{ PKCS11_CKM_SHA224_HMAC, TEE_ALG_SHA224 },
		{ PKCS11_CKM_SHA256_HMAC, TEE_ALG_SHA256 },
		{ PKCS11_CKM_SHA384_HMAC, TEE_ALG_SHA384 },
		{ PKCS11_CKM_SHA512_HMAC, TEE_ALG_SHA512 },
		{ PKCS11_CKM_MD5_HMAC_GENERAL, TEE_ALG_MD5 },
		{ PKCS11_CKM_SHA_1_HMAC_GENERAL, TEE_ALG_SHA1 },
		{ PKCS11_CKM_SHA224_HMAC_GENERAL, TEE_ALG_SHA224 },
		{ PKCS11_CKM_SHA256_HMAC_GENERAL, TEE_ALG_SHA256 },
		{ PKCS11_CKM_SHA384_HMAC_GENERAL, TEE_ALG_SHA384 },
		{ PKCS11_CKM_SHA512_HMAC_GENERAL, TEE_ALG_SHA512 },
	};
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(hmac_hash); n++) {
		if (hmac_hash[n].mech == mech_id) {
			*algo = hmac_hash[n].tee_id;
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
	uint32_t key_size = size / 8;
	uint32_t algo = 0;
	uint32_t mode = 0;
	uint32_t max_key_size = 0;
	uint32_t min_key_size = 0;
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
	case PKCS11_CKM_MD5_HMAC_GENERAL:
	case PKCS11_CKM_SHA_1_HMAC_GENERAL:
	case PKCS11_CKM_SHA224_HMAC_GENERAL:
	case PKCS11_CKM_SHA256_HMAC_GENERAL:
	case PKCS11_CKM_SHA384_HMAC_GENERAL:
	case PKCS11_CKM_SHA512_HMAC_GENERAL:
		mechanism_supported_key_sizes_bytes(params->id, &min_key_size,
						    &max_key_size);
		if (key_size < min_key_size)
			return PKCS11_CKR_KEY_SIZE_RANGE;

		/*
		 * If size of generic key is greater than the size
		 * supported by TEE API, this is not considered an
		 * error. When loading TEE key, we will hash the key
		 * to generate the appropriate key for HMAC operation.
		 * This key size will not be greater than the
		 * max_key_size. So we can use max_key_size for
		 * TEE_AllocateOperation().
		 */
		if (key_size > max_key_size)
			size = max_key_size * 8;

		mode = TEE_MODE_MAC;
		break;
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_AES_CMAC_GENERAL:
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

static enum pkcs11_rc hash_secret_helper(enum pkcs11_mechanism_id mech_id,
					 struct pkcs11_object *obj,
					 TEE_Attribute *tee_attr,
					 void **ctx,
					 size_t *object_size_bits)
{
	uint32_t algo = 0;
	void *hash_ptr = NULL;
	uint32_t hash_size = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = hmac_to_tee_hash(&algo, mech_id);
	if (rc)
		return rc;

	hash_size = TEE_ALG_GET_DIGEST_SIZE(algo);
	hash_ptr = TEE_Malloc(hash_size, 0);
	if (!hash_ptr)
		return PKCS11_CKR_DEVICE_MEMORY;

	rc = pkcs2tee_load_hashed_attr(tee_attr, TEE_ATTR_SECRET_VALUE, obj,
				       PKCS11_CKA_VALUE, algo, hash_ptr,
				       &hash_size);
	if (rc) {
		EMSG("No secret/hash error");
		TEE_Free(hash_ptr);
		return rc;
	}

	*ctx = hash_ptr;

	*object_size_bits = hash_size * 8;

	return PKCS11_CKR_OK;
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
	uint32_t max_key_size = 0;
	uint32_t min_key_size = 0;

	if (obj->key_handle != TEE_HANDLE_NULL) {
		/* Key was already loaded and fits current need */
		goto key_ready;
	}

	object_size = get_object_key_bit_size(obj);
	if (!object_size)
		return PKCS11_CKR_GENERAL_ERROR;

	switch (proc_params->id) {
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_MD5_HMAC_GENERAL:
	case PKCS11_CKM_SHA_1_HMAC_GENERAL:
	case PKCS11_CKM_SHA224_HMAC_GENERAL:
	case PKCS11_CKM_SHA256_HMAC_GENERAL:
	case PKCS11_CKM_SHA384_HMAC_GENERAL:
	case PKCS11_CKM_SHA512_HMAC_GENERAL:
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

		if (rc)
			return rc;

		mechanism_supported_key_sizes_bytes(proc_params->id,
						    &min_key_size,
						    &max_key_size);

		if ((object_size / 8) > max_key_size) {
			rc = hash_secret_helper(proc_params->id, obj, &tee_attr,
						&session->processing->extra_ctx,
						&object_size);
			if (rc)
				return rc;
		} else {
			if (!pkcs2tee_load_attr(&tee_attr,
						TEE_ATTR_SECRET_VALUE,
						obj,
						PKCS11_CKA_VALUE)) {
				EMSG("No secret found");
				return PKCS11_CKR_FUNCTION_FAILED;
			}
		}
		break;

	default:
		rc = pkcs2tee_key_type(&tee_key_type, obj);
		if (rc)
			return rc;

		if (!pkcs2tee_load_attr(&tee_attr, TEE_ATTR_SECRET_VALUE,
					obj, PKCS11_CKA_VALUE)) {
			EMSG("No secret found");
			return PKCS11_CKR_FUNCTION_FAILED;
		}
		break;
	}

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
tee_init_derive_symm(struct active_processing *processing,
		     struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct input_data_ref *param = NULL;
	void *iv = NULL;

	if (!proc_params)
		return PKCS11_CKR_ARGUMENTS_BAD;

	param =	TEE_Malloc(sizeof(struct input_data_ref), TEE_MALLOC_FILL_ZERO);
	if (!param)
		return PKCS11_CKR_DEVICE_MEMORY;

	serialargs_init(&args, proc_params->data, proc_params->size);

	switch (proc_params->id) {
	case PKCS11_CKM_AES_CBC_ENCRYPT_DATA:
		rc = serialargs_get_ptr(&args, &iv, 16);
		if (rc)
			goto err;
		break;
	default:
		break;
	}

	rc = serialargs_get(&args, &param->size, sizeof(uint32_t));
	if (rc)
		goto err;

	rc = serialargs_get_ptr(&args, &param->data, param->size);
	if (rc)
		goto err;

	if (serialargs_remaining_bytes(&args)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto err;
	}

	processing->extra_ctx = param;

	switch (proc_params->id) {
	case PKCS11_CKM_AES_ECB_ENCRYPT_DATA:
		if (param->size % TEE_AES_BLOCK_SIZE) {
			rc = PKCS11_CKR_DATA_LEN_RANGE;
			goto err;
		}
		TEE_CipherInit(processing->tee_op_handle, NULL, 0);
		break;
	case PKCS11_CKM_AES_CBC_ENCRYPT_DATA:
		if (param->size % TEE_AES_BLOCK_SIZE) {
			rc = PKCS11_CKR_DATA_LEN_RANGE;
			goto err;
		}
		TEE_CipherInit(processing->tee_op_handle, iv, 16);
		break;
	default:
		TEE_Panic(proc_params->id);
		break;
	}

	return PKCS11_CKR_OK;

err:
	processing->extra_ctx = NULL;
	TEE_Free(param);
	return rc;
}

static enum pkcs11_rc
input_hmac_len_is_valid(struct pkcs11_attribute_head *proc_params,
			uint32_t hmac_len)
{
	uint32_t sign_sz = 0;

	switch (proc_params->id) {
	case PKCS11_CKM_MD5_HMAC_GENERAL:
		sign_sz = TEE_MD5_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA_1_HMAC_GENERAL:
		sign_sz = TEE_SHA1_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA224_HMAC_GENERAL:
		sign_sz = TEE_SHA224_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA256_HMAC_GENERAL:
		sign_sz = TEE_SHA256_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA384_HMAC_GENERAL:
		sign_sz = TEE_SHA384_HASH_SIZE;
		break;
	case PKCS11_CKM_SHA512_HMAC_GENERAL:
		sign_sz = TEE_SHA512_HASH_SIZE;
		break;
	case PKCS11_CKM_AES_CMAC_GENERAL:
		sign_sz = TEE_AES_BLOCK_SIZE;
		break;
	default:
		return PKCS11_CKR_MECHANISM_INVALID;
	}

	if (!hmac_len || hmac_len > sign_sz)
		return PKCS11_CKR_SIGNATURE_LEN_RANGE;

	return PKCS11_CKR_OK;
}

static enum pkcs11_rc
init_tee_operation(struct pkcs11_session *session,
		   struct pkcs11_attribute_head *proc_params)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t *pkcs11_data = NULL;

	switch (proc_params->id) {
	case PKCS11_CKM_AES_CMAC:
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
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_MD5_HMAC_GENERAL:
	case PKCS11_CKM_SHA_1_HMAC_GENERAL:
	case PKCS11_CKM_SHA224_HMAC_GENERAL:
	case PKCS11_CKM_SHA256_HMAC_GENERAL:
	case PKCS11_CKM_SHA384_HMAC_GENERAL:
	case PKCS11_CKM_SHA512_HMAC_GENERAL:
		if (proc_params->size != sizeof(uint32_t))
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;

		pkcs11_data = TEE_Malloc(sizeof(uint32_t),
					 TEE_MALLOC_FILL_ZERO);
		if (!pkcs11_data)
			return PKCS11_CKR_DEVICE_MEMORY;

		TEE_MemMove(pkcs11_data, proc_params->data, sizeof(uint32_t));

		rc = input_hmac_len_is_valid(proc_params, *pkcs11_data);
		if (rc) {
			TEE_Free(pkcs11_data);
			return rc;
		}

		session->processing->extra_ctx = (void *)pkcs11_data;

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
	case PKCS11_CKM_AES_ECB_ENCRYPT_DATA:
	case PKCS11_CKM_AES_CBC_ENCRYPT_DATA:
		rc = tee_init_derive_symm(session->processing, proc_params);
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
	case PKCS11_CKM_AES_CMAC:
		sign_sz = TEE_AES_BLOCK_SIZE;
		break;
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (in_size != sign_sz)
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
	uint32_t hmac_len = 0;
	uint8_t computed_mac[TEE_MAX_HASH_SIZE] = { 0 };
	uint32_t computed_mac_size = TEE_MAX_HASH_SIZE;

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
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_MD5_HMAC_GENERAL:
	case PKCS11_CKM_SHA_1_HMAC_GENERAL:
	case PKCS11_CKM_SHA224_HMAC_GENERAL:
	case PKCS11_CKM_SHA256_HMAC_GENERAL:
	case PKCS11_CKM_SHA384_HMAC_GENERAL:
	case PKCS11_CKM_SHA512_HMAC_GENERAL:
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
	case PKCS11_CKM_AES_CMAC:
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

	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_MD5_HMAC_GENERAL:
	case PKCS11_CKM_SHA_1_HMAC_GENERAL:
	case PKCS11_CKM_SHA224_HMAC_GENERAL:
	case PKCS11_CKM_SHA256_HMAC_GENERAL:
	case PKCS11_CKM_SHA384_HMAC_GENERAL:
	case PKCS11_CKM_SHA512_HMAC_GENERAL:
		assert(session->processing->extra_ctx);
		hmac_len = *(uint32_t *)session->processing->extra_ctx;

		switch (function) {
		case PKCS11_FUNCTION_SIGN:
			if (out_size < hmac_len) {
				/* inform client of required size */
				out_size = hmac_len;
				output_data = true;
				rc = PKCS11_CKR_BUFFER_TOO_SMALL;
				goto out;
			}

			res = TEE_MACComputeFinal(proc->tee_op_handle,
						  in_buf, in_size,
						  computed_mac,
						  &computed_mac_size);
			if (res == TEE_SUCCESS) {
				/* truncate to hmac_len */
				TEE_MemMove(out_buf, computed_mac, hmac_len);
				output_data = true;
			}

			/* inform client of required size */
			out_size = hmac_len;
			rc = tee2pkcs_error(res);
			break;
		case PKCS11_FUNCTION_VERIFY:
			/* must compute full MAC before comparing partial */
			res = TEE_MACComputeFinal(proc->tee_op_handle, in_buf,
						  in_size, computed_mac,
						  &computed_mac_size);

			if (!in2_size || in2_size > computed_mac_size) {
				EMSG("Invalid signature size: %"PRIu32,
				     in2_size);
				return PKCS11_CKR_SIGNATURE_LEN_RANGE;
			}

			if (res == TEE_SUCCESS) {
				/*
				 * Only the first in2_size bytes of the
				 * signature to be verified is passed in from
				 * caller
				 */
				if (TEE_MemCompare(in2_buf, computed_mac,
						   in2_size)) {
					res = TEE_ERROR_MAC_INVALID;
				}
			}

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

enum pkcs11_rc derive_key_by_symm_enc(struct pkcs11_session *session,
				      void **out_buf, uint32_t *out_size)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct active_processing *proc = session->processing;
	struct input_data_ref *input = proc->extra_ctx;
	void *in_buf = NULL;
	uint32_t in_size = 0;

	switch (proc->mecha_type) {
	case PKCS11_CKM_AES_ECB_ENCRYPT_DATA:
	case PKCS11_CKM_AES_CBC_ENCRYPT_DATA:
		if (!proc->extra_ctx)
			return PKCS11_CKR_ARGUMENTS_BAD;

		in_buf = input->data;
		in_size = input->size;

		*out_size = in_size;
		*out_buf = TEE_Malloc(*out_size, 0);
		if (!*out_buf)
			return PKCS11_CKR_DEVICE_MEMORY;

		res = TEE_CipherDoFinal(proc->tee_op_handle, in_buf, in_size,
					*out_buf, out_size);
		rc = tee2pkcs_error(res);
		if (rc)
			TEE_Free(*out_buf);
		break;
	default:
		return PKCS11_CKR_MECHANISM_INVALID;
	}

	return rc;
}

enum pkcs11_rc wrap_data_by_symm_enc(struct pkcs11_session *session,
				     void *data, uint32_t data_sz,
				     void *out_buf, uint32_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct active_processing *proc = session->processing;
	void *in_buf = NULL;
	uint32_t align = 0;
	uint32_t in_sz = data_sz;
	uint32_t tmp_sz = *out_sz;
	uint8_t *tmp_buf = out_buf;

	switch (proc->mecha_type) {
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
		align = data_sz % TEE_AES_BLOCK_SIZE;
		if (align)
			in_sz = data_sz + (TEE_AES_BLOCK_SIZE - align);

		if (*out_sz < in_sz) {
			*out_sz = in_sz;
			return PKCS11_CKR_BUFFER_TOO_SMALL;
		}

		if (align) {
			if (data_sz > TEE_AES_BLOCK_SIZE) {
				in_sz = data_sz - align;
				res = TEE_CipherUpdate(proc->tee_op_handle,
						       data, in_sz, tmp_buf,
						       &tmp_sz);
				if (res) {
					assert(res != TEE_ERROR_SHORT_BUFFER);
					return tee2pkcs_error(res);
				}
				tmp_buf += tmp_sz;
				tmp_sz = *out_sz - tmp_sz;
			} else {
				in_sz = 0;
			}

			in_buf = TEE_Malloc(TEE_AES_BLOCK_SIZE,
					    TEE_MALLOC_FILL_ZERO);
			if (!in_buf)
				return PKCS11_CKR_DEVICE_MEMORY;

			TEE_MemMove(in_buf, (uint8_t *)data + in_sz, align);
			in_sz = TEE_AES_BLOCK_SIZE;
		} else {
			in_buf = data;
			in_sz = data_sz;
		}

		res = TEE_CipherDoFinal(proc->tee_op_handle, in_buf, in_sz,
					tmp_buf, &tmp_sz);
		if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) {
			*out_sz = tmp_sz;
			if (align)
				*out_sz += tmp_buf - (uint8_t *)out_buf;
		}

		if (align)
			TEE_Free(in_buf);

		return tee2pkcs_error(res);
	default:
		return PKCS11_CKR_MECHANISM_INVALID;
	}

	return PKCS11_CKR_GENERAL_ERROR;
}

enum pkcs11_rc unwrap_key_by_symm(struct pkcs11_session *session, void *data,
				  uint32_t data_sz, void **out_buf,
				  uint32_t *out_sz)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct active_processing *proc = session->processing;

	if (input_data_size_is_valid(proc, PKCS11_FUNCTION_DECRYPT, data_sz))
		return PKCS11_CKR_WRAPPED_KEY_LEN_RANGE;

	switch (proc->mecha_type) {
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
		*out_sz = 0;
		res = TEE_CipherDoFinal(proc->tee_op_handle, data, data_sz,
					NULL, out_sz);
		if (res != TEE_ERROR_SHORT_BUFFER) {
			DMSG("TEE_CipherDoFinal() issue: %#"PRIx32, res);
			return PKCS11_CKR_GENERAL_ERROR;
		}

		*out_buf = TEE_Malloc(*out_sz, TEE_MALLOC_FILL_ZERO);
		if (!*out_buf)
			return PKCS11_CKR_DEVICE_MEMORY;

		res = TEE_CipherDoFinal(proc->tee_op_handle, data, data_sz,
				        *out_buf, out_sz);
		if (tee2pkcs_error(res)) {
			TEE_Free(*out_buf);
			*out_buf = NULL;
			return PKCS11_CKR_WRAPPED_KEY_INVALID;
		}
		break;
	default:
		return PKCS11_CKR_MECHANISM_INVALID;
	}

	return PKCS11_CKR_OK;
}
