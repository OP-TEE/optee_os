// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2021, Linaro Limited
 */

#include <assert.h>
#include <pkcs11_ta.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_token.h"
#include "processing.h"

enum pkcs11_rc
pkcs2tee_proc_params_rsa_pss(struct active_processing *proc,
			     struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct rsa_pss_processing_ctx *ctx = NULL;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t salt_len = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get_u32(&args, &hash);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &mgf);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &salt_len);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	proc->extra_ctx = TEE_Malloc(sizeof(struct rsa_pss_processing_ctx),
				     TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!proc->extra_ctx)
		return PKCS11_CKR_DEVICE_MEMORY;

	ctx = proc->extra_ctx;

	ctx->hash_alg = hash;
	ctx->mgf_type = mgf;
	ctx->salt_len = salt_len;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc pkcs2tee_validate_rsa_pss(struct active_processing *proc,
					 struct pkcs11_object *obj)
{
	struct rsa_pss_processing_ctx *rsa_pss_ctx = NULL;
	size_t modulus_size = 0;
	size_t hash_size = 0;
	uint32_t k = 0;

	rsa_pss_ctx = proc->extra_ctx;
	assert(rsa_pss_ctx);

	switch (rsa_pss_ctx->hash_alg) {
	case PKCS11_CKM_SHA_1:
		hash_size = TEE_ALG_GET_DIGEST_SIZE(TEE_ALG_SHA1);
		break;
	case PKCS11_CKM_SHA224:
		hash_size = TEE_ALG_GET_DIGEST_SIZE(TEE_ALG_SHA224);
		break;
	case PKCS11_CKM_SHA256:
		hash_size = TEE_ALG_GET_DIGEST_SIZE(TEE_ALG_SHA256);
		break;
	case PKCS11_CKM_SHA384:
		hash_size = TEE_ALG_GET_DIGEST_SIZE(TEE_ALG_SHA384);
		break;
	case PKCS11_CKM_SHA512:
		hash_size = TEE_ALG_GET_DIGEST_SIZE(TEE_ALG_SHA512);
		break;
	default:
		assert(0);
		break;
	}

	modulus_size = get_object_key_bit_size(obj);

	/**
	 * The sLen field must be less than or equal to k*-2-hLen where
	 * hLen is the length in bytes of the hash value. k* is the
	 * length in bytes of the RSA modulus, except if the length in
	 * bits of the RSA modulus is one more than a multiple of 8, in
	 * which case k* is one less than the length in bytes of the
	 * RSA modulus.
	 */
	if ((modulus_size % 8) == 1)
		k = modulus_size / 8;
	else
		k = ROUNDUP(modulus_size, 8) / 8;

	if (rsa_pss_ctx->salt_len > (k - 2 - hash_size))
		return PKCS11_CKR_KEY_SIZE_RANGE;

	return PKCS11_CKR_OK;
}

/*
 * Check or set TEE algorithm identifier upon PKCS11 mechanism parameters
 * @tee_id: Input and/or output TEE algorithm identifier
 * @proc_params: PKCS11 processing parameters
 */
enum pkcs11_rc pkcs2tee_algo_rsa_pss(uint32_t *tee_id,
				     struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t salt_len = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get_u32(&args, &hash);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &mgf);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &salt_len);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (proc_params->id == PKCS11_CKM_RSA_PKCS_PSS) {
		if (hash == PKCS11_CKM_SHA_1 && mgf == PKCS11_CKG_MGF1_SHA1) {
			*tee_id = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1;
			return PKCS11_CKR_OK;
		}
		if (hash == PKCS11_CKM_SHA224 &&
		    mgf == PKCS11_CKG_MGF1_SHA224) {
			*tee_id = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224;
			return PKCS11_CKR_OK;
		}
		if (hash == PKCS11_CKM_SHA256 &&
		    mgf == PKCS11_CKG_MGF1_SHA256) {
			*tee_id = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
			return PKCS11_CKR_OK;
		}
		if (hash == PKCS11_CKM_SHA384 &&
		    mgf == PKCS11_CKG_MGF1_SHA384) {
			*tee_id = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384;
			return PKCS11_CKR_OK;
		}
		if (hash == PKCS11_CKM_SHA512 &&
		    mgf == PKCS11_CKG_MGF1_SHA512) {
			*tee_id = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512;
			return PKCS11_CKR_OK;
		}
		return PKCS11_CKR_MECHANISM_PARAM_INVALID;
	}

	switch (*tee_id) {
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		if (hash != PKCS11_CKM_SHA_1 || mgf != PKCS11_CKG_MGF1_SHA1)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		if (hash != PKCS11_CKM_SHA224 || mgf != PKCS11_CKG_MGF1_SHA224)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		if (hash != PKCS11_CKM_SHA256 || mgf != PKCS11_CKG_MGF1_SHA256)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		if (hash != PKCS11_CKM_SHA384 || mgf != PKCS11_CKG_MGF1_SHA384)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		if (hash != PKCS11_CKM_SHA512 || mgf != PKCS11_CKG_MGF1_SHA512)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}

	return PKCS11_CKR_OK;
}

enum pkcs11_rc
pkcs2tee_proc_params_rsa_oaep(struct active_processing *proc,
			      struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct rsa_oaep_processing_ctx *ctx = NULL;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t source_type = 0;
	void *source_data = NULL;
	uint32_t source_size = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get_u32(&args, &hash);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &mgf);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &source_type);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &source_size);
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &source_data, source_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	proc->extra_ctx = TEE_Malloc(sizeof(struct rsa_oaep_processing_ctx) +
				     source_size,
				     TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!proc->extra_ctx)
		return PKCS11_CKR_DEVICE_MEMORY;

	ctx = proc->extra_ctx;

	ctx->hash_alg = hash;
	ctx->mgf_type = mgf;
	ctx->source_type = source_type;
	ctx->source_data_len = source_size;
	TEE_MemMove(ctx->source_data, source_data, source_size);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc
pkcs2tee_proc_params_rsa_aes_wrap(struct active_processing *proc,
				  struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct rsa_aes_key_wrap_processing_ctx *ctx = NULL;
	uint32_t aes_key_bits = 0;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t source_type = 0;
	void *source_data = NULL;
	uint32_t source_size = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get_u32(&args, &aes_key_bits);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &hash);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &mgf);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &source_type);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &source_size);
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &source_data, source_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	proc->extra_ctx =
		TEE_Malloc(sizeof(struct rsa_aes_key_wrap_processing_ctx) +
			   source_size,
			   TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!proc->extra_ctx)
		return PKCS11_CKR_DEVICE_MEMORY;

	ctx = proc->extra_ctx;

	ctx->aes_key_bits = aes_key_bits;
	ctx->hash_alg = hash;
	ctx->mgf_type = mgf;
	ctx->source_type = source_type;
	ctx->source_data_len = source_size;
	TEE_MemMove(ctx->source_data, source_data, source_size);

	return PKCS11_CKR_OK;
}

/*
 * Set TEE RSA OAEP algorithm identifier upon PKCS11 mechanism parameters
 * @tee_id: output TEE RSA OAEP algorithm identifier
 * @tee_hash_id: output TEE hash algorithm identifier
 * @proc_params: PKCS11 processing parameters
 */
enum pkcs11_rc
pkcs2tee_algo_rsa_oaep(uint32_t *tee_id, uint32_t *tee_hash_id,
		       struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t source_type = 0;
	void *source_data = NULL;
	uint32_t source_size = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get_u32(&args, &hash);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &mgf);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &source_type);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &source_size);
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &source_data, source_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (source_type != PKCS11_CKZ_DATA_SPECIFIED)
		return PKCS11_CKR_MECHANISM_PARAM_INVALID;

	switch (proc_params->id) {
	case PKCS11_CKM_RSA_PKCS_OAEP:
		switch (hash) {
		case PKCS11_CKM_SHA_1:
			if (mgf != PKCS11_CKG_MGF1_SHA1)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1;
			*tee_hash_id = TEE_ALG_SHA1;
			break;
		case PKCS11_CKM_SHA224:
			if (mgf != PKCS11_CKG_MGF1_SHA224)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224;
			*tee_hash_id = TEE_ALG_SHA224;
			break;
		case PKCS11_CKM_SHA256:
			if (mgf != PKCS11_CKG_MGF1_SHA256)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
			*tee_hash_id = TEE_ALG_SHA256;
			break;
		case PKCS11_CKM_SHA384:
			if (mgf != PKCS11_CKG_MGF1_SHA384)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384;
			*tee_hash_id = TEE_ALG_SHA384;
			break;
		case PKCS11_CKM_SHA512:
			if (mgf != PKCS11_CKG_MGF1_SHA512)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512;
			*tee_hash_id = TEE_ALG_SHA512;
			break;
		default:
			EMSG("Unexpected %#"PRIx32"/%s", hash,
			     id2str_proc(hash));

			return PKCS11_CKR_GENERAL_ERROR;
		}
		break;
	default:
		EMSG("Unexpected mechanism %#"PRIx32"/%s", proc_params->id,
		     id2str_proc(proc_params->id));

		return PKCS11_CKR_GENERAL_ERROR;
	}

	return PKCS11_CKR_OK;
}

enum pkcs11_rc
pkcs2tee_algo_rsa_aes_wrap(uint32_t *tee_id, uint32_t *tee_hash_id,
			   struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t aes_key_bits = 0;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t source_type = 0;
	void *source_data = NULL;
	uint32_t source_size = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get_u32(&args, &aes_key_bits);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &hash);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &mgf);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &source_type);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&args, &source_size);
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &source_data, source_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (source_type != PKCS11_CKZ_DATA_SPECIFIED)
		return PKCS11_CKR_MECHANISM_PARAM_INVALID;

	switch (proc_params->id) {
	case PKCS11_CKM_RSA_AES_KEY_WRAP:
		switch (hash) {
		case PKCS11_CKM_SHA_1:
			if (mgf != PKCS11_CKG_MGF1_SHA1)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1;
			*tee_hash_id = TEE_ALG_SHA1;
			break;
		case PKCS11_CKM_SHA224:
			if (mgf != PKCS11_CKG_MGF1_SHA224)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224;
			*tee_hash_id = TEE_ALG_SHA224;
			break;
		case PKCS11_CKM_SHA256:
			if (mgf != PKCS11_CKG_MGF1_SHA256)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
			*tee_hash_id = TEE_ALG_SHA256;
			break;
		case PKCS11_CKM_SHA384:
			if (mgf != PKCS11_CKG_MGF1_SHA384)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384;
			*tee_hash_id = TEE_ALG_SHA384;
			break;
		case PKCS11_CKM_SHA512:
			if (mgf != PKCS11_CKG_MGF1_SHA512)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512;
			*tee_hash_id = TEE_ALG_SHA512;
			break;
		default:
			EMSG("Unexpected %#"PRIx32"/%s", hash,
			     id2str_proc(hash));

			return PKCS11_CKR_GENERAL_ERROR;
		}
		break;
	default:
		EMSG("Unexpected mechanism %#"PRIx32"/%s", proc_params->id,
		     id2str_proc(proc_params->id));

		return PKCS11_CKR_GENERAL_ERROR;
	}

	return PKCS11_CKR_OK;
}

enum pkcs11_rc load_tee_rsa_key_attrs(TEE_Attribute **tee_attrs,
				      size_t *tee_count,
				      struct pkcs11_object *obj)
{
	TEE_Attribute *attrs = NULL;
	size_t count = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *a_ptr = NULL;

	assert(get_key_type(obj->attributes) == PKCS11_CKK_RSA);

	switch (get_class(obj->attributes)) {
	case PKCS11_CKO_PUBLIC_KEY:
		attrs = TEE_Malloc(2 * sizeof(TEE_Attribute),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!attrs)
			return PKCS11_CKR_DEVICE_MEMORY;

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_MODULUS,
				       obj, PKCS11_CKA_MODULUS))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
				       TEE_ATTR_RSA_PUBLIC_EXPONENT, obj,
				       PKCS11_CKA_PUBLIC_EXPONENT))
			count++;

		if (count == 2)
			rc = PKCS11_CKR_OK;

		break;

	case PKCS11_CKO_PRIVATE_KEY:
		attrs = TEE_Malloc(8 * sizeof(TEE_Attribute),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!attrs)
			return PKCS11_CKR_DEVICE_MEMORY;

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_MODULUS,
				       obj, PKCS11_CKA_MODULUS))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
				       TEE_ATTR_RSA_PUBLIC_EXPONENT, obj,
				       PKCS11_CKA_PUBLIC_EXPONENT))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
				       TEE_ATTR_RSA_PRIVATE_EXPONENT, obj,
				       PKCS11_CKA_PRIVATE_EXPONENT))
			count++;

		if (count != 3)
			break;

		/* If pre-computed values are present load those */
		rc = get_attribute_ptr(obj->attributes, PKCS11_CKA_PRIME_1,
				       &a_ptr, NULL);
		if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
			break;
		if (rc == PKCS11_RV_NOT_FOUND || !a_ptr) {
			rc = PKCS11_CKR_OK;
			break;
		}

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_PRIME1, obj,
				       PKCS11_CKA_PRIME_1))
			count++;

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_PRIME2, obj,
				       PKCS11_CKA_PRIME_2))
			count++;

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_EXPONENT1,
				       obj, PKCS11_CKA_EXPONENT_1))
			count++;

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_EXPONENT2,
				       obj, PKCS11_CKA_EXPONENT_2))
			count++;

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_COEFFICIENT,
				       obj, PKCS11_CKA_COEFFICIENT))
			count++;

		if (count == 8)
			rc = PKCS11_CKR_OK;

		break;

	default:
		assert(0);
		break;
	}

	if (rc == PKCS11_CKR_OK) {
		*tee_attrs = attrs;
		*tee_count = count;
	} else {
		TEE_Free(attrs);
	}

	return rc;
}

static enum pkcs11_rc tee2pkcs_rsa_attributes(struct obj_attrs **pub_head,
					      struct obj_attrs **priv_head,
					      TEE_ObjectHandle tee_obj)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *a_ptr = NULL;

	rc = tee2pkcs_add_attribute(pub_head, PKCS11_CKA_MODULUS, tee_obj,
				    TEE_ATTR_RSA_MODULUS);
	if (rc)
		goto out;

	rc = get_attribute_ptr(*pub_head, PKCS11_CKA_PUBLIC_EXPONENT, &a_ptr,
			       NULL);
	if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
		goto out;

	if (rc == PKCS11_CKR_OK && !a_ptr) {
		rc = remove_empty_attribute(pub_head,
					    PKCS11_CKA_PUBLIC_EXPONENT);
		if (rc)
			goto out;
		rc = PKCS11_RV_NOT_FOUND;
	}

	if (rc == PKCS11_RV_NOT_FOUND) {
		rc = tee2pkcs_add_attribute(pub_head,
					    PKCS11_CKA_PUBLIC_EXPONENT,
					    tee_obj,
					    TEE_ATTR_RSA_PUBLIC_EXPONENT);
		if (rc)
			goto out;
	}

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_MODULUS, tee_obj,
				    TEE_ATTR_RSA_MODULUS);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_PUBLIC_EXPONENT,
				    tee_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_PRIVATE_EXPONENT,
				    tee_obj, TEE_ATTR_RSA_PRIVATE_EXPONENT);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_PRIME_1, tee_obj,
				    TEE_ATTR_RSA_PRIME1);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_PRIME_2, tee_obj,
				    TEE_ATTR_RSA_PRIME2);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_EXPONENT_1, tee_obj,
				    TEE_ATTR_RSA_EXPONENT1);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_EXPONENT_2, tee_obj,
				    TEE_ATTR_RSA_EXPONENT2);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_COEFFICIENT, tee_obj,
				    TEE_ATTR_RSA_COEFFICIENT);
out:
	return rc;
}

enum pkcs11_rc generate_rsa_keys(struct pkcs11_attribute_head *proc_params,
				 struct obj_attrs **pub_head,
				 struct obj_attrs **priv_head)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *a_ptr = NULL;
	uint32_t a_size = 0;
	TEE_ObjectHandle tee_obj = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t modulus_bits = 0;
	TEE_Attribute tee_attrs[1] = { };
	uint32_t tee_count = 0;

	if (!proc_params || !*pub_head || !*priv_head)
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;

	rc = get_attribute_ptr(*pub_head, PKCS11_CKA_MODULUS_BITS, &a_ptr,
			       &a_size);
	if (rc != PKCS11_CKR_OK || a_size != sizeof(uint32_t))
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;

	TEE_MemMove(&modulus_bits, a_ptr, sizeof(uint32_t));

	rc = get_attribute_ptr(*pub_head, PKCS11_CKA_PUBLIC_EXPONENT, &a_ptr,
			       &a_size);
	if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
		return rc;

	if (rc == PKCS11_CKR_OK && a_ptr) {
		TEE_InitRefAttribute(&tee_attrs[tee_count],
				     TEE_ATTR_RSA_PUBLIC_EXPONENT,
				     a_ptr, a_size);
		tee_count++;
	}

	if (remove_empty_attribute(priv_head, PKCS11_CKA_MODULUS) ||
	    remove_empty_attribute(priv_head, PKCS11_CKA_PUBLIC_EXPONENT) ||
	    remove_empty_attribute(priv_head, PKCS11_CKA_PRIVATE_EXPONENT) ||
	    remove_empty_attribute(priv_head, PKCS11_CKA_PRIME_1) ||
	    remove_empty_attribute(priv_head, PKCS11_CKA_PRIME_2) ||
	    remove_empty_attribute(priv_head, PKCS11_CKA_EXPONENT_1) ||
	    remove_empty_attribute(priv_head, PKCS11_CKA_EXPONENT_2) ||
	    remove_empty_attribute(priv_head, PKCS11_CKA_COEFFICIENT)) {
		EMSG("Unexpected attribute(s) found");
		rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
		goto out;
	}

	/* Create an RSA TEE key */
	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, modulus_bits,
					  &tee_obj);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed %#"PRIx32, res);

		rc = tee2pkcs_error(res);
		goto out;
	}

	res = TEE_RestrictObjectUsage1(tee_obj, TEE_USAGE_EXTRACTABLE);
	if (res) {
		DMSG("TEE_RestrictObjectUsage1 failed %#"PRIx32, res);

		rc = tee2pkcs_error(res);
		goto out;
	}

	res = TEE_GenerateKey(tee_obj, modulus_bits, tee_attrs, tee_count);
	if (res) {
		DMSG("TEE_GenerateKey failed %#"PRIx32, res);

		rc = tee2pkcs_error(res);
		goto out;
	}

	rc = tee2pkcs_rsa_attributes(pub_head, priv_head, tee_obj);

out:
	if (tee_obj != TEE_HANDLE_NULL)
		TEE_CloseObject(tee_obj);

	return rc;
}

size_t rsa_get_input_max_byte_size(TEE_OperationHandle op)
{
	TEE_OperationInfo info = { };

	TEE_GetOperationInfo(op, &info);

	return info.maxKeySize / 8;
}
