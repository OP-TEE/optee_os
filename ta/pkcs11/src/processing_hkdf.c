// SPDX-License-Identifier: BSD-2-Clause
/*
 * HKDF (RFC 5869) built on TEE_MAC_* so extract-only, expand-only and
 * combined modes are exposed uniformly for any HMAC PRF.
 */

#include <pkcs11_ta.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

/* Mirrors the strict GP HMAC type ranges from core/tee/tee_svc_cryp.c */
struct hkdf_prf {
	uint32_t hmac_alg;
	uint32_t hmac_key_type;
	uint32_t hmac_min_bits;
	uint32_t hmac_max_bits;
	uint32_t hash_len;
};

bool processing_is_tee_hkdf(enum pkcs11_mechanism_id proc_id)
{
	return proc_id == PKCS11_CKM_HKDF_DERIVE;
}

static enum pkcs11_rc pkcs2tee_hkdf_prf(uint32_t prf_hash_mech,
					struct hkdf_prf *prf)
{
	switch (prf_hash_mech) {
	case PKCS11_CKM_MD5:
		prf->hmac_alg = TEE_ALG_HMAC_MD5;
		prf->hmac_key_type = TEE_TYPE_HMAC_MD5;
		prf->hmac_min_bits = 64;
		prf->hmac_max_bits = 512;
		prf->hash_len = 16;
		return PKCS11_CKR_OK;
	case PKCS11_CKM_SHA_1:
		prf->hmac_alg = TEE_ALG_HMAC_SHA1;
		prf->hmac_key_type = TEE_TYPE_HMAC_SHA1;
		prf->hmac_min_bits = 80;
		prf->hmac_max_bits = 512;
		prf->hash_len = 20;
		return PKCS11_CKR_OK;
	case PKCS11_CKM_SHA224:
		prf->hmac_alg = TEE_ALG_HMAC_SHA224;
		prf->hmac_key_type = TEE_TYPE_HMAC_SHA224;
		prf->hmac_min_bits = 112;
		prf->hmac_max_bits = 512;
		prf->hash_len = 28;
		return PKCS11_CKR_OK;
	case PKCS11_CKM_SHA256:
		prf->hmac_alg = TEE_ALG_HMAC_SHA256;
		prf->hmac_key_type = TEE_TYPE_HMAC_SHA256;
		prf->hmac_min_bits = 192;
		prf->hmac_max_bits = 1024;
		prf->hash_len = 32;
		return PKCS11_CKR_OK;
	case PKCS11_CKM_SHA384:
		prf->hmac_alg = TEE_ALG_HMAC_SHA384;
		prf->hmac_key_type = TEE_TYPE_HMAC_SHA384;
		prf->hmac_min_bits = 256;
		prf->hmac_max_bits = 1024;
		prf->hash_len = 48;
		return PKCS11_CKR_OK;
	case PKCS11_CKM_SHA512:
		prf->hmac_alg = TEE_ALG_HMAC_SHA512;
		prf->hmac_key_type = TEE_TYPE_HMAC_SHA512;
		prf->hmac_min_bits = 256;
		prf->hmac_max_bits = 1024;
		prf->hash_len = 64;
		return PKCS11_CKR_OK;
	default:
		return PKCS11_CKR_MECHANISM_PARAM_INVALID;
	}
}

/*
 * Keys shorter than the GP HMAC type minimum are zero-padded; per RFC
 * 2104 this yields the same MAC as the unpadded key.
 */
static TEE_Result hmac_one_shot(const struct hkdf_prf *prf,
				const uint8_t *key, size_t key_len,
				const uint8_t *data1, size_t data1_len,
				const uint8_t *data2, size_t data2_len,
				const uint8_t *data3, size_t data3_len,
				uint8_t *out)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
	TEE_Attribute key_attr = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t out_len = prf->hash_len;
	uint8_t padded_key[TEE_MAX_HASH_SIZE * 2] = { 0 };
	size_t min_bytes = prf->hmac_min_bits / 8;
	size_t effective_key_len = key_len;
	const uint8_t *effective_key = key;

	if (key_len * 8 > prf->hmac_max_bits)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key_len < min_bytes) {
		if (min_bytes > sizeof(padded_key))
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(padded_key, key, key_len);
		effective_key = padded_key;
		effective_key_len = min_bytes;
	}

	res = TEE_AllocateOperation(&op, prf->hmac_alg, TEE_MODE_MAC,
				    prf->hmac_max_bits);
	if (res)
		goto out;

	res = TEE_AllocateTransientObject(prf->hmac_key_type,
					  effective_key_len * 8, &key_obj);
	if (res)
		goto out;

	TEE_InitRefAttribute(&key_attr, TEE_ATTR_SECRET_VALUE,
			     (void *)effective_key, effective_key_len);
	res = TEE_PopulateTransientObject(key_obj, &key_attr, 1);
	if (res)
		goto out;

	res = TEE_SetOperationKey(op, key_obj);
	if (res)
		goto out;

	TEE_MACInit(op, NULL, 0);
	if (data1_len)
		TEE_MACUpdate(op, data1, data1_len);
	if (data2_len)
		TEE_MACUpdate(op, data2, data2_len);
	if (data3_len)
		TEE_MACUpdate(op, data3, data3_len);
	res = TEE_MACComputeFinal(op, NULL, 0, out, &out_len);
	if (res)
		goto out;

	if (out_len != prf->hash_len)
		res = TEE_ERROR_GENERIC;

out:
	memzero_explicit(padded_key, sizeof(padded_key));
	if (key_obj != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_obj);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

/* RFC 5869 §2.2: PRK = HMAC-Hash(salt, IKM); empty salt => HashLen zero bytes */
static TEE_Result hkdf_extract(const struct hkdf_prf *prf,
			       const uint8_t *salt, size_t salt_len,
			       const uint8_t *ikm, size_t ikm_len,
			       uint8_t prk_out[TEE_MAX_HASH_SIZE])
{
	uint8_t zero_salt[TEE_MAX_HASH_SIZE] = { 0 };

	if (!salt_len) {
		salt = zero_salt;
		salt_len = prf->hash_len;
	}
	return hmac_one_shot(prf, salt, salt_len, ikm, ikm_len, NULL, 0,
			     NULL, 0, prk_out);
}

/* RFC 5869 §2.3: T(i) = HMAC-Hash(PRK, T(i-1) || info || i), N <= 255 */
static TEE_Result hkdf_expand(const struct hkdf_prf *prf,
			      const uint8_t *prk, size_t prk_len,
			      const uint8_t *info, size_t info_len,
			      uint8_t *okm, size_t okm_len)
{
	uint8_t tn[TEE_MAX_HASH_SIZE] = { 0 };
	size_t tn_len = 0;
	size_t n = 0;
	size_t i = 0;
	size_t off = 0;
	TEE_Result res = TEE_SUCCESS;

	n = (okm_len + prf->hash_len - 1) / prf->hash_len;
	if (n == 0 || n > 255)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 1; i <= n; i++) {
		uint8_t counter = (uint8_t)i;
		size_t take = (i < n) ? prf->hash_len : (okm_len - off);

		res = hmac_one_shot(prf, prk, prk_len, tn, tn_len, info,
				    info_len, &counter, 1, tn);
		if (res)
			return res;

		memcpy(okm + off, tn, take);
		off += take;
		tn_len = prf->hash_len;
	}

	return TEE_SUCCESS;
}

/*
 * Wire format from libckteec serialize_mecha_hkdf_derive_param():
 *   u32 bExtract, u32 bExpand, u32 prfHashMechanism,
 *   u32 ulSaltType, u32 ulSaltLen, bytes salt[ulSaltLen],
 *   u32 hSaltKey, u32 ulInfoLen, bytes info[ulInfoLen]
 */
static enum pkcs11_rc parse_hkdf_params(struct pkcs11_attribute_head *proc_params,
					uint32_t *extract, uint32_t *expand,
					uint32_t *prf_hash,
					uint32_t *salt_type,
					void **salt, uint32_t *salt_len,
					uint32_t *salt_handle,
					void **info, uint32_t *info_len)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get_u32(&args, extract);
	if (rc)
		return rc;
	rc = serialargs_get_u32(&args, expand);
	if (rc)
		return rc;
	rc = serialargs_get_u32(&args, prf_hash);
	if (rc)
		return rc;
	rc = serialargs_get_u32(&args, salt_type);
	if (rc)
		return rc;
	rc = serialargs_get_u32(&args, salt_len);
	if (rc)
		return rc;
	if (*salt_len) {
		rc = serialargs_get_ptr(&args, salt, *salt_len);
		if (rc)
			return rc;
	}
	rc = serialargs_get_u32(&args, salt_handle);
	if (rc)
		return rc;
	rc = serialargs_get_u32(&args, info_len);
	if (rc)
		return rc;
	if (*info_len) {
		rc = serialargs_get_ptr(&args, info, *info_len);
		if (rc)
			return rc;
	}
	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc derive_key_by_hkdf(struct pkcs11_session *session,
				  struct pkcs11_attribute_head *proc_params,
				  struct pkcs11_object *parent,
				  struct obj_attrs **head)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct hkdf_prf prf = { };
	uint32_t extract = 0;
	uint32_t expand = 0;
	uint32_t prf_hash = 0;
	uint32_t salt_type = 0;
	uint32_t salt_handle = 0;
	uint32_t salt_len = 0;
	uint32_t info_len = 0;
	uint32_t out_byte_size = 0;
	uint32_t ikm_size = 0;
	void *salt = NULL;
	void *info = NULL;
	void *ikm_ptr = NULL;
	uint8_t prk[TEE_MAX_HASH_SIZE] = { 0 };
	uint8_t *okm = NULL;

	rc = parse_hkdf_params(proc_params, &extract, &expand, &prf_hash,
			       &salt_type, &salt, &salt_len, &salt_handle,
			       &info, &info_len);
	if (rc)
		goto out;

	if (extract != PKCS11_TRUE && expand != PKCS11_TRUE) {
		rc = PKCS11_CKR_MECHANISM_PARAM_INVALID;
		goto out;
	}

	rc = pkcs2tee_hkdf_prf(prf_hash, &prf);
	if (rc)
		goto out;

	switch (salt_type) {
	case PKCS11_CKF_HKDF_SALT_NULL:
		if (salt || salt_len)
			rc = PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case PKCS11_CKF_HKDF_SALT_DATA:
		break;
	case PKCS11_CKF_HKDF_SALT_KEY: {
		struct pkcs11_object *salt_obj = NULL;
		void *salt_value = NULL;
		uint32_t salt_value_size = 0;

		salt_obj = pkcs11_handle2object(salt_handle, session);
		if (!salt_obj) {
			rc = PKCS11_CKR_KEY_HANDLE_INVALID;
			goto out;
		}
		rc = check_access_attrs_against_token(session, salt_obj->attributes);
		if (rc)
			goto out;
		rc = get_attribute_ptr(salt_obj->attributes, PKCS11_CKA_VALUE,
				       &salt_value, &salt_value_size);
		if (rc)
			goto out;
		salt = salt_value;
		salt_len = salt_value_size;
		break;
	}
	default:
		rc = PKCS11_CKR_MECHANISM_PARAM_INVALID;
		goto out;
	}

	rc = get_attribute_ptr(parent->attributes, PKCS11_CKA_VALUE,
			       &ikm_ptr, &ikm_size);
	if (rc)
		goto out;

	if (remove_empty_attribute(head, PKCS11_CKA_VALUE)) {
		rc = PKCS11_CKR_FUNCTION_FAILED;
		goto out;
	}

	rc = get_u32_attribute(*head, PKCS11_CKA_VALUE_LEN, &out_byte_size);
	if (rc)
		goto out;

	if (!out_byte_size) {
		rc = PKCS11_CKR_KEY_SIZE_RANGE;
		goto out;
	}

	/* RFC 5869: extract-only L == HashLen, expand L <= 255 * HashLen */
	if (extract == PKCS11_TRUE && expand != PKCS11_TRUE &&
	    out_byte_size != prf.hash_len) {
		rc = PKCS11_CKR_KEY_SIZE_RANGE;
		goto out;
	}
	if (expand == PKCS11_TRUE &&
	    out_byte_size > 255 * prf.hash_len) {
		rc = PKCS11_CKR_KEY_SIZE_RANGE;
		goto out;
	}
	if (expand == PKCS11_TRUE && extract != PKCS11_TRUE &&
	    ikm_size < prf.hash_len) {
		rc = PKCS11_CKR_KEY_SIZE_RANGE;
		goto out;
	}

	okm = TEE_Malloc(out_byte_size, 0);
	if (!okm) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto out;
	}

	if (extract == PKCS11_TRUE) {
		res = hkdf_extract(&prf, salt, salt_len, ikm_ptr, ikm_size,
				   prk);
		if (res) {
			rc = tee2pkcs_error(res);
			goto out;
		}
	}

	if (expand == PKCS11_TRUE) {
		const uint8_t *expand_key = NULL;
		size_t expand_key_len = 0;

		if (extract == PKCS11_TRUE) {
			expand_key = prk;
			expand_key_len = prf.hash_len;
		} else {
			expand_key = ikm_ptr;
			expand_key_len = ikm_size;
		}

		res = hkdf_expand(&prf, expand_key, expand_key_len, info,
				  info_len, okm, out_byte_size);
		if (res) {
			rc = tee2pkcs_error(res);
			goto out;
		}
	} else {
		memcpy(okm, prk, out_byte_size);
	}

	rc = add_attribute(head, PKCS11_CKA_VALUE, okm, out_byte_size);

out:
	memzero_explicit(prk, sizeof(prk));
	if (okm) {
		memzero_explicit(okm, out_byte_size);
		TEE_Free(okm);
	}
	release_active_processing(session);

	return rc;
}
