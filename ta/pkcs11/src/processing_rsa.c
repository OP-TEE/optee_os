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
#include "processing.h"

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
