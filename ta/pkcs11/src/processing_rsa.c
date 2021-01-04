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
#include "processing.h"

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
