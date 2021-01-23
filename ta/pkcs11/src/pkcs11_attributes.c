// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <inttypes.h>
#include <pkcs11_ta.h>
#include <stdlib.h>
#include <string_ext.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <trace.h>
#include <util.h>

#include "attributes.h"
#include "handle.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "token_capabilities.h"

static uint32_t pkcs11_func2ckfm(enum processing_func function)
{
	switch (function) {
	case PKCS11_FUNCTION_DIGEST:
		return PKCS11_CKFM_DIGEST;
	case PKCS11_FUNCTION_GENERATE:
		return PKCS11_CKFM_GENERATE;
	case PKCS11_FUNCTION_GENERATE_PAIR:
		return PKCS11_CKFM_GENERATE_KEY_PAIR;
	case PKCS11_FUNCTION_DERIVE:
		return PKCS11_CKFM_DERIVE;
	case PKCS11_FUNCTION_WRAP:
		return PKCS11_CKFM_WRAP;
	case PKCS11_FUNCTION_UNWRAP:
		return PKCS11_CKFM_UNWRAP;
	case PKCS11_FUNCTION_ENCRYPT:
		return PKCS11_CKFM_ENCRYPT;
	case PKCS11_FUNCTION_DECRYPT:
		return PKCS11_CKFM_DECRYPT;
	case PKCS11_FUNCTION_SIGN:
		return PKCS11_CKFM_SIGN;
	case PKCS11_FUNCTION_VERIFY:
		return PKCS11_CKFM_VERIFY;
	case PKCS11_FUNCTION_SIGN_RECOVER:
		return PKCS11_CKFM_SIGN_RECOVER;
	case PKCS11_FUNCTION_VERIFY_RECOVER:
		return PKCS11_CKFM_VERIFY_RECOVER;
	default:
		return 0;
	}
}

enum pkcs11_rc
check_mechanism_against_processing(struct pkcs11_session *session,
				   enum pkcs11_mechanism_id mechanism_type,
				   enum processing_func function,
				   enum processing_step step)
{
	bool allowed = false;

	switch (step) {
	case PKCS11_FUNC_STEP_INIT:
		switch (function) {
		case PKCS11_FUNCTION_IMPORT:
		case PKCS11_FUNCTION_COPY:
		case PKCS11_FUNCTION_MODIFY:
		case PKCS11_FUNCTION_DESTROY:
			return PKCS11_CKR_OK;
		default:
			break;
		}
		/*
		 * Check that the returned PKCS11_CKFM_* flag from
		 * pkcs11_func2ckfm() is among the ones from
		 * mechanism_supported_flags().
		 */
		allowed = mechanism_supported_flags(mechanism_type) &
			  pkcs11_func2ckfm(function);
		break;

	case PKCS11_FUNC_STEP_ONESHOT:
		if (session->processing->always_authen &&
		    !session->processing->relogged)
			return PKCS11_CKR_USER_NOT_LOGGED_IN;

		if (session->processing->step == PKCS11_FUNC_STEP_UPDATE ||
		    session->processing->step == PKCS11_FUNC_STEP_FINAL) {
			EMSG("Cannot perform one-shot on active processing");
			return PKCS11_CKR_OPERATION_ACTIVE;
		}

		allowed = true;
		break;

	case PKCS11_FUNC_STEP_UPDATE:
		if (session->processing->always_authen &&
		    !session->processing->relogged)
			return PKCS11_CKR_USER_NOT_LOGGED_IN;

		if (session->processing->step == PKCS11_FUNC_STEP_ONESHOT ||
		    session->processing->step == PKCS11_FUNC_STEP_FINAL) {
			EMSG("Cannot perform update on finalized processing");
			return PKCS11_CKR_OPERATION_ACTIVE;
		}

		allowed = !mechanism_is_one_shot_only(mechanism_type);
		break;

	case PKCS11_FUNC_STEP_UPDATE_KEY:
		assert(function == PKCS11_FUNCTION_DIGEST);

		if (session->processing->always_authen &&
		    !session->processing->relogged)
			return PKCS11_CKR_USER_NOT_LOGGED_IN;

		allowed = true;
		break;

	case PKCS11_FUNC_STEP_FINAL:
		if (session->processing->always_authen &&
		    !session->processing->relogged)
			return PKCS11_CKR_USER_NOT_LOGGED_IN;

		if (session->processing->step == PKCS11_FUNC_STEP_ONESHOT) {
			EMSG("Cannot perform final on oneshot processing");
			return PKCS11_CKR_OPERATION_ACTIVE;
		}
		return PKCS11_CKR_OK;

	default:
		TEE_Panic(step);
		break;
	}

	if (!allowed) {
		EMSG("Processing %#x/%s not permitted (%u/%u)",
		     (unsigned int)mechanism_type, id2str_proc(mechanism_type),
		     function, step);
		return PKCS11_CKR_MECHANISM_INVALID;
	}

	return PKCS11_CKR_OK;
}

/*
 * Object default boolean attributes as per PKCS#11
 */
static uint8_t *pkcs11_object_default_boolprop(uint32_t attribute)
{
	static const uint8_t bool_true = 1;
	static const uint8_t bool_false;

	switch (attribute) {
	/* As per PKCS#11 default value */
	case PKCS11_CKA_MODIFIABLE:
	case PKCS11_CKA_COPYABLE:
	case PKCS11_CKA_DESTROYABLE:
		return (uint8_t *)&bool_true;
	case PKCS11_CKA_TOKEN:
	case PKCS11_CKA_PRIVATE:
	case PKCS11_CKA_WRAP_WITH_TRUSTED:
	case PKCS11_CKA_ALWAYS_AUTHENTICATE:
	case PKCS11_CKA_SENSITIVE:
		return (uint8_t *)&bool_false;
	/* Token specific default value */
	case PKCS11_CKA_SIGN:
	case PKCS11_CKA_VERIFY:
	case PKCS11_CKA_DERIVE:
	case PKCS11_CKA_ENCRYPT:
	case PKCS11_CKA_DECRYPT:
	case PKCS11_CKA_SIGN_RECOVER:
	case PKCS11_CKA_VERIFY_RECOVER:
	case PKCS11_CKA_WRAP:
	case PKCS11_CKA_UNWRAP:
	case PKCS11_CKA_EXTRACTABLE:
	case PKCS11_CKA_TRUSTED:
		return (uint8_t *)&bool_false;
	default:
		DMSG("No default for boolprop attribute %#"PRIx32, attribute);
		return NULL;
	}
}

/*
 * Object expects several boolean attributes to be set to a default value
 * or to a validate client configuration value. This function append the input
 * attribute (id/size/value) in the serialized object.
 */
static enum pkcs11_rc pkcs11_import_object_boolprop(struct obj_attrs **out,
						    struct obj_attrs *templ,
						    uint32_t attribute)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t bbool = 0;
	uint32_t size = sizeof(uint8_t);
	void *attr = NULL;

	rc = get_attribute(templ, attribute, &bbool, &size);
	if (rc) {
		if (rc != PKCS11_RV_NOT_FOUND)
			return rc;
		attr = pkcs11_object_default_boolprop(attribute);
		if (!attr)
			return PKCS11_CKR_TEMPLATE_INCOMPLETE;
	} else {
		attr = &bbool;
	}

	/* Boolean attributes are 1byte in the ABI, no alignment issue */
	return add_attribute(out, attribute, attr, sizeof(uint8_t));
}

static enum pkcs11_rc set_mandatory_boolprops(struct obj_attrs **out,
					      struct obj_attrs *temp,
					      uint32_t const *bp,
					      size_t bp_count)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t n = 0;

	for (n = 0; n < bp_count; n++) {
		rc = pkcs11_import_object_boolprop(out, temp, bp[n]);
		if (rc)
			return rc;
	}

	return rc;
}

static enum pkcs11_rc set_mandatory_attributes(struct obj_attrs **out,
					       struct obj_attrs *temp,
					       uint32_t const *attrs,
					       size_t attrs_count)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t n = 0;

	for (n = 0; n < attrs_count; n++) {
		uint32_t size = 0;
		void *value = NULL;

		if (get_attribute_ptr(temp, attrs[n], &value, &size))
			return PKCS11_CKR_TEMPLATE_INCOMPLETE;

		rc = add_attribute(out, attrs[n], value, size);
		if (rc)
			return rc;
	}

	return rc;
}

static enum pkcs11_rc get_default_value(enum pkcs11_attr_id id, void **value,
					uint32_t *size)
{
	/* should have been taken care of already */
	assert(!pkcs11_attr_is_boolean(id));

	/* All other attributes have an empty default value */
	*value = NULL;
	*size = 0;
	return PKCS11_CKR_OK;
}

static enum pkcs11_rc set_optional_attributes_with_def(struct obj_attrs **out,
						       struct obj_attrs *temp,
						       uint32_t const *attrs,
						       size_t attrs_count,
						       bool default_to_null)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t n = 0;

	for (n = 0; n < attrs_count; n++) {
		uint32_t size = 0;
		void *value = NULL;

		rc = get_attribute_ptr(temp, attrs[n], &value, &size);
		if (rc == PKCS11_RV_NOT_FOUND) {
			if (default_to_null) {
				rc = get_default_value(attrs[n], &value, &size);
			} else {
				rc = PKCS11_CKR_OK;
				continue;
			}
		}
		if (rc)
			return rc;

		rc = add_attribute(out, attrs[n], value, size);
		if (rc)
			return rc;
	}

	return rc;
}

static enum pkcs11_rc set_attributes_opt_or_null(struct obj_attrs **out,
						 struct obj_attrs *temp,
						 uint32_t const *attrs,
						 size_t attrs_count)
{
	return set_optional_attributes_with_def(out, temp, attrs, attrs_count,
						true /* defaults to empty */);
}

static enum pkcs11_rc set_optional_attributes(struct obj_attrs **out,
					      struct obj_attrs *temp,
					      uint32_t const *attrs,
					      size_t attrs_count)
{
	return set_optional_attributes_with_def(out, temp, attrs, attrs_count,
						false /* no default value */);
}

/*
 * Below are listed the mandated or optional expected attributes for
 * PKCS#11 storage objects.
 *
 * Note: boolprops (mandated boolean attributes) PKCS11_CKA_ALWAYS_SENSITIVE,
 * and PKCS11_CKA_NEVER_EXTRACTABLE are set by the token, not provided
 * in the client template.
 */

/* PKCS#11 specification for any object (session/token) of the storage */
static const uint32_t any_object_boolprops[] = {
	PKCS11_CKA_TOKEN, PKCS11_CKA_PRIVATE,
	PKCS11_CKA_MODIFIABLE, PKCS11_CKA_COPYABLE, PKCS11_CKA_DESTROYABLE,
};

static const uint32_t any_object_opt_or_null[] = {
	PKCS11_CKA_LABEL,
};

/* PKCS#11 specification for raw data object (+any_object_xxx) */
const uint32_t raw_data_opt_or_null[] = {
	PKCS11_CKA_OBJECT_ID, PKCS11_CKA_APPLICATION, PKCS11_CKA_VALUE,
};

/* PKCS#11 specification for certificate object (+pkcs11_any_object_xxx) */
static const uint32_t pkcs11_certificate_mandated[] = {
	PKCS11_CKA_CERTIFICATE_TYPE,
};

static const uint32_t pkcs11_certificate_boolprops[] = {
	PKCS11_CKA_TRUSTED,
};

static const uint32_t pkcs11_certificate_optional[] = {
	PKCS11_CKA_CERTIFICATE_CATEGORY, PKCS11_CKA_CHECK_VALUE,
	PKCS11_CKA_START_DATE, PKCS11_CKA_END_DATE, PKCS11_CKA_PUBLIC_KEY_INFO,
};

/*
 * PKCS#11 specification for X.509 certificate object (+pkcs11_certificate_xxx)
 */
static const uint32_t pkcs11_x509_certificate_mandated[] = {
	PKCS11_CKA_SUBJECT,
};

static const uint32_t pkcs11_x509_certificate_optional[] = {
	PKCS11_CKA_ID, PKCS11_CKA_ISSUER, PKCS11_CKA_SERIAL_NUMBER,
	PKCS11_CKA_VALUE, PKCS11_CKA_URL,
	PKCS11_CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
	PKCS11_CKA_HASH_OF_ISSUER_PUBLIC_KEY,
	PKCS11_CKA_JAVA_MIDP_SECURITY_DOMAIN, PKCS11_CKA_NAME_HASH_ALGORITHM,
};

/* PKCS#11 specification for any key object (+any_object_xxx) */
static const uint32_t any_key_boolprops[] = {
	PKCS11_CKA_DERIVE,
};

static const uint32_t any_key_opt_or_null[] = {
	PKCS11_CKA_ID,
	PKCS11_CKA_START_DATE, PKCS11_CKA_END_DATE,
};

static const uint32_t any_key_optional[] = {
	PKCS11_CKA_ALLOWED_MECHANISMS,
};

/* PKCS#11 specification for any symmetric key (+any_key_xxx) */
static const uint32_t symm_key_boolprops[] = {
	PKCS11_CKA_ENCRYPT, PKCS11_CKA_DECRYPT,
	PKCS11_CKA_SIGN, PKCS11_CKA_VERIFY,
	PKCS11_CKA_WRAP, PKCS11_CKA_UNWRAP,
	PKCS11_CKA_SENSITIVE, PKCS11_CKA_EXTRACTABLE,
	PKCS11_CKA_WRAP_WITH_TRUSTED, PKCS11_CKA_TRUSTED,
};

static const uint32_t symm_key_opt_or_null[] = {
	PKCS11_CKA_WRAP_TEMPLATE, PKCS11_CKA_UNWRAP_TEMPLATE,
	PKCS11_CKA_DERIVE_TEMPLATE, PKCS11_CKA_VALUE,
};

static const uint32_t symm_key_optional[] = {
	PKCS11_CKA_VALUE_LEN,
};

/* PKCS#11 specification for any asymmetric public key (+any_key_xxx) */
static const uint32_t public_key_boolprops[] = {
	PKCS11_CKA_ENCRYPT, PKCS11_CKA_VERIFY, PKCS11_CKA_VERIFY_RECOVER,
	PKCS11_CKA_WRAP,
	PKCS11_CKA_TRUSTED,
};

static const uint32_t public_key_mandated[] = {
};

static const uint32_t public_key_opt_or_null[] = {
	PKCS11_CKA_SUBJECT, PKCS11_CKA_WRAP_TEMPLATE,
	PKCS11_CKA_PUBLIC_KEY_INFO,
};

/* PKCS#11 specification for any asymmetric private key (+any_key_xxx) */
static const uint32_t private_key_boolprops[] = {
	PKCS11_CKA_DECRYPT, PKCS11_CKA_SIGN, PKCS11_CKA_SIGN_RECOVER,
	PKCS11_CKA_UNWRAP,
	PKCS11_CKA_SENSITIVE, PKCS11_CKA_EXTRACTABLE,
	PKCS11_CKA_WRAP_WITH_TRUSTED, PKCS11_CKA_ALWAYS_AUTHENTICATE,
};

static const uint32_t private_key_mandated[] = {
};

static const uint32_t private_key_opt_or_null[] = {
	PKCS11_CKA_SUBJECT, PKCS11_CKA_UNWRAP_TEMPLATE,
	PKCS11_CKA_PUBLIC_KEY_INFO,
};

/* PKCS#11 specification for any RSA key (+public/private_key_xxx) */
static const uint32_t rsa_pub_key_gen_mand[] = {
	PKCS11_CKA_MODULUS_BITS,
};

static const uint32_t rsa_pub_key_create_mand[] = {
	PKCS11_CKA_MODULUS, PKCS11_CKA_PUBLIC_EXPONENT,
};

static const uint32_t rsa_pub_key_gen_opt_or_null[] = {
	PKCS11_CKA_PUBLIC_EXPONENT,
};

static const uint32_t rsa_priv_key_opt_or_null[] = {
	PKCS11_CKA_MODULUS, PKCS11_CKA_PUBLIC_EXPONENT,
	PKCS11_CKA_PRIVATE_EXPONENT,
	PKCS11_CKA_PRIME_1, PKCS11_CKA_PRIME_2,
	PKCS11_CKA_EXPONENT_1, PKCS11_CKA_EXPONENT_2, PKCS11_CKA_COEFFICIENT,
};

/* PKCS#11 specification for any EC key (+public/private_key_xxx) */
static const uint32_t ec_public_key_mandated[] = {
	PKCS11_CKA_EC_PARAMS,
};

static const uint32_t ec_public_key_opt_or_null[] = {
	PKCS11_CKA_EC_POINT,
};

static const uint32_t ec_private_key_mandated[] = {
};

static const uint32_t ec_private_key_opt_or_null[] = {
	PKCS11_CKA_EC_PARAMS,
	PKCS11_CKA_VALUE,
};

static enum pkcs11_rc create_storage_attributes(struct obj_attrs **out,
						struct obj_attrs *temp)
{
	enum pkcs11_class_id class = PKCS11_CKO_UNDEFINED_ID;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = init_attributes_head(out);
	if (rc)
		return rc;

	/* Object class is mandatory */
	class = get_class(temp);
	if (class == PKCS11_CKO_UNDEFINED_ID) {
		EMSG("Class attribute not found");

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}
	rc = add_attribute(out, PKCS11_CKA_CLASS, &class, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = set_mandatory_boolprops(out, temp, any_object_boolprops,
				     ARRAY_SIZE(any_object_boolprops));
	if (rc)
		return rc;

	return set_attributes_opt_or_null(out, temp, any_object_opt_or_null,
					  ARRAY_SIZE(any_object_opt_or_null));
}

static enum pkcs11_rc create_genkey_attributes(struct obj_attrs **out,
					       struct obj_attrs *temp)
{
	uint32_t type = PKCS11_CKO_UNDEFINED_ID;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = create_storage_attributes(out, temp);
	if (rc)
		return rc;

	type = get_key_type(temp);
	if (type == PKCS11_CKK_UNDEFINED_ID) {
		EMSG("Key type attribute not found");

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}
	rc = add_attribute(out, PKCS11_CKA_KEY_TYPE, &type, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = set_mandatory_boolprops(out, temp, any_key_boolprops,
				     ARRAY_SIZE(any_key_boolprops));
	if (rc)
		return rc;

	rc = set_attributes_opt_or_null(out, temp, any_key_opt_or_null,
					ARRAY_SIZE(any_key_opt_or_null));
	if (rc)
		return rc;

	return set_optional_attributes(out, temp, any_key_optional,
				       ARRAY_SIZE(any_key_optional));

}

static enum pkcs11_rc create_symm_key_attributes(struct obj_attrs **out,
						 struct obj_attrs *temp)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_SECRET_KEY);

	rc = create_genkey_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_SECRET_KEY);

	switch (get_key_type(*out)) {
	case PKCS11_CKK_GENERIC_SECRET:
	case PKCS11_CKK_AES:
	case PKCS11_CKK_MD5_HMAC:
	case PKCS11_CKK_SHA_1_HMAC:
	case PKCS11_CKK_SHA256_HMAC:
	case PKCS11_CKK_SHA384_HMAC:
	case PKCS11_CKK_SHA512_HMAC:
	case PKCS11_CKK_SHA224_HMAC:
		break;
	default:
		EMSG("Invalid key type %#"PRIx32"/%s",
		     get_key_type(*out), id2str_key_type(get_key_type(*out)));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	rc = set_mandatory_boolprops(out, temp, symm_key_boolprops,
				     ARRAY_SIZE(symm_key_boolprops));
	if (rc)
		return rc;

	rc = set_attributes_opt_or_null(out, temp, symm_key_opt_or_null,
					ARRAY_SIZE(symm_key_opt_or_null));
	if (rc)
		return rc;

	return set_optional_attributes(out, temp, symm_key_optional,
				       ARRAY_SIZE(symm_key_optional));
}

static enum pkcs11_rc create_data_attributes(struct obj_attrs **out,
					     struct obj_attrs *temp)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_DATA);

	rc = create_storage_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_DATA);

	return set_attributes_opt_or_null(out, temp, raw_data_opt_or_null,
					  ARRAY_SIZE(raw_data_opt_or_null));
}

static enum pkcs11_rc create_certificate_attributes(struct obj_attrs **out,
						    struct obj_attrs *temp)
{
	uint32_t const *mandated = NULL;
	uint32_t const *optional = NULL;
	size_t mandated_count = 0;
	size_t optional_count = 0;
	void *attr_value = NULL;
	uint32_t attr_size = 0;
	uint32_t default_cert_category =
		PKCS11_CK_CERTIFICATE_CATEGORY_UNSPECIFIED;
	uint32_t default_name_hash_alg = PKCS11_CKM_SHA_1;
	uint32_t cert_category = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_CERTIFICATE);

	rc = create_storage_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_CERTIFICATE);

	rc = set_mandatory_boolprops(out, temp, pkcs11_certificate_boolprops,
				     ARRAY_SIZE(pkcs11_certificate_boolprops));
	if (rc)
		return rc;

	rc = set_mandatory_attributes(out, temp, pkcs11_certificate_mandated,
				      ARRAY_SIZE(pkcs11_certificate_mandated));
	if (rc)
		return rc;

	rc = set_optional_attributes(out, temp, pkcs11_certificate_optional,
				     ARRAY_SIZE(pkcs11_certificate_optional));
	if (rc)
		return rc;

	switch (get_certificate_type(*out)) {
	case PKCS11_CKC_X_509:
		mandated = pkcs11_x509_certificate_mandated;
		optional = pkcs11_x509_certificate_optional;
		mandated_count = ARRAY_SIZE(pkcs11_x509_certificate_mandated);
		optional_count = ARRAY_SIZE(pkcs11_x509_certificate_optional);
		break;
	default:
		EMSG("Invalid certificate type %#"PRIx32"/%s",
		     get_certificate_type(*out),
		     id2str_certificate_type(get_certificate_type(*out)));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	rc = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rc)
		return rc;

	rc = set_optional_attributes(out, temp, optional, optional_count);
	if (rc)
		return rc;

	attr_size = 0;
	rc = get_attribute_ptr(*out, PKCS11_CKA_CERTIFICATE_CATEGORY,
			       &attr_value, &attr_size);
	if (rc == PKCS11_CKR_OK && attr_size == sizeof(cert_category)) {
		/* Sanitize certificate category */
		TEE_MemMove(&cert_category, attr_value, sizeof(cert_category));

		switch (cert_category) {
		case PKCS11_CK_CERTIFICATE_CATEGORY_UNSPECIFIED:
		case PKCS11_CK_CERTIFICATE_CATEGORY_TOKEN_USER:
		case PKCS11_CK_CERTIFICATE_CATEGORY_AUTHORITY:
		case PKCS11_CK_CERTIFICATE_CATEGORY_OTHER_ENTITY:
			break;
		default:
			EMSG("Invalid certificate category %#"PRIx32,
			     cert_category);

			return PKCS11_CKR_ATTRIBUTE_VALUE_INVALID;
		}
	} else if (rc == PKCS11_RV_NOT_FOUND) {
		/* Set default category when missing */
		rc = set_attribute(out, PKCS11_CKA_CERTIFICATE_CATEGORY,
				   &default_cert_category,
				   sizeof(default_cert_category));
		if (rc)
			return rc;
	} else {
		/* All other cases are errors */
		EMSG("Invalid certificate category");

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	attr_size = 0;
	rc = get_attribute_ptr(*out, PKCS11_CKA_NAME_HASH_ALGORITHM, NULL,
			       &attr_size);
	if (rc == PKCS11_CKR_OK && attr_size == sizeof(uint32_t)) {
		/* We accept any algorithm what caller wanted to specify */
	} else if (rc == PKCS11_RV_NOT_FOUND) {
		/* Set default hash algorithm when missing */
		rc = set_attribute(out, PKCS11_CKA_NAME_HASH_ALGORITHM,
				   &default_name_hash_alg,
				   sizeof(default_name_hash_alg));
		if (rc)
			return rc;
	} else {
		/* All other cases are errors */
		EMSG("Invalid name hash algorithm");

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	return rc;
}

static enum pkcs11_rc create_pub_key_attributes(struct obj_attrs **out,
						struct obj_attrs *temp,
						enum processing_func function)
{
	uint32_t const *mandated = NULL;
	uint32_t const *oon = NULL;
	size_t mandated_count = 0;
	size_t oon_count = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_PUBLIC_KEY);

	rc = create_genkey_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_PUBLIC_KEY);

	rc = set_mandatory_boolprops(out, temp, public_key_boolprops,
				     ARRAY_SIZE(public_key_boolprops));
	if (rc)
		return rc;

	rc = set_mandatory_attributes(out, temp, public_key_mandated,
				      ARRAY_SIZE(public_key_mandated));
	if (rc)
		return rc;

	rc = set_attributes_opt_or_null(out, temp,
					public_key_opt_or_null,
					ARRAY_SIZE(public_key_opt_or_null));
	if (rc)
		return rc;

	switch (get_key_type(*out)) {
	case PKCS11_CKK_RSA:
		switch (function) {
		case PKCS11_FUNCTION_GENERATE_PAIR:
			mandated = rsa_pub_key_gen_mand;
			oon = rsa_pub_key_gen_opt_or_null;
			mandated_count = ARRAY_SIZE(rsa_pub_key_gen_mand);
			oon_count = ARRAY_SIZE(rsa_pub_key_gen_opt_or_null);
			break;
		case PKCS11_FUNCTION_IMPORT:
			mandated = rsa_pub_key_create_mand;
			mandated_count = ARRAY_SIZE(rsa_pub_key_create_mand);
			break;
		default:
			EMSG("Unsupported function %#"PRIx32"/%s", function,
			     id2str_function(function));

			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}
		break;
	case PKCS11_CKK_EC:
		mandated = ec_public_key_mandated;
		oon = ec_public_key_opt_or_null;
		mandated_count = ARRAY_SIZE(ec_public_key_mandated);
		oon_count = ARRAY_SIZE(ec_public_key_opt_or_null);
		break;
	default:
		EMSG("Invalid key type %#"PRIx32"/%s",
		     get_key_type(*out), id2str_key_type(get_key_type(*out)));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	rc = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rc)
		return rc;

	return set_attributes_opt_or_null(out, temp, oon, oon_count);
}

static enum pkcs11_rc create_priv_key_attributes(struct obj_attrs **out,
						 struct obj_attrs *temp)
{
	uint32_t const *mandated = NULL;
	uint32_t const *oon = NULL;
	size_t mandated_count = 0;
	size_t oon_count = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_PRIVATE_KEY);

	rc = create_genkey_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_PRIVATE_KEY);

	rc = set_mandatory_boolprops(out, temp, private_key_boolprops,
				     ARRAY_SIZE(private_key_boolprops));
	if (rc)
		return rc;

	rc = set_mandatory_attributes(out, temp, private_key_mandated,
				      ARRAY_SIZE(private_key_mandated));
	if (rc)
		return rc;

	rc = set_attributes_opt_or_null(out, temp, private_key_opt_or_null,
					ARRAY_SIZE(private_key_opt_or_null));
	if (rc)
		return rc;

	switch (get_key_type(*out)) {
	case PKCS11_CKK_RSA:
		oon = rsa_priv_key_opt_or_null;
		oon_count = ARRAY_SIZE(rsa_priv_key_opt_or_null);
		break;
	case PKCS11_CKK_EC:
		mandated = ec_private_key_mandated;
		oon = ec_private_key_opt_or_null;
		mandated_count = ARRAY_SIZE(ec_private_key_mandated);
		oon_count = ARRAY_SIZE(ec_private_key_opt_or_null);
		break;
	default:
		EMSG("Invalid key type %#"PRIx32"/%s",
		     get_key_type(*out), id2str_key_type(get_key_type(*out)));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	rc = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rc)
		return rc;

	return set_attributes_opt_or_null(out, temp, oon, oon_count);
}

static enum pkcs11_rc
sanitize_symm_key_attributes(struct obj_attrs **temp,
			     enum processing_func function)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint32_t a_size = 0;

	assert(get_class(*temp) == PKCS11_CKO_SECRET_KEY);

	rc = get_attribute_ptr(*temp, PKCS11_CKA_VALUE, NULL, &a_size);

	switch (get_key_type(*temp)) {
	case PKCS11_CKK_GENERIC_SECRET:
	case PKCS11_CKK_AES:
	case PKCS11_CKK_MD5_HMAC:
	case PKCS11_CKK_SHA_1_HMAC:
	case PKCS11_CKK_SHA256_HMAC:
	case PKCS11_CKK_SHA384_HMAC:
	case PKCS11_CKK_SHA512_HMAC:
	case PKCS11_CKK_SHA224_HMAC:
		switch (function) {
		case PKCS11_FUNCTION_IMPORT:
			/* CKA_VALUE is a mandatory with C_CreateObject */
			if (rc || a_size == 0)
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;

			if (get_attribute_ptr(*temp, PKCS11_CKA_VALUE_LEN, NULL,
					      NULL) != PKCS11_RV_NOT_FOUND)
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;

			return add_attribute(temp, PKCS11_CKA_VALUE_LEN,
					     &a_size, sizeof(uint32_t));
		case PKCS11_FUNCTION_GENERATE:
			if (rc != PKCS11_RV_NOT_FOUND)
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;
			break;
		default:
			break;
		}
		break;
	default:
		EMSG("Invalid key type %#"PRIx32"/%s",
		     get_key_type(*temp), id2str_key_type(get_key_type(*temp)));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	return PKCS11_CKR_OK;
}

/*
 * Create an attribute list for a new object from a template and a parent
 * object (optional) for an object generation function (generate, copy,
 * derive...).
 *
 * PKCS#11 directives on the supplied template and expected return value:
 * - template has an invalid attribute ID: ATTRIBUTE_TYPE_INVALID
 * - template has an invalid value for an attribute: ATTRIBUTE_VALID_INVALID
 * - template has value for a read-only attribute: ATTRIBUTE_READ_ONLY
 * - template+default+parent => still miss an attribute: TEMPLATE_INCONSISTENT
 *
 * INFO on PKCS11_CMD_COPY_OBJECT:
 * - parent PKCS11_CKA_COPYIABLE=false => return ACTION_PROHIBITED.
 * - template can specify PKCS11_CKA_TOKEN, PKCS11_CKA_PRIVATE,
 *   PKCS11_CKA_MODIFIABLE, PKCS11_CKA_DESTROYABLE.
 * - SENSITIVE can change from false to true, not from true to false.
 * - LOCAL is the parent LOCAL
 */
enum pkcs11_rc
create_attributes_from_template(struct obj_attrs **out, void *template,
				size_t template_size,
				struct obj_attrs *parent,
				enum processing_func function,
				enum pkcs11_mechanism_id mecha,
				enum pkcs11_class_id template_class)
{
	struct obj_attrs *temp = NULL;
	struct obj_attrs *attrs = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t local = 0;
	uint8_t always_sensitive = 0;
	uint8_t never_extract = 0;
	uint8_t extractable = 0;
	uint32_t class = PKCS11_UNDEFINED_ID;
	uint32_t type = PKCS11_UNDEFINED_ID;
	uint32_t mechanism_id = PKCS11_CKM_UNDEFINED_ID;
	struct obj_attrs *req_attrs = NULL;
	uint32_t size = 0;
	uint32_t indirect_template = PKCS11_CKA_UNDEFINED_ID;

#ifdef DEBUG	/* Sanity: check function argument */
	trace_attributes_from_api_head("template", template, template_size);
	switch (function) {
	case PKCS11_FUNCTION_GENERATE:
	case PKCS11_FUNCTION_GENERATE_PAIR:
	case PKCS11_FUNCTION_IMPORT:
	case PKCS11_FUNCTION_MODIFY:
	case PKCS11_FUNCTION_DERIVE:
	case PKCS11_FUNCTION_UNWRAP:
	case PKCS11_FUNCTION_COPY:
		break;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
#endif

	/*
	 * For PKCS11_FUNCTION_GENERATE, find the class and type
	 * based on the mechanism. These will be passed as hint
	 * sanitize_client_object() and added in temp if not
	 * already present
	 */
	if (function == PKCS11_FUNCTION_GENERATE) {
		switch (mecha) {
		case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
			class = PKCS11_CKO_SECRET_KEY;
			type = PKCS11_CKK_GENERIC_SECRET;
			break;
		case PKCS11_CKM_AES_KEY_GEN:
			class = PKCS11_CKO_SECRET_KEY;
			type = PKCS11_CKK_AES;
			break;
		default:
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
		}
	}

	/*
	 * For PKCS11_FUNCTION_GENERATE_PAIR, find the class and type
	 * based on the mechanism. These will be passed as hint
	 * sanitize_client_object() and added in temp if not
	 * already present
	 */
	if (function == PKCS11_FUNCTION_GENERATE_PAIR) {
		switch (mecha) {
		case PKCS11_CKM_EC_KEY_PAIR_GEN:
			class = template_class;
			type = PKCS11_CKK_EC;
			break;
		case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
			class = template_class;
			type = PKCS11_CKK_RSA;
			break;
		default:
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
		}
	}

	/*
	 * Check and remove duplicates if any and create a new temporary
	 * template
	 */
	rc = sanitize_client_object(&temp, template, template_size, class,
				    type);
	if (rc)
		goto out;

	/*
	 * For function type modify and copy return the created template
	 * from here. Rest of the code below is for creating objects
	 * or generating keys.
	 */
	switch (function) {
	case PKCS11_FUNCTION_MODIFY:
	case PKCS11_FUNCTION_COPY:
		*out = temp;
		return rc;
	case PKCS11_FUNCTION_DERIVE:
	case PKCS11_FUNCTION_UNWRAP:
		if (function == PKCS11_FUNCTION_UNWRAP)
			indirect_template = PKCS11_CKA_UNWRAP_TEMPLATE;
		else
			indirect_template = PKCS11_CKA_DERIVE_TEMPLATE;

		rc = get_attribute_ptr(parent, indirect_template,
				       (void *)&req_attrs, &size);
		if (rc == PKCS11_CKR_OK && size != 0) {
			rc = attributes_match_add_reference(&temp, req_attrs);
			if (rc)
				goto out;
		}
		break;
	default:
		break;
	}

	/*
	 * Check if class and type in temp are consistent with the mechanism
	 */
	switch (mecha) {
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
		if (get_class(temp) != PKCS11_CKO_SECRET_KEY ||
		    get_key_type(temp) != PKCS11_CKK_GENERIC_SECRET) {
			rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
			goto out;
		}
		break;
	case PKCS11_CKM_AES_KEY_GEN:
		if (get_class(temp) != PKCS11_CKO_SECRET_KEY ||
		    get_key_type(temp) != PKCS11_CKK_AES) {
			rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
			goto out;
		}
		break;
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
		if ((get_class(temp) != PKCS11_CKO_PUBLIC_KEY &&
		     get_class(temp) != PKCS11_CKO_PRIVATE_KEY) ||
		    get_key_type(temp) != PKCS11_CKK_EC) {
			rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
			goto out;
		}
		break;
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
		if ((get_class(temp) != PKCS11_CKO_PUBLIC_KEY &&
		     get_class(temp) != PKCS11_CKO_PRIVATE_KEY) ||
		    get_key_type(temp) != PKCS11_CKK_RSA) {
			rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
			goto out;
		}
		break;
	default:
		break;
	}

	if (!sanitize_consistent_class_and_type(temp)) {
		EMSG("Inconsistent class/type");
		rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
		goto out;
	}

	/*
	 * TBD - Add a check to see if temp contains any attribute which
	 * is not consistent with the object class or type and return error.
	 * In current implementation such attributes are ignored and not
	 * added to final object while PKCS#11 specification expects a
	 * failure and an error code be returned.
	 */

	switch (get_class(temp)) {
	case PKCS11_CKO_DATA:
		rc = create_data_attributes(&attrs, temp);
		break;
	case PKCS11_CKO_CERTIFICATE:
		rc = create_certificate_attributes(&attrs, temp);
		break;
	case PKCS11_CKO_SECRET_KEY:
		rc = sanitize_symm_key_attributes(&temp, function);
		if (rc)
			goto out;
		rc = create_symm_key_attributes(&attrs, temp);
		break;
	case PKCS11_CKO_PUBLIC_KEY:
		rc = create_pub_key_attributes(&attrs, temp, function);
		break;
	case PKCS11_CKO_PRIVATE_KEY:
		rc = create_priv_key_attributes(&attrs, temp);
		break;
	default:
		DMSG("Invalid object class %#"PRIx32"/%s",
		     get_class(temp), id2str_class(get_class(temp)));

		rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
		break;
	}
	if (rc)
		goto out;

	if (get_attribute_ptr(temp, PKCS11_CKA_LOCAL, NULL, NULL) !=
	    PKCS11_RV_NOT_FOUND) {
		rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
		goto out;
	}

	if (get_attribute_ptr(temp, PKCS11_CKA_KEY_GEN_MECHANISM, NULL, NULL) !=
	    PKCS11_RV_NOT_FOUND) {
		rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
		goto out;
	}

	switch (function) {
	case PKCS11_FUNCTION_GENERATE:
	case PKCS11_FUNCTION_GENERATE_PAIR:
		local = PKCS11_TRUE;
		break;
	case PKCS11_FUNCTION_IMPORT:
	case PKCS11_FUNCTION_DERIVE:
	case PKCS11_FUNCTION_UNWRAP:
	default:
		local = PKCS11_FALSE;
		break;
	}
	rc = add_attribute(&attrs, PKCS11_CKA_LOCAL, &local, sizeof(local));
	if (rc)
		goto out;

	switch (get_class(attrs)) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
		always_sensitive = PKCS11_FALSE;
		never_extract = PKCS11_FALSE;

		switch (function) {
		case PKCS11_FUNCTION_DERIVE:
			always_sensitive =
				get_bool(parent, PKCS11_CKA_ALWAYS_SENSITIVE) &&
				get_bool(attrs, PKCS11_CKA_SENSITIVE);
			never_extract =
			       get_bool(parent, PKCS11_CKA_NEVER_EXTRACTABLE) &&
			       !get_bool(attrs, PKCS11_CKA_EXTRACTABLE);
			break;
		case PKCS11_FUNCTION_UNWRAP:
			always_sensitive = PKCS11_FALSE;
			never_extract = PKCS11_FALSE;
			extractable = PKCS11_TRUE;

			/*
			 * Check if template passed by user has CKA_EXTRACTABLE.
			 * If not, by default value of CKA_EXTRACTABLE is set as
			 * TRUE.
			 */
			if (get_attribute_ptr(temp, PKCS11_CKA_EXTRACTABLE,
					      NULL,
					      NULL) == PKCS11_RV_NOT_FOUND) {
				rc = set_attribute(&attrs,
						   PKCS11_CKA_EXTRACTABLE,
						   &extractable,
						   sizeof(extractable));
				if (rc)
					goto out;
			}
			break;
		case PKCS11_FUNCTION_GENERATE:
		case PKCS11_FUNCTION_GENERATE_PAIR:
			always_sensitive = get_bool(attrs,
						    PKCS11_CKA_SENSITIVE);
			never_extract = !get_bool(attrs,
						  PKCS11_CKA_EXTRACTABLE);
			break;
		default:
			break;
		}

		rc = add_attribute(&attrs, PKCS11_CKA_ALWAYS_SENSITIVE,
				   &always_sensitive, sizeof(always_sensitive));
		if (rc)
			goto out;

		rc = add_attribute(&attrs, PKCS11_CKA_NEVER_EXTRACTABLE,
				   &never_extract, sizeof(never_extract));
		if (rc)
			goto out;

		/* Keys mandate attribute PKCS11_CKA_KEY_GEN_MECHANISM */
		if (local)
			mechanism_id = mecha;
		else
			mechanism_id = PKCS11_CK_UNAVAILABLE_INFORMATION;

		rc = add_attribute(&attrs, PKCS11_CKA_KEY_GEN_MECHANISM,
				   &mechanism_id, sizeof(mechanism_id));
		if (rc)
			goto out;
		break;

	default:
		break;
	}

	*out = attrs;

#ifdef DEBUG
	trace_attributes("object", attrs);
#endif

out:
	TEE_Free(temp);
	if (rc)
		TEE_Free(attrs);

	return rc;
}

static enum pkcs11_rc check_attrs_misc_integrity(struct obj_attrs *head)
{
	if (get_bool(head, PKCS11_CKA_NEVER_EXTRACTABLE) &&
	    get_bool(head, PKCS11_CKA_EXTRACTABLE)) {
		DMSG("Never/Extractable attributes mismatch %d/%d",
		     get_bool(head, PKCS11_CKA_NEVER_EXTRACTABLE),
		     get_bool(head, PKCS11_CKA_EXTRACTABLE));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	if (get_bool(head, PKCS11_CKA_ALWAYS_SENSITIVE) &&
	    !get_bool(head, PKCS11_CKA_SENSITIVE)) {
		DMSG("Sensitive/always attributes mismatch %d/%d",
		     get_bool(head, PKCS11_CKA_SENSITIVE),
		     get_bool(head, PKCS11_CKA_ALWAYS_SENSITIVE));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	return PKCS11_CKR_OK;
}

bool object_is_private(struct obj_attrs *head)
{
	return get_bool(head, PKCS11_CKA_PRIVATE);
}

bool object_is_token(struct obj_attrs *head)
{
	return get_bool(head, PKCS11_CKA_TOKEN);
}

bool object_is_modifiable(struct obj_attrs *head)
{
	return get_bool(head, PKCS11_CKA_MODIFIABLE);
}

bool object_is_copyable(struct obj_attrs *head)
{
	return get_bool(head, PKCS11_CKA_COPYABLE);
}

/*
 * Check access to object against authentication to token
 */
enum pkcs11_rc check_access_attrs_against_token(struct pkcs11_session *session,
						struct obj_attrs *head)
{
	bool private = true;

	switch (get_class(head)) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_DATA:
	case PKCS11_CKO_CERTIFICATE:
		private = object_is_private(head);
		break;
	default:
		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	if (private && (pkcs11_session_is_public(session) ||
			pkcs11_session_is_so(session))) {
		DMSG("Private object access from a public or SO session");

		return PKCS11_CKR_USER_NOT_LOGGED_IN;
	}

	return PKCS11_CKR_OK;
}

/*
 * Check the attributes of a to-be-created object matches the token state
 */
enum pkcs11_rc check_created_attrs_against_token(struct pkcs11_session *session,
						 struct obj_attrs *head)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = check_attrs_misc_integrity(head);
	if (rc)
		return rc;

	if (get_bool(head, PKCS11_CKA_TRUSTED) &&
	    !pkcs11_session_is_so(session)) {
		DMSG("Can't create trusted object");

		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	if (get_bool(head, PKCS11_CKA_TOKEN) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't create persistent object");

		return PKCS11_CKR_SESSION_READ_ONLY;
	}

	/*
	 * TODO: START_DATE and END_DATE: complies with current time?
	 */
	return PKCS11_CKR_OK;
}

#define DMSG_BAD_BBOOL(attr, proc, head)				\
	do {								\
		uint32_t __maybe_unused _attr = (attr);			\
		uint8_t __maybe_unused _bvalue = 0;			\
		enum pkcs11_rc __maybe_unused _rc = PKCS11_CKR_OK;	\
									\
		_rc = get_attribute((head), _attr, &_bvalue, NULL);	\
		DMSG("%s issue for %s: %sfound, value %"PRIu8,		\
		     id2str_attr(_attr), id2str_proc((proc)),		\
		     _rc ? "not " : "", _bvalue);			\
	} while (0)

static bool __maybe_unused check_attr_bval(uint32_t proc_id __maybe_unused,
					   struct obj_attrs *head,
					   uint32_t attribute, bool val)
{
	uint8_t bbool = 0;
	uint32_t sz = sizeof(bbool);

	if (!get_attribute(head, attribute, &bbool, &sz) && !!bbool == val)
		return true;

	DMSG_BAD_BBOOL(attribute, proc_id, head);
	return false;
}

/*
 * Check the attributes of a new secret match the processing/mechanism
 * used to create it.
 *
 * @proc_id - PKCS11_CKM_xxx
 * @head - head of the attributes of the to-be-created object.
 */
enum pkcs11_rc check_created_attrs_against_processing(uint32_t proc_id,
						      struct obj_attrs *head)
{
	/*
	 * Processings that do not create secrets are not expected to call
	 * this function which would panic.
	 */
	switch (proc_id) {
	case PKCS11_PROCESSING_IMPORT:
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_ECB_ENCRYPT_DATA:
	case PKCS11_CKM_AES_CBC_ENCRYPT_DATA:
		assert(check_attr_bval(proc_id, head, PKCS11_CKA_LOCAL, false));
		break;
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
	case PKCS11_CKM_AES_KEY_GEN:
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
		assert(check_attr_bval(proc_id, head, PKCS11_CKA_LOCAL, true));
		break;
	default:
		TEE_Panic(proc_id);
		break;
	}

	switch (proc_id) {
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
		assert(get_key_type(head) == PKCS11_CKK_GENERIC_SECRET);
		break;
	case PKCS11_CKM_AES_KEY_GEN:
		assert(get_key_type(head) == PKCS11_CKK_AES);
		break;
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
		assert(get_key_type(head) == PKCS11_CKK_EC);
		break;
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
		assert(get_key_type(head) == PKCS11_CKK_RSA);
		break;
	case PKCS11_PROCESSING_IMPORT:
	default:
		break;
	}

	return PKCS11_CKR_OK;
}

/* Return min and max key size supported for a key_type in bytes */
static void get_key_min_max_sizes(enum pkcs11_key_type key_type,
				  uint32_t *min_key_size,
				  uint32_t *max_key_size)
{
	enum pkcs11_mechanism_id mechanism = PKCS11_CKM_UNDEFINED_ID;

	switch (key_type) {
	case PKCS11_CKK_GENERIC_SECRET:
		mechanism = PKCS11_CKM_GENERIC_SECRET_KEY_GEN;
		break;
	case PKCS11_CKK_AES:
		mechanism = PKCS11_CKM_AES_KEY_GEN;
		break;
	case PKCS11_CKK_MD5_HMAC:
		mechanism = PKCS11_CKM_MD5_HMAC;
		break;
	case PKCS11_CKK_SHA_1_HMAC:
		mechanism = PKCS11_CKM_SHA_1_HMAC;
		break;
	case PKCS11_CKK_SHA224_HMAC:
		mechanism = PKCS11_CKM_SHA224_HMAC;
		break;
	case PKCS11_CKK_SHA256_HMAC:
		mechanism = PKCS11_CKM_SHA256_HMAC;
		break;
	case PKCS11_CKK_SHA384_HMAC:
		mechanism = PKCS11_CKM_SHA384_HMAC;
		break;
	case PKCS11_CKK_SHA512_HMAC:
		mechanism = PKCS11_CKM_SHA512_HMAC;
		break;
	case PKCS11_CKK_EC:
		mechanism = PKCS11_CKM_EC_KEY_PAIR_GEN;
		break;
	case PKCS11_CKK_RSA:
		mechanism = PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;
	default:
		TEE_Panic(key_type);
		break;
	}

	mechanism_supported_key_sizes_bytes(mechanism, min_key_size,
					    max_key_size);
}

enum pkcs11_rc check_created_attrs(struct obj_attrs *key1,
				   struct obj_attrs *key2)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct obj_attrs *secret = NULL;
	struct obj_attrs *private = NULL;
	struct obj_attrs *public = NULL;
	uint32_t max_key_size = 0;
	uint32_t min_key_size = 0;
	uint32_t key_length = 0;

	switch (get_class(key1)) {
	case PKCS11_CKO_SECRET_KEY:
		secret = key1;
		break;
	case PKCS11_CKO_PUBLIC_KEY:
		public = key1;
		break;
	case PKCS11_CKO_PRIVATE_KEY:
		private = key1;
		break;
	default:
		return PKCS11_CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (key2) {
		switch (get_class(key2)) {
		case PKCS11_CKO_PUBLIC_KEY:
			public = key2;
			if (private == key1)
				break;

			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		case PKCS11_CKO_PRIVATE_KEY:
			private = key2;
			if (public == key1)
				break;

			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		default:
			return PKCS11_CKR_ATTRIBUTE_VALUE_INVALID;
		}

		if (get_key_type(private) != get_key_type(public))
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	if (secret) {
		switch (get_key_type(secret)) {
		case PKCS11_CKK_AES:
		case PKCS11_CKK_GENERIC_SECRET:
		case PKCS11_CKK_MD5_HMAC:
		case PKCS11_CKK_SHA_1_HMAC:
		case PKCS11_CKK_SHA224_HMAC:
		case PKCS11_CKK_SHA256_HMAC:
		case PKCS11_CKK_SHA384_HMAC:
		case PKCS11_CKK_SHA512_HMAC:
			break;
		default:
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}

		/* Get key size */
		rc = get_u32_attribute(secret, PKCS11_CKA_VALUE_LEN,
				       &key_length);
		if (rc)
			return PKCS11_CKR_TEMPLATE_INCOMPLETE;
	}
	if (public) {
		switch (get_key_type(public)) {
		case PKCS11_CKK_RSA:
			/* Get key size */
			rc = get_u32_attribute(public, PKCS11_CKA_MODULUS_BITS,
					       &key_length);
			if (rc)
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;
			key_length = ROUNDUP(key_length, 8) / 8;
			break;
		case PKCS11_CKK_EC:
			break;
		default:
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}
	}
	if (private) {
		switch (get_key_type(private)) {
		case PKCS11_CKK_RSA:
		case PKCS11_CKK_EC:
			break;
		default:
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}
	}

	/*
	 * Check key size for symmetric keys and RSA keys
	 * EC is bound to domains, no need to check here.
	 */
	switch (get_key_type(key1)) {
	case PKCS11_CKK_EC:
		return PKCS11_CKR_OK;
	default:
		break;
	}

	get_key_min_max_sizes(get_key_type(key1), &min_key_size, &max_key_size);
	if (key_length < min_key_size || key_length > max_key_size) {
		EMSG("Length %"PRIu32" vs range [%"PRIu32" %"PRIu32"]",
		     key_length, min_key_size, max_key_size);

		return PKCS11_CKR_KEY_SIZE_RANGE;
	}

	if (secret && get_key_type(secret) == PKCS11_CKK_AES) {
		if (key_length != 16 && key_length != 24 && key_length != 32)
			return PKCS11_CKR_KEY_SIZE_RANGE;
	}

	return PKCS11_CKR_OK;
}

/* Check processing ID against attribute ALLOWED_MECHANISMS if any */
static bool parent_key_complies_allowed_processings(uint32_t proc_id,
						    struct obj_attrs *head)
{
	char *attr = NULL;
	uint32_t size = 0;
	uint32_t proc = 0;
	size_t count = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	rc = get_attribute_ptr(head, PKCS11_CKA_ALLOWED_MECHANISMS,
			       (void *)&attr, &size);
	if (rc == PKCS11_RV_NOT_FOUND)
		return true;
	if (rc) {
		EMSG("unexpected attributes state");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	for (count = size / sizeof(uint32_t); count; count--) {
		TEE_MemMove(&proc, attr, sizeof(uint32_t));
		attr += sizeof(uint32_t);

		if (proc == proc_id)
			return true;
	}

	DMSG("can't find %s in allowed list", id2str_proc(proc_id));
	return false;
}

static enum pkcs11_attr_id func_to_attr(enum processing_func func)
{
	switch (func) {
	case PKCS11_FUNCTION_ENCRYPT:
		return PKCS11_CKA_ENCRYPT;
	case PKCS11_FUNCTION_DECRYPT:
		return PKCS11_CKA_DECRYPT;
	case PKCS11_FUNCTION_SIGN:
		return PKCS11_CKA_SIGN;
	case PKCS11_FUNCTION_VERIFY:
		return PKCS11_CKA_VERIFY;
	case PKCS11_FUNCTION_WRAP:
		return PKCS11_CKA_WRAP;
	case PKCS11_FUNCTION_UNWRAP:
		return PKCS11_CKA_UNWRAP;
	case PKCS11_FUNCTION_DERIVE:
		return PKCS11_CKA_DERIVE;
	default:
		return PKCS11_CKA_UNDEFINED_ID;
	}
}

enum pkcs11_rc
check_parent_attrs_against_processing(enum pkcs11_mechanism_id proc_id,
				      enum processing_func function,
				      struct obj_attrs *head)
{
	enum pkcs11_class_id key_class = get_class(head);
	enum pkcs11_key_type key_type = get_key_type(head);
	enum pkcs11_attr_id attr = func_to_attr(function);

	if (!get_bool(head, attr)) {
		DMSG("%s not permitted", id2str_attr(attr));
		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	/* Check processing complies with parent key family */
	switch (proc_id) {
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_AES_CMAC_GENERAL:
		if (key_class == PKCS11_CKO_SECRET_KEY &&
		    key_type == PKCS11_CKK_AES)
			break;

		DMSG("%s invalid key %s/%s", id2str_proc(proc_id),
		     id2str_class(key_class), id2str_key_type(key_type));

		if (function == PKCS11_FUNCTION_WRAP)
			return PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
		else if (function == PKCS11_FUNCTION_UNWRAP)
			return PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
		else
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;

	case PKCS11_CKM_AES_ECB_ENCRYPT_DATA:
	case PKCS11_CKM_AES_CBC_ENCRYPT_DATA:
		if (key_class != PKCS11_CKO_SECRET_KEY &&
		    key_type != PKCS11_CKK_AES)
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;

		if (get_bool(head, PKCS11_CKA_ENCRYPT)) {
			/*
			 * Intentionally refuse to proceed despite
			 * PKCS#11 specifications v2.40 and v3.0 not expecting
			 * this behavior to avoid potential security issue
			 * where keys derived by these mechanisms can be
			 * revealed by doing data encryption using parent key.
			 */
			return PKCS11_CKR_FUNCTION_FAILED;
		}

		break;
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
		if (key_class != PKCS11_CKO_SECRET_KEY)
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;

		if (key_type == PKCS11_CKK_GENERIC_SECRET)
			break;

		switch (proc_id) {
		case PKCS11_CKM_MD5_HMAC:
		case PKCS11_CKM_MD5_HMAC_GENERAL:
			if (key_type == PKCS11_CKK_MD5_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA_1_HMAC:
		case PKCS11_CKM_SHA_1_HMAC_GENERAL:
			if (key_type == PKCS11_CKK_SHA_1_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA224_HMAC:
		case PKCS11_CKM_SHA224_HMAC_GENERAL:
			if (key_type == PKCS11_CKK_SHA224_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA256_HMAC:
		case PKCS11_CKM_SHA256_HMAC_GENERAL:
			if (key_type == PKCS11_CKK_SHA256_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA384_HMAC:
		case PKCS11_CKM_SHA384_HMAC_GENERAL:
			if (key_type == PKCS11_CKK_SHA384_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA512_HMAC:
		case PKCS11_CKM_SHA512_HMAC_GENERAL:
			if (key_type == PKCS11_CKK_SHA512_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		default:
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;

	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
		if (key_type != PKCS11_CKK_EC) {
			EMSG("Invalid key %s for mechanism %s",
			     id2str_type(key_type, key_class),
			     id2str_proc(proc_id));

			return PKCS11_CKR_KEY_TYPE_INCONSISTENT;
		}
		if (key_class != PKCS11_CKO_PUBLIC_KEY &&
		    key_class != PKCS11_CKO_PRIVATE_KEY) {
			EMSG("Invalid key class for mechanism %s",
			     id2str_proc(proc_id));

			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;
	case PKCS11_CKM_RSA_PKCS:
	case PKCS11_CKM_MD5_RSA_PKCS:
	case PKCS11_CKM_SHA1_RSA_PKCS:
	case PKCS11_CKM_SHA224_RSA_PKCS:
	case PKCS11_CKM_SHA256_RSA_PKCS:
	case PKCS11_CKM_SHA384_RSA_PKCS:
	case PKCS11_CKM_SHA512_RSA_PKCS:
	case PKCS11_CKM_RSA_PKCS_OAEP:
	case PKCS11_CKM_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
		if (key_type != PKCS11_CKK_RSA) {
			EMSG("Invalid key %s for mechanism %s",
			     id2str_type(key_type, key_class),
			     id2str_proc(proc_id));

			return PKCS11_CKR_KEY_TYPE_INCONSISTENT;
		}
		if (key_class != PKCS11_CKO_PUBLIC_KEY &&
		    key_class != PKCS11_CKO_PRIVATE_KEY) {
			EMSG("Invalid key class for mechanism %s",
			     id2str_proc(proc_id));

			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;
	default:
		DMSG("Invalid processing %#"PRIx32"/%s", proc_id,
		     id2str_proc(proc_id));

		return PKCS11_CKR_MECHANISM_INVALID;
	}

	if (!parent_key_complies_allowed_processings(proc_id, head)) {
		DMSG("Allowed mechanism failed");
		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	return PKCS11_CKR_OK;
}

bool attribute_is_exportable(struct pkcs11_attribute_head *req_attr,
			     struct pkcs11_object *obj)
{
	uint8_t boolval = 0;
	uint32_t boolsize = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	enum pkcs11_class_id key_class = get_class(obj->attributes);

	if (key_class != PKCS11_CKO_SECRET_KEY &&
	    key_class != PKCS11_CKO_PRIVATE_KEY)
		return true;

	switch (req_attr->id) {
	case PKCS11_CKA_PRIVATE_EXPONENT:
	case PKCS11_CKA_PRIME_1:
	case PKCS11_CKA_PRIME_2:
	case PKCS11_CKA_EXPONENT_1:
	case PKCS11_CKA_EXPONENT_2:
	case PKCS11_CKA_COEFFICIENT:
	case PKCS11_CKA_VALUE:
		boolsize = sizeof(boolval);
		rc = get_attribute(obj->attributes, PKCS11_CKA_EXTRACTABLE,
				   &boolval, &boolsize);
		if (rc || boolval == PKCS11_FALSE)
			return false;

		boolsize = sizeof(boolval);
		rc = get_attribute(obj->attributes, PKCS11_CKA_SENSITIVE,
				   &boolval, &boolsize);
		if (rc || boolval == PKCS11_TRUE)
			return false;
		break;
	default:
		break;
	}

	return true;
}

static bool attr_is_modifiable_any_key(struct pkcs11_attribute_head *attr)
{
	switch (attr->id) {
	case PKCS11_CKA_ID:
	case PKCS11_CKA_START_DATE:
	case PKCS11_CKA_END_DATE:
	case PKCS11_CKA_DERIVE:
		return true;
	default:
		return false;
	}
}

static bool attr_is_modifiable_secret_key(struct pkcs11_attribute_head *attr,
					  struct pkcs11_session *session,
					  struct pkcs11_object *obj)
{
	switch (attr->id) {
	case PKCS11_CKA_ENCRYPT:
	case PKCS11_CKA_DECRYPT:
	case PKCS11_CKA_SIGN:
	case PKCS11_CKA_VERIFY:
	case PKCS11_CKA_WRAP:
	case PKCS11_CKA_UNWRAP:
		return true;
	/* Can't be modified once set to CK_FALSE - 12 in Table 10 */
	case PKCS11_CKA_EXTRACTABLE:
		return get_bool(obj->attributes, attr->id);
	/* Can't be modified once set to CK_TRUE - 11 in Table 10 */
	case PKCS11_CKA_SENSITIVE:
	case PKCS11_CKA_WRAP_WITH_TRUSTED:
		return !get_bool(obj->attributes, attr->id);
	/* Change in CKA_TRUSTED can only be done by SO */
	case PKCS11_CKA_TRUSTED:
		return pkcs11_session_is_so(session);
	case PKCS11_CKA_NEVER_EXTRACTABLE:
	case PKCS11_CKA_ALWAYS_SENSITIVE:
		return false;
	default:
		return false;
	}
}

static bool attr_is_modifiable_public_key(struct pkcs11_attribute_head *attr,
					  struct pkcs11_session *session,
					  struct pkcs11_object *obj __unused)
{
	switch (attr->id) {
	case PKCS11_CKA_SUBJECT:
	case PKCS11_CKA_ENCRYPT:
	case PKCS11_CKA_VERIFY:
	case PKCS11_CKA_VERIFY_RECOVER:
	case PKCS11_CKA_WRAP:
		return true;
	case PKCS11_CKA_TRUSTED:
		/* Change in CKA_TRUSTED can only be done by SO */
		return pkcs11_session_is_so(session);
	default:
		return false;
	}
}

static bool attr_is_modifiable_private_key(struct pkcs11_attribute_head *attr,
					   struct pkcs11_session *sess __unused,
					   struct pkcs11_object *obj)
{
	switch (attr->id) {
	case PKCS11_CKA_SUBJECT:
	case PKCS11_CKA_DECRYPT:
	case PKCS11_CKA_SIGN:
	case PKCS11_CKA_SIGN_RECOVER:
	case PKCS11_CKA_UNWRAP:
	/*
	 * TBD: Revisit if we don't support PKCS11_CKA_PUBLIC_KEY_INFO
	 * Specification mentions that if this attribute is
	 * supplied as part of a template for C_CreateObject, C_CopyObject or
	 * C_SetAttributeValue for a private key, the token MUST verify
	 * correspondence between the private key data and the public key data
	 * as supplied in CKA_PUBLIC_KEY_INFO. This needs to be
	 * taken care of when this object type will be implemented
	 */
	case PKCS11_CKA_PUBLIC_KEY_INFO:
		return true;
	/* Can't be modified once set to CK_FALSE - 12 in Table 10 */
	case PKCS11_CKA_EXTRACTABLE:
		return get_bool(obj->attributes, attr->id);
	/* Can't be modified once set to CK_TRUE - 11 in Table 10 */
	case PKCS11_CKA_SENSITIVE:
	case PKCS11_CKA_WRAP_WITH_TRUSTED:
		return !get_bool(obj->attributes, attr->id);
	case PKCS11_CKA_NEVER_EXTRACTABLE:
	case PKCS11_CKA_ALWAYS_SENSITIVE:
		return false;
	default:
		return false;
	}
}

static bool attr_is_modifiable_certificate(struct pkcs11_attribute_head *attr,
					   struct pkcs11_session *session,
					   struct pkcs11_object *obj)
{
	uint8_t boolval = 0;
	uint32_t boolsize = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	/* Trusted certificates cannot be modified. */
	rc = get_attribute(obj->attributes, PKCS11_CKA_TRUSTED,
			   &boolval, &boolsize);
	if (rc || boolval == PKCS11_TRUE)
		return false;

	/* Common certificate attributes */
	switch (attr->id) {
	case PKCS11_CKA_TRUSTED:
		/*
		 * The CKA_TRUSTED attribute cannot be set to CK_TRUE by an
		 * application. It MUST be set by a token initialization
		 * application or by the token’s SO.
		 */
		return pkcs11_session_is_so(session);
	case PKCS11_CKA_CERTIFICATE_TYPE:
	case PKCS11_CKA_CERTIFICATE_CATEGORY:
		return false;
	default:
		break;
	}

	/* Certificate type specific attributes */
	switch (get_certificate_type(obj->attributes)) {
	case PKCS11_CKC_X_509:
		/*
		 * Only the CKA_ID, CKA_ISSUER, and CKA_SERIAL_NUMBER
		 * attributes may be modified after the object is created.
		 */
		switch (attr->id) {
		case PKCS11_CKA_ID:
		case PKCS11_CKA_ISSUER:
		case PKCS11_CKA_SERIAL_NUMBER:
			return true;
		default:
			break;
		}
		break;
	default:
		/* Unsupported certificate type */
		break;
	}

	return false;
}

static bool attribute_is_modifiable(struct pkcs11_session *session,
				    struct pkcs11_attribute_head *req_attr,
				    struct pkcs11_object *obj,
				    enum pkcs11_class_id class,
				    enum processing_func function)
{
	/* Check modifiable attributes common to any object */
	switch (req_attr->id) {
	case PKCS11_CKA_LABEL:
		return true;
	case PKCS11_CKA_TOKEN:
	case PKCS11_CKA_MODIFIABLE:
	case PKCS11_CKA_DESTROYABLE:
	case PKCS11_CKA_PRIVATE:
		return function == PKCS11_FUNCTION_COPY;
	case PKCS11_CKA_COPYABLE:
		/*
		 * Specification mentions that if the attribute value is false
		 * it can't be set to true. Reading this we assume that it
		 * should be possible to modify this attribute even though this
		 * is not marked as modifiable in Table 10 if done in right
		 * direction i.e from TRUE -> FALSE.
		 */
		return get_bool(obj->attributes, req_attr->id);
	default:
		break;
	}

	/* Attribute checking based on class type */
	switch (class) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		if (attr_is_modifiable_any_key(req_attr))
			return true;
		if (class == PKCS11_CKO_SECRET_KEY &&
		    attr_is_modifiable_secret_key(req_attr, session, obj))
			return true;
		if (class == PKCS11_CKO_PUBLIC_KEY &&
		    attr_is_modifiable_public_key(req_attr, session, obj))
			return true;
		if (class == PKCS11_CKO_PRIVATE_KEY &&
		    attr_is_modifiable_private_key(req_attr, session, obj))
			return true;
		break;
	case PKCS11_CKO_DATA:
		/* None of the data object attributes are modifiable */
		return false;
	case PKCS11_CKO_CERTIFICATE:
		return attr_is_modifiable_certificate(req_attr, session, obj);
	default:
		break;
	}

	return false;
}

enum pkcs11_rc check_attrs_against_modification(struct pkcs11_session *session,
						struct obj_attrs *head,
						struct pkcs11_object *obj,
						enum processing_func function)
{
	enum pkcs11_class_id class = PKCS11_CKO_UNDEFINED_ID;
	char *cur = NULL;
	char *end = NULL;
	size_t len = 0;

	class = get_class(obj->attributes);

	cur = (char *)head + sizeof(struct obj_attrs);
	end = cur + head->attrs_size;

	for (; cur < end; cur += len) {
		/* Structure aligned copy of the pkcs11_ref in the object */
		struct pkcs11_attribute_head cli_ref = { };

		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		len = sizeof(cli_ref) + cli_ref.size;

		/*
		 * Check 1 - Check if attribute belongs to the object
		 * The obj->attributes has all the attributes in
		 * it which are allowed for an object.
		 */
		if (get_attribute_ptr(obj->attributes, cli_ref.id, NULL,
				      NULL) == PKCS11_RV_NOT_FOUND)
			return PKCS11_CKR_ATTRIBUTE_TYPE_INVALID;

		/* Check 2 - Is attribute modifiable */
		if (!attribute_is_modifiable(session, &cli_ref, obj, class,
					     function))
			return PKCS11_CKR_ATTRIBUTE_READ_ONLY;

		/*
		 * Checks for modification in PKCS11_CKA_TOKEN and
		 * PKCS11_CKA_PRIVATE are required for PKCS11_FUNCTION_COPY
		 * only, so skip them for PKCS11_FUNCTION_MODIFY.
		 */
		if (function == PKCS11_FUNCTION_MODIFY)
			continue;

		/*
		 * An attempt to copy an object to a token will fail for
		 * RO session
		 */
		if (cli_ref.id == PKCS11_CKA_TOKEN &&
		    get_bool(head, PKCS11_CKA_TOKEN)) {
			if (!pkcs11_session_is_read_write(session)) {
				DMSG("Can't copy to token in a RO session");
				return PKCS11_CKR_SESSION_READ_ONLY;
			}
		}

		if (cli_ref.id == PKCS11_CKA_PRIVATE) {
			bool parent_priv =
				get_bool(obj->attributes, cli_ref.id);
			bool obj_priv = get_bool(head, cli_ref.id);

			/*
			 * If PKCS11_CKA_PRIVATE is being set to TRUE from
			 * FALSE, user has to be logged in
			 */
			if (!parent_priv && obj_priv) {
				if ((pkcs11_session_is_public(session) ||
				     pkcs11_session_is_so(session)))
					return PKCS11_CKR_USER_NOT_LOGGED_IN;
			}

			/*
			 * Restriction added - Even for Copy, do not allow
			 * modification of CKA_PRIVATE from TRUE to FALSE
			 */
			if (parent_priv && !obj_priv)
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}
	}

	return PKCS11_CKR_OK;
}

static enum pkcs11_rc set_secret_key_data(struct obj_attrs **head, void *data,
					  size_t key_size)
{
	uint32_t size = sizeof(uint32_t);
	uint32_t key_length = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	/* Get key size if present in template */
	rc = get_attribute(*head, PKCS11_CKA_VALUE_LEN, &key_length, &size);
	if (rc && rc != PKCS11_RV_NOT_FOUND)
		return rc;

	if (key_length) {
		if (key_size < key_length)
			return PKCS11_CKR_DATA_LEN_RANGE;
	} else {
		key_length = key_size;
		rc = set_attribute(head, PKCS11_CKA_VALUE_LEN, &key_length,
				   sizeof(uint32_t));
		if (rc)
			return rc;
	}

	/* Now we can check the VALUE_LEN field */
	rc = check_created_attrs(*head, NULL);
	if (rc)
		return rc;

	/* Remove the default empty value attribute if found */
	rc = remove_empty_attribute(head, PKCS11_CKA_VALUE);
	if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
		return PKCS11_CKR_GENERAL_ERROR;

	return add_attribute(head, PKCS11_CKA_VALUE, data, key_length);
}

enum pkcs11_rc set_key_data(struct obj_attrs **head, void *data,
			    size_t key_size)
{
	switch (get_class(*head)) {
	case PKCS11_CKO_SECRET_KEY:
		return set_secret_key_data(head, data, key_size);
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}
}

enum pkcs11_rc get_key_data_to_wrap(struct obj_attrs *head, void **data,
				    uint32_t *sz)
{
	switch (get_class(head)) {
	case PKCS11_CKO_SECRET_KEY:
		if (get_attribute_ptr(head, PKCS11_CKA_VALUE, data, sz))
			return PKCS11_CKR_ARGUMENTS_BAD;
		break;
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}

	return PKCS11_CKR_OK;
}

enum pkcs11_rc add_missing_attribute_id(struct obj_attrs **pub_head,
					struct obj_attrs **priv_head)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *id1 = NULL;
	uint32_t id1_size = 0;
	void *id2 = NULL;
	uint32_t id2_size = 0;

	assert(pub_head);
	assert(priv_head);

	rc = get_attribute_ptr(*pub_head, PKCS11_CKA_ID, &id1, &id1_size);
	if (rc) {
		if (rc != PKCS11_RV_NOT_FOUND)
			return rc;
		id1 = NULL;
	} else if (!id1_size) {
		id1 = NULL;
	}

	rc = get_attribute_ptr(*priv_head, PKCS11_CKA_ID, &id2, &id2_size);
	if (rc) {
		if (rc != PKCS11_RV_NOT_FOUND)
			return rc;
		id2 = NULL;
	} else if (!id2_size) {
		id2 = NULL;
	}

	/* Both have value -- let them be what caller has specified them */
	if (id1 && id2)
		return PKCS11_CKR_OK;

	/* Both are empty -- leave empty values */
	if (!id1 && !id2)
		return PKCS11_CKR_OK;

	/* Cross copy CKA_ID value */
	if (id1)
		return set_attribute(priv_head, PKCS11_CKA_ID, id1, id1_size);
	else
		return set_attribute(pub_head, PKCS11_CKA_ID, id2, id2_size);
}
