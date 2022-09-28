// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <string.h>
#include <tee_internal_api.h>
#include <util.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "processing.h"

static const char __maybe_unused unknown[] = "<unknown-identifier>";

struct attr_size {
	uint32_t id;
	uint32_t size;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define PKCS11_ID_SZ(_id, _sz)	\
			{ .id = (uint32_t)(_id), .size = (_sz), .string = #_id }
#else
#define PKCS11_ID_SZ(_id, _sz)	\
			{ .id = (uint32_t)(_id), .size = (_sz) }
#endif

static const struct attr_size attr_ids[] = {
	PKCS11_ID_SZ(PKCS11_CKA_CLASS, 4),
	PKCS11_ID_SZ(PKCS11_CKA_KEY_TYPE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_VALUE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_VALUE_LEN, 4),
	PKCS11_ID_SZ(PKCS11_CKA_KEY_GEN_MECHANISM, 4),
	PKCS11_ID_SZ(PKCS11_CKA_LABEL, 0),
	PKCS11_ID_SZ(PKCS11_CKA_CERTIFICATE_TYPE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_ISSUER, 0),
	PKCS11_ID_SZ(PKCS11_CKA_SERIAL_NUMBER, 0),
	PKCS11_ID_SZ(PKCS11_CKA_CERTIFICATE_CATEGORY, 4),
	PKCS11_ID_SZ(PKCS11_CKA_URL, 0),
	PKCS11_ID_SZ(PKCS11_CKA_HASH_OF_SUBJECT_PUBLIC_KEY, 0),
	PKCS11_ID_SZ(PKCS11_CKA_HASH_OF_ISSUER_PUBLIC_KEY, 0),
	PKCS11_ID_SZ(PKCS11_CKA_JAVA_MIDP_SECURITY_DOMAIN, 4),
	PKCS11_ID_SZ(PKCS11_CKA_NAME_HASH_ALGORITHM, 4),
	PKCS11_ID_SZ(PKCS11_CKA_CHECK_VALUE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_WRAP_TEMPLATE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_UNWRAP_TEMPLATE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_DERIVE_TEMPLATE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_START_DATE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_END_DATE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_OBJECT_ID, 0),
	PKCS11_ID_SZ(PKCS11_CKA_APPLICATION, 0),
	PKCS11_ID_SZ(PKCS11_CKA_MECHANISM_TYPE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_ID, 0),
	PKCS11_ID_SZ(PKCS11_CKA_ALLOWED_MECHANISMS, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EC_POINT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EC_PARAMS, 0),
	PKCS11_ID_SZ(PKCS11_CKA_MODULUS, 0),
	PKCS11_ID_SZ(PKCS11_CKA_MODULUS_BITS, 4),
	PKCS11_ID_SZ(PKCS11_CKA_PUBLIC_EXPONENT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_PRIVATE_EXPONENT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_PRIME_1, 0),
	PKCS11_ID_SZ(PKCS11_CKA_PRIME_2, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EXPONENT_1, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EXPONENT_2, 0),
	PKCS11_ID_SZ(PKCS11_CKA_COEFFICIENT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_SUBJECT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_PUBLIC_KEY_INFO, 0),
	PKCS11_ID_SZ(PKCS11_CKA_KEY_GEN_MECHANISM, 4),
	/* Below are boolean attributes */
	PKCS11_ID_SZ(PKCS11_CKA_TOKEN, 1),
	PKCS11_ID_SZ(PKCS11_CKA_PRIVATE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_TRUSTED, 1),
	PKCS11_ID_SZ(PKCS11_CKA_SENSITIVE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_ENCRYPT, 1),
	PKCS11_ID_SZ(PKCS11_CKA_DECRYPT, 1),
	PKCS11_ID_SZ(PKCS11_CKA_WRAP, 1),
	PKCS11_ID_SZ(PKCS11_CKA_UNWRAP, 1),
	PKCS11_ID_SZ(PKCS11_CKA_SIGN, 1),
	PKCS11_ID_SZ(PKCS11_CKA_SIGN_RECOVER, 1),
	PKCS11_ID_SZ(PKCS11_CKA_VERIFY, 1),
	PKCS11_ID_SZ(PKCS11_CKA_VERIFY_RECOVER, 1),
	PKCS11_ID_SZ(PKCS11_CKA_DERIVE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_EXTRACTABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_LOCAL, 1),
	PKCS11_ID_SZ(PKCS11_CKA_NEVER_EXTRACTABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_ALWAYS_SENSITIVE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_MODIFIABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_COPYABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_DESTROYABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_ALWAYS_AUTHENTICATE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_WRAP_WITH_TRUSTED, 1),
	/* Specific PKCS11 TA internal attribute ID */
	PKCS11_ID_SZ(PKCS11_CKA_UNDEFINED_ID, 0),
};

struct any_id {
	uint32_t id;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

/*
 * Macro PKCS11_ID() can be used to define cells in ID list arrays
 * or ID/string conversion arrays.
 */
#if CFG_TEE_TA_LOG_LEVEL > 0
#define PKCS11_ID(_id)		{ .id = _id, .string = #_id }
#else
#define PKCS11_ID(_id)		{ .id = _id }
#endif

#define ID2STR(id, table, prefix)	\
	id2str(id, table, ARRAY_SIZE(table), prefix)

#if CFG_TEE_TA_LOG_LEVEL > 0
/* Convert a PKCS11 ID into its label string */
static const char *id2str(uint32_t id, const struct any_id *table,
			  size_t count, const char *prefix)
{
	size_t n = 0;
	const char *str = NULL;

	for (n = 0; n < count; n++) {
		if (id != table[n].id)
			continue;

		str = table[n].string;

		/* Skip prefix provided matches found */
		if (prefix && !TEE_MemCompare(str, prefix, strlen(prefix)))
			str += strlen(prefix);

		return str;
	}

	return unknown;
}
#endif /* CFG_TEE_TA_LOG_LEVEL > 0 */

/*
 * TA command IDs: used only as ID/string conversion for debug trace support
 */
static const struct any_id __maybe_unused string_ta_cmd[] = {
	PKCS11_ID(PKCS11_CMD_PING),
	PKCS11_ID(PKCS11_CMD_SLOT_LIST),
	PKCS11_ID(PKCS11_CMD_SLOT_INFO),
	PKCS11_ID(PKCS11_CMD_TOKEN_INFO),
	PKCS11_ID(PKCS11_CMD_MECHANISM_IDS),
	PKCS11_ID(PKCS11_CMD_MECHANISM_INFO),
	PKCS11_ID(PKCS11_CMD_OPEN_SESSION),
	PKCS11_ID(PKCS11_CMD_SESSION_INFO),
	PKCS11_ID(PKCS11_CMD_CLOSE_SESSION),
	PKCS11_ID(PKCS11_CMD_CLOSE_ALL_SESSIONS),
	PKCS11_ID(PKCS11_CMD_INIT_TOKEN),
	PKCS11_ID(PKCS11_CMD_INIT_PIN),
	PKCS11_ID(PKCS11_CMD_SET_PIN),
	PKCS11_ID(PKCS11_CMD_LOGIN),
	PKCS11_ID(PKCS11_CMD_LOGOUT),
	PKCS11_ID(PKCS11_CMD_CREATE_OBJECT),
	PKCS11_ID(PKCS11_CMD_DESTROY_OBJECT),
	PKCS11_ID(PKCS11_CMD_ENCRYPT_INIT),
	PKCS11_ID(PKCS11_CMD_DECRYPT_INIT),
	PKCS11_ID(PKCS11_CMD_ENCRYPT_UPDATE),
	PKCS11_ID(PKCS11_CMD_DECRYPT_UPDATE),
	PKCS11_ID(PKCS11_CMD_ENCRYPT_FINAL),
	PKCS11_ID(PKCS11_CMD_DECRYPT_FINAL),
	PKCS11_ID(PKCS11_CMD_ENCRYPT_ONESHOT),
	PKCS11_ID(PKCS11_CMD_DECRYPT_ONESHOT),
	PKCS11_ID(PKCS11_CMD_SIGN_INIT),
	PKCS11_ID(PKCS11_CMD_VERIFY_INIT),
	PKCS11_ID(PKCS11_CMD_SIGN_UPDATE),
	PKCS11_ID(PKCS11_CMD_VERIFY_UPDATE),
	PKCS11_ID(PKCS11_CMD_SIGN_FINAL),
	PKCS11_ID(PKCS11_CMD_VERIFY_FINAL),
	PKCS11_ID(PKCS11_CMD_SIGN_ONESHOT),
	PKCS11_ID(PKCS11_CMD_VERIFY_ONESHOT),
	PKCS11_ID(PKCS11_CMD_GENERATE_KEY),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS_INIT),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS_FINAL),
	PKCS11_ID(PKCS11_CMD_GET_OBJECT_SIZE),
	PKCS11_ID(PKCS11_CMD_GET_ATTRIBUTE_VALUE),
	PKCS11_ID(PKCS11_CMD_SET_ATTRIBUTE_VALUE),
	PKCS11_ID(PKCS11_CMD_COPY_OBJECT),
	PKCS11_ID(PKCS11_CMD_SEED_RANDOM),
	PKCS11_ID(PKCS11_CMD_GENERATE_RANDOM),
	PKCS11_ID(PKCS11_CMD_DERIVE_KEY),
	PKCS11_ID(PKCS11_CMD_RELEASE_ACTIVE_PROCESSING),
	PKCS11_ID(PKCS11_CMD_DIGEST_INIT),
	PKCS11_ID(PKCS11_CMD_DIGEST_UPDATE),
	PKCS11_ID(PKCS11_CMD_DIGEST_KEY),
	PKCS11_ID(PKCS11_CMD_DIGEST_ONESHOT),
	PKCS11_ID(PKCS11_CMD_DIGEST_FINAL),
	PKCS11_ID(PKCS11_CMD_GENERATE_KEY_PAIR),
	PKCS11_ID(PKCS11_CMD_WRAP_KEY),
	PKCS11_ID(PKCS11_CMD_UNWRAP_KEY),
};

static const struct any_id __maybe_unused string_slot_flags[] = {
	PKCS11_ID(PKCS11_CKFS_TOKEN_PRESENT),
	PKCS11_ID(PKCS11_CKFS_REMOVABLE_DEVICE),
	PKCS11_ID(PKCS11_CKFS_HW_SLOT),
};

static const struct any_id __maybe_unused string_token_flags[] = {
	PKCS11_ID(PKCS11_CKFT_RNG),
	PKCS11_ID(PKCS11_CKFT_WRITE_PROTECTED),
	PKCS11_ID(PKCS11_CKFT_LOGIN_REQUIRED),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_INITIALIZED),
	PKCS11_ID(PKCS11_CKFT_RESTORE_KEY_NOT_NEEDED),
	PKCS11_ID(PKCS11_CKFT_CLOCK_ON_TOKEN),
	PKCS11_ID(PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH),
	PKCS11_ID(PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS),
	PKCS11_ID(PKCS11_CKFT_TOKEN_INITIALIZED),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_COUNT_LOW),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_FINAL_TRY),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_LOCKED),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_TO_BE_CHANGED),
	PKCS11_ID(PKCS11_CKFT_SO_PIN_COUNT_LOW),
	PKCS11_ID(PKCS11_CKFT_SO_PIN_FINAL_TRY),
	PKCS11_ID(PKCS11_CKFT_SO_PIN_LOCKED),
	PKCS11_ID(PKCS11_CKFT_SO_PIN_TO_BE_CHANGED),
	PKCS11_ID(PKCS11_CKFT_ERROR_STATE),
};

static const struct any_id __maybe_unused string_session_flags[] = {
	PKCS11_ID(PKCS11_CKFSS_RW_SESSION),
	PKCS11_ID(PKCS11_CKFSS_SERIAL_SESSION),
};

static const struct any_id __maybe_unused string_session_state[] = {
	PKCS11_ID(PKCS11_CKS_RO_PUBLIC_SESSION),
	PKCS11_ID(PKCS11_CKS_RO_USER_FUNCTIONS),
	PKCS11_ID(PKCS11_CKS_RW_PUBLIC_SESSION),
	PKCS11_ID(PKCS11_CKS_RW_USER_FUNCTIONS),
	PKCS11_ID(PKCS11_CKS_RW_SO_FUNCTIONS),
};

static const struct any_id __maybe_unused string_rc[] = {
	PKCS11_ID(PKCS11_CKR_OK),
	PKCS11_ID(PKCS11_CKR_SLOT_ID_INVALID),
	PKCS11_ID(PKCS11_CKR_GENERAL_ERROR),
	PKCS11_ID(PKCS11_CKR_FUNCTION_FAILED),
	PKCS11_ID(PKCS11_CKR_ARGUMENTS_BAD),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_READ_ONLY),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_SENSITIVE),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_TYPE_INVALID),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_VALUE_INVALID),
	PKCS11_ID(PKCS11_CKR_ACTION_PROHIBITED),
	PKCS11_ID(PKCS11_CKR_DATA_LEN_RANGE),
	PKCS11_ID(PKCS11_CKR_DEVICE_MEMORY),
	PKCS11_ID(PKCS11_CKR_ENCRYPTED_DATA_INVALID),
	PKCS11_ID(PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE),
	PKCS11_ID(PKCS11_CKR_KEY_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_KEY_SIZE_RANGE),
	PKCS11_ID(PKCS11_CKR_KEY_TYPE_INCONSISTENT),
	PKCS11_ID(PKCS11_CKR_KEY_INDIGESTIBLE),
	PKCS11_ID(PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED),
	PKCS11_ID(PKCS11_CKR_KEY_NOT_WRAPPABLE),
	PKCS11_ID(PKCS11_CKR_KEY_UNEXTRACTABLE),
	PKCS11_ID(PKCS11_CKR_MECHANISM_INVALID),
	PKCS11_ID(PKCS11_CKR_MECHANISM_PARAM_INVALID),
	PKCS11_ID(PKCS11_CKR_OBJECT_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_OPERATION_ACTIVE),
	PKCS11_ID(PKCS11_CKR_OPERATION_NOT_INITIALIZED),
	PKCS11_ID(PKCS11_CKR_PIN_INCORRECT),
	PKCS11_ID(PKCS11_CKR_PIN_INVALID),
	PKCS11_ID(PKCS11_CKR_PIN_LEN_RANGE),
	PKCS11_ID(PKCS11_CKR_PIN_EXPIRED),
	PKCS11_ID(PKCS11_CKR_PIN_LOCKED),
	PKCS11_ID(PKCS11_CKR_SESSION_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_SESSION_PARALLEL_NOT_SUPPORTED),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_ONLY),
	PKCS11_ID(PKCS11_CKR_SESSION_EXISTS),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_ONLY_EXISTS),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS),
	PKCS11_ID(PKCS11_CKR_SIGNATURE_INVALID),
	PKCS11_ID(PKCS11_CKR_SIGNATURE_LEN_RANGE),
	PKCS11_ID(PKCS11_CKR_TEMPLATE_INCOMPLETE),
	PKCS11_ID(PKCS11_CKR_TEMPLATE_INCONSISTENT),
	PKCS11_ID(PKCS11_CKR_TOKEN_NOT_PRESENT),
	PKCS11_ID(PKCS11_CKR_TOKEN_NOT_RECOGNIZED),
	PKCS11_ID(PKCS11_CKR_TOKEN_WRITE_PROTECTED),
	PKCS11_ID(PKCS11_CKR_UNWRAPPING_KEY_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_UNWRAPPING_KEY_SIZE_RANGE),
	PKCS11_ID(PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
	PKCS11_ID(PKCS11_CKR_USER_ALREADY_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_NOT_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_PIN_NOT_INITIALIZED),
	PKCS11_ID(PKCS11_CKR_USER_TYPE_INVALID),
	PKCS11_ID(PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_TOO_MANY_TYPES),
	PKCS11_ID(PKCS11_CKR_WRAPPED_KEY_INVALID),
	PKCS11_ID(PKCS11_CKR_WRAPPED_KEY_LEN_RANGE),
	PKCS11_ID(PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_WRAPPING_KEY_SIZE_RANGE),
	PKCS11_ID(PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
	PKCS11_ID(PKCS11_CKR_RANDOM_SEED_NOT_SUPPORTED),
	PKCS11_ID(PKCS11_CKR_RANDOM_NO_RNG),
	PKCS11_ID(PKCS11_CKR_DOMAIN_PARAMS_INVALID),
	PKCS11_ID(PKCS11_CKR_CURVE_NOT_SUPPORTED),
	PKCS11_ID(PKCS11_CKR_BUFFER_TOO_SMALL),
	PKCS11_ID(PKCS11_CKR_PIN_TOO_WEAK),
	PKCS11_ID(PKCS11_RV_NOT_FOUND),
	PKCS11_ID(PKCS11_RV_NOT_IMPLEMENTED),
};

static const struct any_id __maybe_unused string_class[] = {
	PKCS11_ID(PKCS11_CKO_SECRET_KEY),
	PKCS11_ID(PKCS11_CKO_PUBLIC_KEY),
	PKCS11_ID(PKCS11_CKO_PRIVATE_KEY),
	PKCS11_ID(PKCS11_CKO_OTP_KEY),
	PKCS11_ID(PKCS11_CKO_CERTIFICATE),
	PKCS11_ID(PKCS11_CKO_DATA),
	PKCS11_ID(PKCS11_CKO_DOMAIN_PARAMETERS),
	PKCS11_ID(PKCS11_CKO_HW_FEATURE),
	PKCS11_ID(PKCS11_CKO_MECHANISM),
	PKCS11_ID(PKCS11_CKO_UNDEFINED_ID)
};

static const struct any_id __maybe_unused string_key_type[] = {
	PKCS11_ID(PKCS11_CKK_AES),
	PKCS11_ID(PKCS11_CKK_GENERIC_SECRET),
	PKCS11_ID(PKCS11_CKK_MD5_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA_1_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA224_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA256_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA384_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA512_HMAC),
	PKCS11_ID(PKCS11_CKK_EC),
	PKCS11_ID(PKCS11_CKK_EC_EDWARDS),
	PKCS11_ID(PKCS11_CKK_EDDSA),
	PKCS11_ID(PKCS11_CKK_RSA),
	PKCS11_ID(PKCS11_CKK_UNDEFINED_ID)
};

static const struct any_id __maybe_unused string_certificate_type[] = {
	PKCS11_ID(PKCS11_CKC_X_509),
	PKCS11_ID(PKCS11_CKC_X_509_ATTR_CERT),
	PKCS11_ID(PKCS11_CKC_WTLS),
	PKCS11_ID(PKCS11_CKC_UNDEFINED_ID)
};

/*
 * Processing IDs not exported in the TA API.
 * PKCS11_CKM_* mechanism IDs are looked up from mechanism_string_id().
 */
static const struct any_id __maybe_unused string_internal_processing[] = {
	PKCS11_ID(PKCS11_PROCESSING_IMPORT),
};

static const struct any_id __maybe_unused string_functions[] = {
	PKCS11_ID(PKCS11_FUNCTION_DIGEST),
	PKCS11_ID(PKCS11_FUNCTION_IMPORT),
	PKCS11_ID(PKCS11_FUNCTION_ENCRYPT),
	PKCS11_ID(PKCS11_FUNCTION_DECRYPT),
	PKCS11_ID(PKCS11_FUNCTION_SIGN),
	PKCS11_ID(PKCS11_FUNCTION_VERIFY),
	PKCS11_ID(PKCS11_FUNCTION_DERIVE),
	PKCS11_ID(PKCS11_FUNCTION_WRAP),
	PKCS11_ID(PKCS11_FUNCTION_UNWRAP),
};

/*
 * Conversion between PKCS11 TA and GPD TEE return codes
 */
enum pkcs11_rc tee2pkcs_error(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return PKCS11_CKR_OK;

	case TEE_ERROR_BAD_PARAMETERS:
		return PKCS11_CKR_ARGUMENTS_BAD;

	case TEE_ERROR_CIPHERTEXT_INVALID:
		return PKCS11_CKR_ENCRYPTED_DATA_INVALID;

	case TEE_ERROR_OUT_OF_MEMORY:
		return PKCS11_CKR_DEVICE_MEMORY;

	case TEE_ERROR_SHORT_BUFFER:
		return PKCS11_CKR_BUFFER_TOO_SMALL;

	case TEE_ERROR_MAC_INVALID:
	case TEE_ERROR_SIGNATURE_INVALID:
		return PKCS11_CKR_SIGNATURE_INVALID;

	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}
}

/*
 * Helper functions to analyse PKCS11 identifiers
 */

/* Check attribute ID is known and size matches if fixed */
bool valid_pkcs11_attribute_id(uint32_t id, uint32_t size)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(attr_ids); n++)
		if (id == attr_ids[n].id)
			return !attr_ids[n].size || size == attr_ids[n].size;

	return false;
}

size_t pkcs11_attr_is_type(uint32_t attribute_id)
{
	enum pkcs11_attr_id id = attribute_id;

	switch (id) {
	case PKCS11_CKA_KEY_TYPE:
	case PKCS11_CKA_MECHANISM_TYPE:
	case PKCS11_CKA_KEY_GEN_MECHANISM:
		return sizeof(uint32_t);
	default:
		return 0;
	}
}

bool pkcs11_attr_has_indirect_attributes(uint32_t attribute_id)
{
	switch (attribute_id) {
	case PKCS11_CKA_WRAP_TEMPLATE:
	case PKCS11_CKA_UNWRAP_TEMPLATE:
	case PKCS11_CKA_DERIVE_TEMPLATE:
		return true;
	default:
		return false;
	}
}

bool pkcs11_class_has_type(uint32_t class)
{
	enum pkcs11_class_id class_id = class;

	switch (class_id) {
	case PKCS11_CKO_CERTIFICATE:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_MECHANISM:
	case PKCS11_CKO_HW_FEATURE:
		return true;
	default:
		return false;
	}
}

bool pkcs11_attr_class_is_key(uint32_t class)
{
	enum pkcs11_class_id class_id = class;

	switch (class_id) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		return true;
	default:
		return false;
	}
}

bool key_type_is_symm_key(uint32_t id)
{
	enum pkcs11_key_type key_type = id;

	switch (key_type) {
	case PKCS11_CKK_AES:
	case PKCS11_CKK_GENERIC_SECRET:
	case PKCS11_CKK_MD5_HMAC:
	case PKCS11_CKK_SHA_1_HMAC:
	case PKCS11_CKK_SHA224_HMAC:
	case PKCS11_CKK_SHA256_HMAC:
	case PKCS11_CKK_SHA384_HMAC:
	case PKCS11_CKK_SHA512_HMAC:
		return true;
	default:
		return false;
	}
}

bool key_type_is_asymm_key(uint32_t id)
{
	enum pkcs11_key_type key_type = id;

	switch (key_type) {
	case PKCS11_CKK_EC:
	case PKCS11_CKK_EC_EDWARDS:
	case PKCS11_CKK_RSA:
		return true;
	default:
		return false;
	}
}

/*
 * Returns shift position or -1 on error.
 * Mainly used when PKCS11_SHEAD_WITH_BOOLPROPS is enabled
 */
int pkcs11_attr2boolprop_shift(uint32_t attr)
{
	static const uint32_t bpa[] = {
		[BPA_TOKEN]		= PKCS11_CKA_TOKEN,
		[BPA_PRIVATE]		= PKCS11_CKA_PRIVATE,
		[BPA_TRUSTED]		= PKCS11_CKA_TRUSTED,
		[BPA_SENSITIVE]		= PKCS11_CKA_SENSITIVE,
		[BPA_ENCRYPT]		= PKCS11_CKA_ENCRYPT,
		[BPA_DECRYPT]		= PKCS11_CKA_DECRYPT,
		[BPA_WRAP]		= PKCS11_CKA_WRAP,
		[BPA_UNWRAP]		= PKCS11_CKA_UNWRAP,
		[BPA_SIGN]		= PKCS11_CKA_SIGN,
		[BPA_SIGN_RECOVER]	= PKCS11_CKA_SIGN_RECOVER,
		[BPA_VERIFY]		= PKCS11_CKA_VERIFY,
		[BPA_VERIFY_RECOVER]	= PKCS11_CKA_VERIFY_RECOVER,
		[BPA_DERIVE]		= PKCS11_CKA_DERIVE,
		[BPA_EXTRACTABLE]	= PKCS11_CKA_EXTRACTABLE,
		[BPA_LOCAL]		= PKCS11_CKA_LOCAL,
		[BPA_NEVER_EXTRACTABLE]	= PKCS11_CKA_NEVER_EXTRACTABLE,
		[BPA_ALWAYS_SENSITIVE]	= PKCS11_CKA_ALWAYS_SENSITIVE,
		[BPA_MODIFIABLE]	= PKCS11_CKA_MODIFIABLE,
		[BPA_COPYABLE]		= PKCS11_CKA_COPYABLE,
		[BPA_DESTROYABLE]	= PKCS11_CKA_DESTROYABLE,
		[BPA_ALWAYS_AUTHENTICATE] = PKCS11_CKA_ALWAYS_AUTHENTICATE,
		[BPA_WRAP_WITH_TRUSTED] = PKCS11_CKA_WRAP_WITH_TRUSTED,
	};
	size_t pos = 0;

	for (pos = 0; pos < ARRAY_SIZE(bpa); pos++)
		if (bpa[pos] == attr)
			return (int)pos;

	return -1;
}

/* Initialize a TEE attribute for a target PKCS11 TA attribute in an object */
bool pkcs2tee_load_attr(TEE_Attribute *tee_ref, uint32_t tee_id,
			struct pkcs11_object *obj,
			enum pkcs11_attr_id pkcs11_id)
{
	void *a_ptr = NULL;
	uint8_t *der_ptr = NULL;
	uint32_t a_size = 0;
	uint32_t data32 = 0;
	size_t hsize = 0;
	size_t qsize = 0;

	switch (tee_id) {
	case TEE_ATTR_ECC_PUBLIC_VALUE_X:
	case TEE_ATTR_ECC_PUBLIC_VALUE_Y:
	case TEE_ATTR_ECC_CURVE:
		if (get_attribute_ptr(obj->attributes, PKCS11_CKA_EC_PARAMS,
				      &a_ptr, &a_size) || !a_ptr) {
			EMSG("Missing EC_PARAMS attribute");
			return false;
		}

		if (tee_id == TEE_ATTR_ECC_CURVE) {
			data32 = ec_params2tee_curve(a_ptr, a_size);
			TEE_InitValueAttribute(tee_ref, TEE_ATTR_ECC_CURVE,
					       data32, 0);
			return true;
		}

		data32 = (ec_params2tee_keysize(a_ptr, a_size) + 7) / 8;

		if (get_attribute_ptr(obj->attributes, PKCS11_CKA_EC_POINT,
				      &a_ptr, &a_size)) {
			/*
			 * Public X/Y is required for both TEE keypair and
			 * public key, so abort if EC_POINT is not provided
			 * during object import.
			 */

			EMSG("Missing EC_POINT attribute");
			return false;
		}

		der_ptr = (uint8_t *)a_ptr;

		if (der_ptr[0] != 0x04) {
			EMSG("Unsupported DER type");
			return false;
		}

		if ((der_ptr[1] & 0x80) == 0) {
			/* DER short definitive form up to 127 bytes */
			qsize = der_ptr[1] & 0x7F;
			hsize = 2 /* der */ + 1 /* point compression */;
		} else if (der_ptr[1] == 0x81) {
			/* DER long definitive form up to 255 bytes */
			qsize = der_ptr[2];
			hsize = 3 /* der */ + 1 /* point compression */;
		} else {
			EMSG("Unsupported DER long form");
			return false;
		}

		if (der_ptr[hsize - 1] != 0x04) {
			EMSG("Unsupported EC_POINT compression");
			return false;
		}

		if (a_size != (hsize - 1) + qsize) {
			EMSG("Invalid EC_POINT attribute");
			return false;
		}

		if (a_size != hsize + 2 * data32) {
			EMSG("Invalid EC_POINT attribute");
			return false;
		}

		if (tee_id == TEE_ATTR_ECC_PUBLIC_VALUE_X)
			TEE_InitRefAttribute(tee_ref, tee_id,
					     der_ptr + hsize, data32);
		else
			TEE_InitRefAttribute(tee_ref, tee_id,
					     der_ptr + hsize + data32,
					     data32);

		return true;

	default:
		break;
	}

	if (get_attribute_ptr(obj->attributes, pkcs11_id, &a_ptr, &a_size))
		return false;

	TEE_InitRefAttribute(tee_ref, tee_id, a_ptr, a_size);

	return true;
}

/*
 * Initialize a TEE attribute with hash of a target PKCS11 TA attribute
 * in an object.
 */
enum pkcs11_rc pkcs2tee_load_hashed_attr(TEE_Attribute *tee_ref,
					 uint32_t tee_id,
					 struct pkcs11_object *obj,
					 enum pkcs11_attr_id pkcs11_id,
					 uint32_t tee_algo, void *hash_ptr,
					 uint32_t *hash_size)
{
	TEE_OperationHandle handle = TEE_HANDLE_NULL;
	void *a_ptr = NULL;
	uint32_t a_size = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	TEE_Result res = TEE_ERROR_GENERIC;

	rc = get_attribute_ptr(obj->attributes, pkcs11_id, &a_ptr, &a_size);
	if (rc)
		return rc;

	res = TEE_AllocateOperation(&handle, tee_algo, TEE_MODE_DIGEST, 0);
	if (res) {
		EMSG("TEE_AllocateOperation() failed %#"PRIx32, tee_algo);
		return tee2pkcs_error(res);
	}

	res = TEE_DigestDoFinal(handle, a_ptr, a_size, hash_ptr, hash_size);
	TEE_FreeOperation(handle);
	if (res) {
		EMSG("TEE_DigestDoFinal() failed %#"PRIx32, tee_algo);
		return PKCS11_CKR_FUNCTION_FAILED;
	}

	TEE_InitRefAttribute(tee_ref, tee_id, hash_ptr, *hash_size);

	return PKCS11_CKR_OK;
}

/* Easy conversion between PKCS11 TA function of TEE crypto mode */
void pkcs2tee_mode(uint32_t *tee_id, enum processing_func function)
{
	switch (function) {
	case PKCS11_FUNCTION_ENCRYPT:
		*tee_id = TEE_MODE_ENCRYPT;
		break;
	case PKCS11_FUNCTION_DECRYPT:
		*tee_id = TEE_MODE_DECRYPT;
		break;
	case PKCS11_FUNCTION_SIGN:
		*tee_id = TEE_MODE_SIGN;
		break;
	case PKCS11_FUNCTION_VERIFY:
		*tee_id = TEE_MODE_VERIFY;
		break;
	case PKCS11_FUNCTION_DERIVE:
		*tee_id = TEE_MODE_DERIVE;
		break;
	case PKCS11_FUNCTION_DIGEST:
		*tee_id = TEE_MODE_DIGEST;
		break;
	default:
		TEE_Panic(function);
	}
}

#if CFG_TEE_TA_LOG_LEVEL > 0
const char *id2str_rc(uint32_t id)
{
	return ID2STR(id, string_rc, "PKCS11_CKR_");
}

const char *id2str_ta_cmd(uint32_t id)
{
	return ID2STR(id, string_ta_cmd, NULL);
}

const char *id2str_slot_flag(uint32_t id)
{
	return ID2STR(id, string_slot_flags, "PKCS11_CKFS_");
}

const char *id2str_token_flag(uint32_t id)
{
	return ID2STR(id, string_token_flags, "PKCS11_CKFT_");
}

const char *id2str_session_flag(uint32_t id)
{
	return ID2STR(id, string_session_flags, "PKCS11_CKFSS_");
}

const char *id2str_session_state(uint32_t id)
{
	return ID2STR(id, string_session_state, "PKCS11_CKS_");
}

const char *id2str_attr(uint32_t id)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(attr_ids); n++) {
		if (id == attr_ids[n].id) {
			/* Skip PKCS11_CKA_ prefix */
			return attr_ids[n].string + strlen("PKCS11_CKA_");
		}
	}

	return unknown;
}

const char *id2str_class(uint32_t id)
{
	return ID2STR(id, string_class, "PKCS11_CKO_");
}

const char *id2str_type(uint32_t id, uint32_t class)
{
	enum pkcs11_class_id class_id = class;
	enum pkcs11_key_type key_type = id;

	switch (class_id) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		return id2str_key_type(key_type);
	default:
		return unknown;
	}
}

const char *id2str_key_type(uint32_t id)
{
	return ID2STR(id, string_key_type, "PKCS11_CKK_");
}

const char *id2str_certificate_type(uint32_t id)
{
	return ID2STR(id, string_certificate_type, "PKCS11_CKC_");
}

const char *id2str_attr_value(uint32_t id, size_t size, void *value)
{
	static const char str_true[] = "TRUE";
	static const char str_false[] = "FALSE";
	static const char str_unknown[] = "*";
	uint32_t type = 0;

	if (pkcs11_attr2boolprop_shift(id) >= 0)
		return *(uint8_t *)value ? str_true : str_false;

	if (size < sizeof(uint32_t))
		return str_unknown;

	TEE_MemMove(&type, value, sizeof(uint32_t));

	switch (id) {
	case PKCS11_CKA_CLASS:
		return id2str_class(type);
	case PKCS11_CKA_KEY_TYPE:
		return id2str_key_type(type);
	case PKCS11_CKA_MECHANISM_TYPE:
		return id2str_mechanism(type);
	default:
		return str_unknown;
	}
}

const char *id2str_proc(uint32_t id)
{
	const char *str = ID2STR(id, string_internal_processing,
				 "PKCS11_PROCESSING_");

	if (str != unknown)
		return str;

	return id2str_mechanism(id);
}

const char *id2str_function(uint32_t id)
{
	return ID2STR(id, string_functions, "PKCS11_FUNCTION_");
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
