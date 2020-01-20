// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <string.h>
#include <util.h>
#include <tee_internal_api.h>

#include "pkcs11_helpers.h"

static const char __maybe_unused unknown[] = "<unknown-identifier>";

struct attr_size {
	uint32_t id;
	uint32_t size;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define PKCS11_ID_SZ(_id, _sz)	{ .id = (_id), .size = (_sz), .string = #_id }
#else
#define PKCS11_ID_SZ(_id, _sz)	{ .id = (_id), .size = (_sz) }
#endif

static const struct attr_size pkcs11_attribute_ids[] = {
	PKCS11_ID_SZ(PKCS11_CKA_CLASS, 4),
	PKCS11_ID_SZ(PKCS11_CKA_KEY_TYPE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_VALUE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_VALUE_LEN, 4),
	PKCS11_ID_SZ(PKCS11_CKA_LABEL, 0),
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
	PKCS11_ID(PKCS11_CMD_INIT_TOKEN),
	PKCS11_ID(PKCS11_CMD_INIT_PIN),
	PKCS11_ID(PKCS11_CMD_SET_PIN),
	PKCS11_ID(PKCS11_CMD_LOGIN),
	PKCS11_ID(PKCS11_CMD_LOGOUT),
	PKCS11_ID(PKCS11_CMD_OPEN_RO_SESSION),
	PKCS11_ID(PKCS11_CMD_OPEN_RW_SESSION),
	PKCS11_ID(PKCS11_CMD_CLOSE_SESSION),
	PKCS11_ID(PKCS11_CMD_SESSION_INFO),
	PKCS11_ID(PKCS11_CMD_CLOSE_ALL_SESSIONS),
	PKCS11_ID(PKCS11_CMD_GET_SESSION_STATE),
	PKCS11_ID(PKCS11_CMD_SET_SESSION_STATE),
	PKCS11_ID(PKCS11_CMD_IMPORT_OBJECT),
	PKCS11_ID(PKCS11_CMD_COPY_OBJECT),
	PKCS11_ID(PKCS11_CMD_DESTROY_OBJECT),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS_INIT),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS_FINAL),
	PKCS11_ID(PKCS11_CMD_GET_OBJECT_SIZE),
	PKCS11_ID(PKCS11_CMD_GET_OBJECT_SIZE),
	PKCS11_ID(PKCS11_CMD_GET_ATTRIBUTE_VALUE),
	PKCS11_ID(PKCS11_CMD_SET_ATTRIBUTE_VALUE),
};

static const struct any_id __maybe_unused string_rc[] = {
	PKCS11_ID(PKCS11_CKR_OK),
	PKCS11_ID(PKCS11_CKR_GENERAL_ERROR),
	PKCS11_ID(PKCS11_CKR_DEVICE_MEMORY),
	PKCS11_ID(PKCS11_CKR_ARGUMENTS_BAD),
	PKCS11_ID(PKCS11_CKR_BUFFER_TOO_SMALL),
	PKCS11_ID(PKCS11_CKR_FUNCTION_FAILED),
	PKCS11_ID(PKCS11_CKR_SIGNATURE_INVALID),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_TYPE_INVALID),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_VALUE_INVALID),
	PKCS11_ID(PKCS11_CKR_OBJECT_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_KEY_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_MECHANISM_INVALID),
	PKCS11_ID(PKCS11_CKR_SESSION_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_SLOT_ID_INVALID),
	PKCS11_ID(PKCS11_CKR_MECHANISM_PARAM_INVALID),
	PKCS11_ID(PKCS11_CKR_TEMPLATE_INCONSISTENT),
	PKCS11_ID(PKCS11_CKR_TEMPLATE_INCOMPLETE),
	PKCS11_ID(PKCS11_CKR_PIN_INCORRECT),
	PKCS11_ID(PKCS11_CKR_PIN_LOCKED),
	PKCS11_ID(PKCS11_CKR_PIN_EXPIRED),
	PKCS11_ID(PKCS11_CKR_PIN_INVALID),
	PKCS11_ID(PKCS11_CKR_PIN_LEN_RANGE),
	PKCS11_ID(PKCS11_CKR_SESSION_EXISTS),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_ONLY),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS),
	PKCS11_ID(PKCS11_CKR_OPERATION_ACTIVE),
	PKCS11_ID(PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED),
	PKCS11_ID(PKCS11_CKR_OPERATION_NOT_INITIALIZED),
	PKCS11_ID(PKCS11_CKR_TOKEN_WRITE_PROTECTED),
	PKCS11_ID(PKCS11_CKR_TOKEN_NOT_PRESENT),
	PKCS11_ID(PKCS11_CKR_TOKEN_NOT_RECOGNIZED),
	PKCS11_ID(PKCS11_CKR_ACTION_PROHIBITED),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_READ_ONLY),
	PKCS11_ID(PKCS11_CKR_PIN_TOO_WEAK),
	PKCS11_ID(PKCS11_CKR_CURVE_NOT_SUPPORTED),
	PKCS11_ID(PKCS11_CKR_DOMAIN_PARAMS_INVALID),
	PKCS11_ID(PKCS11_CKR_USER_ALREADY_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_NOT_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_PIN_NOT_INITIALIZED),
	PKCS11_ID(PKCS11_CKR_USER_TOO_MANY_TYPES),
	PKCS11_ID(PKCS11_CKR_USER_TYPE_INVALID),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_ONLY_EXISTS),
	PKCS11_ID(PKCS11_RV_NOT_FOUND),
	PKCS11_ID(PKCS11_RV_NOT_IMPLEMENTED),
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

static const struct any_id __maybe_unused string_proc_flags[] = {
	PKCS11_ID(PKCS11_CKFM_HW),
	PKCS11_ID(PKCS11_CKFM_ENCRYPT),
	PKCS11_ID(PKCS11_CKFM_DECRYPT),
	PKCS11_ID(PKCS11_CKFM_DIGEST),
	PKCS11_ID(PKCS11_CKFM_SIGN),
	PKCS11_ID(PKCS11_CKFM_SIGN_RECOVER),
	PKCS11_ID(PKCS11_CKFM_VERIFY),
	PKCS11_ID(PKCS11_CKFM_VERIFY_RECOVER),
	PKCS11_ID(PKCS11_CKFM_GENERATE),
	PKCS11_ID(PKCS11_CKFM_GENERATE_KEY_PAIR),
	PKCS11_ID(PKCS11_CKFM_WRAP),
	PKCS11_ID(PKCS11_CKFM_UNWRAP),
	PKCS11_ID(PKCS11_CKFM_DERIVE),
	PKCS11_ID(PKCS11_CKFM_EC_F_P),
	PKCS11_ID(PKCS11_CKFM_EC_F_2M),
	PKCS11_ID(PKCS11_CKFM_EC_ECPARAMETERS),
	PKCS11_ID(PKCS11_CKFM_EC_NAMEDCURVE),
	PKCS11_ID(PKCS11_CKFM_EC_UNCOMPRESS),
	PKCS11_ID(PKCS11_CKFM_EC_COMPRESS),
};

/*
 * Conversion between PKCS11 TA and GPD TEE return codes
 */

TEE_Result pkcs2tee_error(uint32_t rv)
{
	switch (rv) {
	case PKCS11_CKR_OK:
		return TEE_SUCCESS;

	case PKCS11_CKR_ARGUMENTS_BAD:
		return TEE_ERROR_BAD_PARAMETERS;

	case PKCS11_CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case PKCS11_CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;

	default:
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result pkcs2tee_noerr(uint32_t rc)
{
	switch (rc) {
	case PKCS11_CKR_ARGUMENTS_BAD:
		return TEE_ERROR_BAD_PARAMETERS;

	case PKCS11_CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case PKCS11_CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;

	case PKCS11_CKR_GENERAL_ERROR:
		return TEE_ERROR_GENERIC;

	default:
		return TEE_SUCCESS;
	}
}

uint32_t tee2pkcs_error(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return PKCS11_CKR_OK;

	case TEE_ERROR_BAD_PARAMETERS:
		return PKCS11_CKR_ARGUMENTS_BAD;

	case TEE_ERROR_OUT_OF_MEMORY:
		return PKCS11_CKR_DEVICE_MEMORY;

	case TEE_ERROR_SHORT_BUFFER:
		return PKCS11_CKR_BUFFER_TOO_SMALL;

	case TEE_ERROR_MAC_INVALID:
		return PKCS11_CKR_SIGNATURE_INVALID;

	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}
}

/*
 * Helper functions to analyse SKS identifiers
 */

bool valid_pkcs11_attribute_id(uint32_t attribute_id, uint32_t size)
{
	enum pkcs11_attr_id id = attribute_id;
	size_t n = 0;

	/* Check size matches if provided */
	for (n = 0; n < ARRAY_SIZE(pkcs11_attribute_ids); n++)
		if (id == pkcs11_attribute_ids[n].id)
			return !pkcs11_attribute_ids[n].size ||
			       size == pkcs11_attribute_ids[n].size;

	return false;
}

size_t pkcs11_attr_is_class(uint32_t attribute_id)
{
	enum pkcs11_attr_id id = attribute_id;

	if (id == PKCS11_CKA_CLASS)
		return sizeof(uint32_t);
	else
		return 0;
}

size_t pkcs11_attr_is_type(uint32_t attribute_id)
{
	enum pkcs11_attr_id id = attribute_id;

	switch (id) {
	case PKCS11_CKA_KEY_TYPE:
	case PKCS11_CKA_MECHANISM_TYPE:
		return sizeof(uint32_t);
	default:
		return 0;
	}
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/*
 * Convert a PKCS11 ID into its label string
 */
const char *id2str_attr(uint32_t id)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(pkcs11_attribute_ids); n++) {
		if (id != pkcs11_attribute_ids[n].id)
			continue;

		/* Skip PKCS11_ prefix */
		return (char *)pkcs11_attribute_ids[n].string +
		       strlen("SKS_CKA_");
	}

	return unknown;
}

const char *id2str_rc(uint32_t id)
{
	return ID2STR(id, string_rc, "PKCS11_CKR_");
}

const char *id2str_ta_cmd(uint32_t id)
{
	return ID2STR(id, string_ta_cmd, NULL);
}

const char *id2str_boolprop(uint32_t id)
{
	if (id < 64)
		return id2str_attr(id);

	return unknown;
}

const char *id2str_proc_flag(uint32_t id)
{
	return ID2STR(id, string_proc_flags, "PKCS11_CKFM_");
}

const char *id2str_slot_flag(uint32_t id)
{
	return ID2STR(id, string_slot_flags, "PKCS11_CKFS_");
}

const char *id2str_token_flag(uint32_t id)
{
	return ID2STR(id, string_token_flags, "PKCS11_CKFT_");
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
