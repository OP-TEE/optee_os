// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <assert.h>
#include <sks_ta.h>
#include <string.h>

#include "sks_helpers.h"

struct string_id {
	uint32_t id;
	const char *string;
};

#define SKS_ID(_id)		{ .id = _id, .string = #_id }

struct attr_size {
	uint32_t id;
	uint32_t size;
	const char *string;
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define SKS_ID_SZ(_id, _size)	{ .id = _id, .string = #_id, .size = _size }
#else
#define SKS_ID_SZ(_id, _size)	{ .id = _id, .size = _size }
#endif

static const struct attr_size attr_ids[] = {
	SKS_ID_SZ(SKS_CKA_CLASS, 4),
	SKS_ID_SZ(SKS_CKA_KEY_TYPE, 4),
	SKS_ID_SZ(SKS_CKA_VALUE, 0),
	SKS_ID_SZ(SKS_CKA_VALUE_LEN, 4),
	SKS_ID_SZ(SKS_CKA_WRAP_TEMPLATE, 0),
	SKS_ID_SZ(SKS_CKA_UNWRAP_TEMPLATE, 0),
	SKS_ID_SZ(SKS_CKA_DERIVE_TEMPLATE, 0),
	SKS_ID_SZ(SKS_CKA_START_DATE, 4),
	SKS_ID_SZ(SKS_CKA_END_DATE, 4),
	SKS_ID_SZ(SKS_CKA_OBJECT_ID, 0),
	SKS_ID_SZ(SKS_CKA_APPLICATION, 0),
	SKS_ID_SZ(SKS_CKA_MECHANISM_TYPE, 4),
	SKS_ID_SZ(SKS_CKA_ID, 0),
	SKS_ID_SZ(SKS_CKA_ALLOWED_MECHANISMS, 0),
	/* Below are boolean attribs */
	SKS_ID_SZ(SKS_CKA_TOKEN, 1),
	SKS_ID_SZ(SKS_CKA_PRIVATE, 1),
	SKS_ID_SZ(SKS_CKA_TRUSTED, 1),
	SKS_ID_SZ(SKS_CKA_SENSITIVE, 1),
	SKS_ID_SZ(SKS_CKA_ENCRYPT, 1),
	SKS_ID_SZ(SKS_CKA_DECRYPT, 1),
	SKS_ID_SZ(SKS_CKA_WRAP, 1),
	SKS_ID_SZ(SKS_CKA_UNWRAP, 1),
	SKS_ID_SZ(SKS_CKA_SIGN, 1),
	SKS_ID_SZ(SKS_CKA_SIGN_RECOVER, 1),
	SKS_ID_SZ(SKS_CKA_VERIFY, 1),
	SKS_ID_SZ(SKS_CKA_VERIFY_RECOVER, 1),
	SKS_ID_SZ(SKS_CKA_DERIVE, 1),
	SKS_ID_SZ(SKS_CKA_EXTRACTABLE, 1),
	SKS_ID_SZ(SKS_CKA_LOCAL, 1),
	SKS_ID_SZ(SKS_CKA_NEVER_EXTRACTABLE, 1),
	SKS_ID_SZ(SKS_CKA_ALWAYS_SENSITIVE, 1),
	SKS_ID_SZ(SKS_CKA_MODIFIABLE, 1),
	SKS_ID_SZ(SKS_CKA_COPYABLE, 1),
	SKS_ID_SZ(SKS_CKA_DESTROYABLE, 1),
	SKS_ID_SZ(SKS_CKA_ALWAYS_AUTHENTICATE, 1),
	SKS_ID_SZ(SKS_CKA_WRAP_WITH_TRUSTED, 1),
	/* Specific SKS attribute IDs */
	SKS_ID_SZ(SKS_UNDEFINED_ID, 0),
};

#if CFG_TEE_TA_LOG_LEVEL > 0
static const char __maybe_unused unknown[] = "<unknown-identifier>";

static const struct string_id __maybe_unused string_cmd[] = {
	SKS_ID(SKS_CMD_PING),
	SKS_ID(SKS_CMD_CK_SLOT_LIST),
	SKS_ID(SKS_CMD_CK_SLOT_INFO),
	SKS_ID(SKS_CMD_CK_TOKEN_INFO),
	SKS_ID(SKS_CMD_CK_MECHANISM_IDS),
	SKS_ID(SKS_CMD_CK_MECHANISM_INFO),
	SKS_ID(SKS_CMD_CK_INIT_TOKEN),
	SKS_ID(SKS_CMD_CK_INIT_PIN),
	SKS_ID(SKS_CMD_CK_SET_PIN),
	SKS_ID(SKS_CMD_CK_OPEN_RO_SESSION),
	SKS_ID(SKS_CMD_CK_OPEN_RW_SESSION),
	SKS_ID(SKS_CMD_CK_CLOSE_SESSION),
	SKS_ID(SKS_CMD_CK_SESSION_INFO),
	SKS_ID(SKS_CMD_CK_CLOSE_ALL_SESSIONS),
	SKS_ID(SKS_CMD_IMPORT_OBJECT),
	SKS_ID(SKS_CMD_DESTROY_OBJECT),
	SKS_ID(SKS_CMD_ENCRYPT_INIT),
	SKS_ID(SKS_CMD_DECRYPT_INIT),
	SKS_ID(SKS_CMD_ENCRYPT_UPDATE),
	SKS_ID(SKS_CMD_DECRYPT_UPDATE),
	SKS_ID(SKS_CMD_ENCRYPT_FINAL),
	SKS_ID(SKS_CMD_DECRYPT_FINAL),
	SKS_ID(SKS_CMD_GENERATE_SYMM_KEY),
	SKS_ID(SKS_CMD_SIGN_INIT),
	SKS_ID(SKS_CMD_VERIFY_INIT),
	SKS_ID(SKS_CMD_SIGN_UPDATE),
	SKS_ID(SKS_CMD_VERIFY_UPDATE),
	SKS_ID(SKS_CMD_SIGN_FINAL),
	SKS_ID(SKS_CMD_VERIFY_FINAL),
	SKS_ID(SKS_CMD_FIND_OBJECTS_INIT),
	SKS_ID(SKS_CMD_FIND_OBJECTS),
	SKS_ID(SKS_CMD_FIND_OBJECTS_FINAL),
	SKS_ID(SKS_CMD_GET_OBJECT_SIZE),
	SKS_ID(SKS_CMD_GET_ATTRIBUTE_VALUE),
	SKS_ID(SKS_CMD_SET_ATTRIBUTE_VALUE),
};

static const struct string_id __maybe_unused string_rc[] = {
	SKS_ID(SKS_CKR_OK),
	SKS_ID(SKS_CKR_GENERAL_ERROR),
	SKS_ID(SKS_CKR_DEVICE_MEMORY),
	SKS_ID(SKS_CKR_ARGUMENT_BAD),
	SKS_ID(SKS_CKR_BUFFER_TOO_SMALL),
	SKS_ID(SKS_CKR_FUNCTION_FAILED),
	SKS_ID(SKS_CKR_SIGNATURE_INVALID),
	SKS_ID(SKS_CKR_ATTRIBUTE_TYPE_INVALID),
	SKS_ID(SKS_CKR_ATTRIBUTE_VALUE_INVALID),
	SKS_ID(SKS_CKR_OBJECT_HANDLE_INVALID),
	SKS_ID(SKS_CKR_KEY_HANDLE_INVALID),
	SKS_ID(SKS_CKR_MECHANISM_INVALID),
	SKS_ID(SKS_CKR_SESSION_HANDLE_INVALID),
	SKS_ID(SKS_CKR_SLOT_ID_INVALID),
	SKS_ID(SKS_CKR_MECHANISM_PARAM_INVALID),
	SKS_ID(SKS_CKR_TEMPLATE_INCONSISTENT),
	SKS_ID(SKS_CKR_TEMPLATE_INCOMPLETE),
	SKS_ID(SKS_CKR_PIN_INCORRECT),
	SKS_ID(SKS_CKR_PIN_LOCKED),
	SKS_ID(SKS_CKR_PIN_EXPIRED),
	SKS_ID(SKS_CKR_PIN_INVALID),
	SKS_ID(SKS_CKR_PIN_LEN_RANGE),
	SKS_ID(SKS_CKR_SESSION_EXISTS),
	SKS_ID(SKS_CKR_SESSION_READ_ONLY),
	SKS_ID(SKS_CKR_SESSION_READ_WRITE_SO_EXISTS),
	SKS_ID(SKS_CKR_OPERATION_ACTIVE),
	SKS_ID(SKS_CKR_KEY_FUNCTION_NOT_PERMITTED),
	SKS_ID(SKS_CKR_OPERATION_NOT_INITIALIZED),
	SKS_ID(SKS_NOT_FOUND),
	SKS_ID(SKS_NOT_IMPLEMENTED),
};

static const struct string_id __maybe_unused string_slot_flags[] = {
	SKS_ID(SKS_CKFS_TOKEN_PRESENT),
	SKS_ID(SKS_CKFS_REMOVABLE_DEVICE),
	SKS_ID(SKS_CKFS_HW_SLOT),
};

static const struct string_id __maybe_unused string_token_flags[] = {
	SKS_ID(SKS_CKFT_RNG),
	SKS_ID(SKS_CKFT_WRITE_PROTECTED),
	SKS_ID(SKS_CKFT_LOGIN_REQUIRED),
	SKS_ID(SKS_CKFT_USER_PIN_INITIALIZED),
	SKS_ID(SKS_CKFT_RESTORE_KEY_NOT_NEEDED),
	SKS_ID(SKS_CKFT_CLOCK_ON_TOKEN),
	SKS_ID(SKS_CKFT_PROTECTED_AUTHENTICATION_PATH),
	SKS_ID(SKS_CKFT_DUAL_CRYPTO_OPERATIONS),
	SKS_ID(SKS_CKFT_TOKEN_INITIALIZED),
	SKS_ID(SKS_CKFT_USER_PIN_COUNT_LOW),
	SKS_ID(SKS_CKFT_USER_PIN_FINAL_TRY),
	SKS_ID(SKS_CKFT_USER_PIN_LOCKED),
	SKS_ID(SKS_CKFT_USER_PIN_TO_BE_CHANGED),
	SKS_ID(SKS_CKFT_SO_PIN_COUNT_LOW),
	SKS_ID(SKS_CKFT_SO_PIN_FINAL_TRY),
	SKS_ID(SKS_CKFT_SO_PIN_LOCKED),
	SKS_ID(SKS_CKFT_SO_PIN_TO_BE_CHANGED),
	SKS_ID(SKS_CKFT_ERROR_STATE),
};

static const struct string_id __maybe_unused string_class[] = {
	SKS_ID(SKS_CKO_SECRET_KEY),
	SKS_ID(SKS_CKO_PUBLIC_KEY),
	SKS_ID(SKS_CKO_PRIVATE_KEY),
	SKS_ID(SKS_CKO_OTP_KEY),
	SKS_ID(SKS_CKO_CERTIFICATE),
	SKS_ID(SKS_CKO_DATA),
	SKS_ID(SKS_CKO_DOMAIN_PARAMETERS),
	SKS_ID(SKS_CKO_HW_FEATURE),
	SKS_ID(SKS_CKO_MECHANISM),
	SKS_ID(SKS_UNDEFINED_ID)
};

static const struct string_id __maybe_unused string_key_type[] = {
	SKS_ID(SKS_CKK_AES),
	SKS_ID(SKS_CKK_GENERIC_SECRET),
	SKS_ID(SKS_CKK_MD5_HMAC),
	SKS_ID(SKS_CKK_SHA_1_HMAC),
	SKS_ID(SKS_CKK_SHA224_HMAC),
	SKS_ID(SKS_CKK_SHA256_HMAC),
	SKS_ID(SKS_CKK_SHA384_HMAC),
	SKS_ID(SKS_CKK_SHA512_HMAC),
	SKS_ID(SKS_UNDEFINED_ID)
};

static const struct string_id __maybe_unused string_processing[] = {
	SKS_ID(SKS_CKM_AES_ECB),
	SKS_ID(SKS_CKM_AES_CBC),
	SKS_ID(SKS_CKM_AES_CBC_PAD),
	SKS_ID(SKS_CKM_AES_CTR),
	SKS_ID(SKS_CKM_AES_GCM),
	SKS_ID(SKS_CKM_AES_CCM),
	SKS_ID(SKS_CKM_AES_CTS),
	SKS_ID(SKS_CKM_AES_GMAC),
	SKS_ID(SKS_CKM_AES_CMAC),
	SKS_ID(SKS_CKM_AES_CMAC_GENERAL),
	SKS_ID(SKS_CKM_AES_ECB_ENCRYPT_DATA),
	SKS_ID(SKS_CKM_AES_CBC_ENCRYPT_DATA),
	SKS_ID(SKS_CKM_AES_KEY_GEN),
	SKS_ID(SKS_CKM_GENERIC_SECRET_KEY_GEN),
	SKS_ID(SKS_CKM_MD5_HMAC),
	SKS_ID(SKS_CKM_SHA_1_HMAC),
	SKS_ID(SKS_CKM_SHA224_HMAC),
	SKS_ID(SKS_CKM_SHA256_HMAC),
	SKS_ID(SKS_CKM_SHA384_HMAC),
	SKS_ID(SKS_CKM_SHA512_HMAC),
	SKS_ID(SKS_CKM_AES_XCBC_MAC),
	SKS_ID(SKS_UNDEFINED_ID)
};

/* Processing IDs not exported in the TA API */
static const struct string_id __maybe_unused string_internal_processing[] = {
	SKS_ID(SKS_PROCESSING_IMPORT),
	SKS_ID(SKS_PROCESSING_COPY),
};

static const struct string_id __maybe_unused string_proc_flags[] = {
	SKS_ID(SKS_CKFM_HW),
	SKS_ID(SKS_CKFM_ENCRYPT),
	SKS_ID(SKS_CKFM_DECRYPT),
	SKS_ID(SKS_CKFM_DIGEST),
	SKS_ID(SKS_CKFM_SIGN),
	SKS_ID(SKS_CKFM_SIGN_RECOVER),
	SKS_ID(SKS_CKFM_VERIFY),
	SKS_ID(SKS_CKFM_VERIFY_RECOVER),
	SKS_ID(SKS_CKFM_GENERATE),
	SKS_ID(SKS_CKFM_GENERATE_PAIR),
	SKS_ID(SKS_CKFM_WRAP),
	SKS_ID(SKS_CKFM_UNWRAP),
	SKS_ID(SKS_CKFM_DERIVE),
};
#endif /*CFG_TEE_TA_LOG_LEVEL*/

/*
 * Helper functions to analyse SKS identifiers
 */

size_t sks_attr_is_class(uint32_t attribute_id)
{
	if (attribute_id == SKS_CKA_CLASS)
		return sizeof(uint32_t);
	else
		return 0;
}

size_t sks_attr_is_type(uint32_t attribute_id)
{
	switch (attribute_id) {
	case SKS_CKA_KEY_TYPE:
	case SKS_CKA_MECHANISM_TYPE:
		return sizeof(uint32_t);
	default:
		return 0;
	}
}

bool sks_class_has_type(uint32_t class)
{
	switch (class) {
	case SKS_CKO_CERTIFICATE:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_MECHANISM:
	case SKS_CKO_HW_FEATURE:
		return 1;
	default:
		return 0;
	}
}

bool sks_attr_class_is_key(uint32_t class)
{
	switch (class) {
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
		return 1;
	default:
		return 0;
	}
}

/* Returns shift position or -1 on error */
int sks_attr2boolprop_shift(uint32_t attr)
{
	COMPILE_TIME_ASSERT(SKS_BOOLPROPS_BASE == 0);

	if (attr > SKS_BOOLPROPS_LAST)
		return -1;

	return attr;
}

/*
 * Conversion between SKS and GPD TEE return codes
 */

TEE_Result sks2tee_error(uint32_t rv)
{
	switch (rv) {
	case SKS_CKR_OK:
		return TEE_SUCCESS;

	case SKS_CKR_ARGUMENT_BAD:
		return TEE_ERROR_BAD_PARAMETERS;

	case SKS_CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case SKS_CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;

	default:
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result sks2tee_noerr(uint32_t rc)
{
	switch (rc) {
	case SKS_CKR_ARGUMENT_BAD:
		return TEE_ERROR_BAD_PARAMETERS;

	case SKS_CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case SKS_CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;

	case SKS_CKR_GENERAL_ERROR:
		return TEE_ERROR_GENERIC;

	default:
		return TEE_SUCCESS;
	}
}

uint32_t tee2sks_error(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return SKS_CKR_OK;

	case TEE_ERROR_BAD_PARAMETERS:
		return SKS_CKR_ARGUMENT_BAD;

	case TEE_ERROR_OUT_OF_MEMORY:
		return SKS_CKR_DEVICE_MEMORY;

	case TEE_ERROR_SHORT_BUFFER:
		return SKS_CKR_BUFFER_TOO_SMALL;

	case TEE_ERROR_MAC_INVALID:
		return SKS_CKR_SIGNATURE_INVALID;

	default:
		return SKS_CKR_GENERAL_ERROR;
	}
}

bool valid_sks_attribute_id(uint32_t id, uint32_t size)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(attr_ids); n++) {
		if (id != attr_ids[n].id)
			continue;

		/* Check size matches if provided */
		return !size || size == attr_ids[n].size;
	}

	return false;
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/*
 * Convert a SKS ID into its label string
 */
const char *sks2str_attr(uint32_t id)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(attr_ids); n++) {
		if (id != attr_ids[n].id)
			continue;

		/* Skip SKS_ prefix */
		return (char *)attr_ids[n].string + strlen("SKS_CKA_");
	}

	return unknown;
}

static const char *id2str(uint32_t id, const struct string_id *table,
			  size_t count, const char *prefix)
{
	size_t n;
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

#define ID2STR(id, table, prefix)	\
	id2str(id, table, ARRAY_SIZE(table), prefix)

const char *sks2str_class(uint32_t id)
{
	return ID2STR(id, string_class, "SKS_CKO_");
}

const char *sks2str_type(uint32_t id, uint32_t class)
{
	switch (class) {
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
		return sks2str_key_type(id);
	default:
		return unknown;
	}
}
const char *sks2str_key_type(uint32_t id)
{
	return ID2STR(id, string_key_type, "SKS_CKK_");
}

const char *sks2str_boolprop(uint32_t id)
{
	if (id < 64)
		return sks2str_attr(id);

	return unknown;
}

const char *sks2str_proc(uint32_t id)
{
	const char *str = ID2STR(id, string_internal_processing, "SKS_PROC_");

	if (str != unknown)
		return str;

	return ID2STR(id, string_processing, "SKS_CKM_");
}

const char *sks2str_proc_flag(uint32_t id)
{
	return ID2STR(id, string_proc_flags, "SKS_CKFM_");
}

const char *sks2str_rc(uint32_t id)
{
	return ID2STR(id, string_rc, "SKS_CKR_");
}

const char *sks2str_skscmd(uint32_t id)
{
	return ID2STR(id, string_cmd, NULL);
}

const char *sks2str_slot_flag(uint32_t id)
{
	return ID2STR(id, string_slot_flags, "SKS_CKFS_");
}

const char *sks2str_token_flag(uint32_t id)
{
	return ID2STR(id, string_token_flags, "SKS_CKFT_");
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
