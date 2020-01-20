// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <string.h>
#include <tee_internal_api.h>
#include <util.h>

#include "pkcs11_helpers.h"

static const char __maybe_unused unknown[] = "<unknown-identifier>";

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

#if CFG_TEE_TA_LOG_LEVEL > 0
const char *id2str_rc(uint32_t id)
{
	return ID2STR(id, string_rc, "PKCS11_CKR_");
}

const char *id2str_ta_cmd(uint32_t id)
{
	return ID2STR(id, string_ta_cmd, NULL);
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
