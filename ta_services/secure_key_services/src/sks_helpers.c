// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <sks_ta.h>
#include <string.h>

#include "sks_helpers.h"

struct string_id {
	uint32_t id;
	const char *string;
};

#define SKS_ID(_id)		{ .id = _id, .string = #_id }

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
	SKS_ID(SKS_OK),
	SKS_ID(SKS_ERROR),
	SKS_ID(SKS_MEMORY),
	SKS_ID(SKS_BAD_PARAM),
	SKS_ID(SKS_SHORT_BUFFER),
	SKS_ID(SKS_FAILED),
	SKS_ID(SKS_NOT_FOUND),
	SKS_ID(SKS_VERIFY_FAILED),
	SKS_ID(SKS_INVALID_ATTRIBUTES),
	SKS_ID(SKS_INVALID_TYPE),
	SKS_ID(SKS_INVALID_VALUE),
	SKS_ID(SKS_INVALID_OBJECT),
	SKS_ID(SKS_INVALID_KEY),
	SKS_ID(SKS_INVALID_PROC),
	SKS_ID(SKS_INVALID_SESSION),
	SKS_ID(SKS_INVALID_SLOT),
	SKS_ID(SKS_INVALID_PROC_PARAM),
	SKS_ID(SKS_PIN_INCORRECT),
	SKS_ID(SKS_PIN_LOCKED),
	SKS_ID(SKS_PIN_EXPIRED),
	SKS_ID(SKS_PIN_INVALID),
	SKS_ID(SKS_CK_SESSION_PENDING),
	SKS_ID(SKS_CK_SESSION_IS_READ_ONLY),
	SKS_ID(SKS_CK_SO_IS_LOGGED_READ_WRITE),
	SKS_ID(SKS_PROCESSING_ACTIVE),
	SKS_ID(SKS_CK_NOT_PERMITTED),
	SKS_ID(SKS_PROCESSING_INACTIVE),
	SKS_ID(SKS_UNDEFINED_ID)
};

static const struct string_id __maybe_unused string_slot_flags[] = {
	SKS_ID(SKS_TOKEN_PRESENT),
	SKS_ID(SKS_TOKEN_REMOVABLE),
	SKS_ID(SKS_TOKEN_HW),
};

static const struct string_id __maybe_unused string_token_flags[] = {
	SKS_ID(SKS_TOKEN_HAS_RNG),
	SKS_ID(SKS_TOKEN_IS_READ_ONLY),
	SKS_ID(SKS_TOKEN_REQUIRE_LOGIN),
	SKS_ID(SKS_TOKEN_HAS_USER_PIN),
	SKS_ID(SKS_TOKEN_FULLY_RESTORABLE),
	SKS_ID(SKS_TOKEN_HAS_CLOCK),
	SKS_ID(SKS_TOKEN_ALT_AUTHENT),
	SKS_ID(SKS_TOKEN_CAN_DUAL_PROC),
	SKS_ID(SKS_TOKEN_INITED),
	SKS_ID(SKS_TOKEN_USR_PIN_FAILURE),
	SKS_ID(SKS_TOKEN_USR_PIN_LAST),
	SKS_ID(SKS_TOKEN_USR_PIN_LOCKED),
	SKS_ID(SKS_TOKEN_USR_PIN_TO_CHANGE),
	SKS_ID(SKS_TOKEN_SO_PIN_FAILURE),
	SKS_ID(SKS_TOKEN_SO_PIN_LAST),
	SKS_ID(SKS_TOKEN_SO_PIN_LOCKED),
	SKS_ID(SKS_TOKEN_SO_PIN_TO_CHANGE),
	SKS_ID(SKS_TOKEN_BAD_STATE),
};

/*
 * Conversion between SKS and GPD TEE return codes
 */

TEE_Result sks2tee_error(uint32_t rv)
{
	switch (rv) {
	case SKS_OK:
		return TEE_SUCCESS;

	case SKS_BAD_PARAM:
		return TEE_ERROR_BAD_PARAMETERS;

	case SKS_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case SKS_SHORT_BUFFER:
		return TEE_ERROR_SHORT_BUFFER;

	default:
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result sks2tee_noerr(uint32_t rc)
{
	switch (rc) {
	case SKS_BAD_PARAM:
		return TEE_ERROR_BAD_PARAMETERS;

	case SKS_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case SKS_SHORT_BUFFER:
		return TEE_ERROR_SHORT_BUFFER;

	case SKS_ERROR:
		return TEE_ERROR_GENERIC;

	default:
		return TEE_SUCCESS;
	}
}

uint32_t tee2sks_error(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return SKS_OK;

	case TEE_ERROR_BAD_PARAMETERS:
		return SKS_BAD_PARAM;

	case TEE_ERROR_OUT_OF_MEMORY:
		return SKS_MEMORY;

	case TEE_ERROR_SHORT_BUFFER:
		return SKS_SHORT_BUFFER;

	case TEE_ERROR_MAC_INVALID:
		return SKS_VERIFY_FAILED;
	default:
		return SKS_ERROR;
	}
}

/*
 * Convert a SKS ID into its label string
 */
#if CFG_TEE_TA_LOG_LEVEL > 0

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

const char *sks2str_rc(uint32_t id)
{
	return ID2STR(id, string_rc, "SKS_");
}

const char *sks2str_skscmd(uint32_t id)
{
	return ID2STR(id, string_cmd, NULL);
}

const char *sks2str_slot_flag(uint32_t id)
{
	return ID2STR(id, string_slot_flags, "SKS_TOKEN_");
}

const char *sks2str_token_flag(uint32_t id)
{
	return ID2STR(id, string_token_flags, "SKS_TOKEN_");
}
#endif /* CFG_TEE_TA_LOG_LEVEL */
