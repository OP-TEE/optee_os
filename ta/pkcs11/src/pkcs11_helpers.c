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

#if CFG_TEE_TA_LOG_LEVEL > 0
const char *id2str_ta_cmd(uint32_t id)
{
	return ID2STR(id, string_ta_cmd, NULL);
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
