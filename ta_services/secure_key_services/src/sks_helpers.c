/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <string.h>
#include <tee_internal_api.h>

#include "sks_helpers.h"

/*
 * Helper functions to analyse SKS identifiers
 */

size_t sks_attr_is_class(uint32_t attribute_id)
{
	if (attribute_id == SKS_CLASS)
		return sizeof(uint32_t);
	else
		return 0;
}

size_t sks_attr_is_type(uint32_t attribute_id)
{
	switch (attribute_id) {
	case SKS_TYPE:
	case SKS_PROCESSING_ID:
		return sizeof(uint32_t);
	default:
		return 0;
	}
}

bool sks_class_has_type(uint32_t class)
{
	switch (class) {
	case SKS_OBJ_CERTIFICATE:
	case SKS_OBJ_PUB_KEY:
	case SKS_OBJ_PRIV_KEY:
	case SKS_OBJ_SYM_KEY:
	case SKS_OBJ_CK_MECHANISM:
	case SKS_OBJ_CK_HW_FEATURES:
		return 1;
	default:
		return 0;
	}
}

bool sks_attr_class_is_key(uint32_t class)
{
	switch (class) {
	case SKS_OBJ_SYM_KEY:
	case SKS_OBJ_PUB_KEY:
	case SKS_OBJ_PRIV_KEY:
		return 1;
	default:
		return 0;
	}
}

/* Returns shift position or -1 on error */
int sks_attr2boolprop_shift(uint32_t attr)
{
	if (attr < SKS_BOOLPROPS_BASE || attr > SKS_BOOLPROPS_LAST)
		return -1;

	return attr - SKS_BOOLPROPS_BASE;
}

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

	default:
		return SKS_ERROR;
	}
}

#undef SKS_ID_SZ
#define SKS_ID_SZ(_sks, _size)		\
	case _sks: \
		return !_size || size == _size;

/* This is a bit ugly... */
bool valid_sks_attribute_id(uint32_t id, uint32_t size)
{
	switch (id) {
	/* Below are all SKS attributes IDs relted to a Cryptoki ID */
	SKS_ATTRIBS_IDS
	default:
		return false;
	}
}

#if CFG_TEE_TA_LOG_LEVEL > 0

struct id2str {
	uint32_t id;
	const char *string;
};

static const char unknown[] = "<unknown-identifier>";

/*
 * Convert a SKS ID into its label string
 */
#undef SKS_ID_SZ
#define SKS_ID_SZ(sks, size)		{ .id = sks, .string = #sks },

#undef SKS_ID
#define SKS_ID(sks)		{ .id = sks, .string = #sks },

static struct id2str sks_attr2str_table[] = {
	SKS_ATTRIBS_IDS
	/* Add below the attributes not exported to the TA API */
};

static struct id2str sks_class2str_table[] = {
	SKS_OBJECT_CLASS_IDS
};

static struct id2str sks_key_type2str_table[] = {
	SKS_KEY_TYPE_IDS
};

static struct id2str boolattr2str_table[] = {
	SKS_BOOLPROP_ATTRIBS_IDS
};

static struct id2str proc_flag2str_table[] = {
	SKS_MECHANISM_FLAG_IDS
};

static struct id2str sks_proc2str_table[] = {
	SKS_PROCESSING_IDS
	/* Add below retrun codes not exported to TA API */
	SKS_ID(SKS_PROC_RAW_IMPORT)
	SKS_ID(SKS_PROC_RAW_COPY)
};

static struct id2str sks_rc2str_table[] = {
	SKS_ERROR_CODES
	/* Add below retrun codes not exported to TA API */
};

static struct id2str cmd2str_table[] = {
	SKS_COMMAND_IDS
};

static struct id2str slot_flag2str_table[] = {
	SKS_SLOT_FLAG_MASKS
};

static struct id2str token_flag2str_table[] = {
	SKS_TOKEN_FLAG_MASKS
};

#define ID2STR(id, table, prefix)	\
	id2str(id, table, sizeof(table) / sizeof(struct id2str), prefix)

static const char *id2str(uint32_t id, struct id2str *table, size_t count,
			  const char *prefix)
{
	size_t n;
	const char *str = NULL;

	for (n = 0; n < count; n++) {
		if (id != table[n].id)
			continue;

		str = table[n].string;

		if (prefix && !TEE_MemCompare(str, prefix, strlen(prefix)))
			str += strlen(prefix);

		return str;
	}

	return unknown;
}

const char *sks2str_attr(uint32_t id)
{
	return ID2STR(id, sks_attr2str_table, "SKS_");
}

const char *sks2str_class(uint32_t id)
{
	return ID2STR(id, sks_class2str_table, "SKS_OBJ_");
}

const char *sks2str_type(uint32_t id, uint32_t class)
{
	switch (class) {
	case SKS_OBJ_SYM_KEY:
	case SKS_OBJ_PUB_KEY:
	case SKS_OBJ_PRIV_KEY:
		return sks2str_key_type(id);
	default:
		return unknown;
	}
}
const char *sks2str_key_type(uint32_t id)
{
	return ID2STR(id, sks_key_type2str_table, "SKS_");
}

/* TODO: this supports only up to 32 boolprop */
const char *sks2str_boolprop(uint32_t id)
{
	return ID2STR(id, boolattr2str_table, "SKS_BP_");
}

const char *sks2str_proc(uint32_t id)
{
	return ID2STR(id, sks_proc2str_table, "SKS_PROC_");
}

const char *sks2str_proc_flag(uint32_t id)
{
	return ID2STR(id, proc_flag2str_table, "SKS_PROC_");
}

const char *sks2str_rc(uint32_t id)
{
	return ID2STR(id, sks_rc2str_table, "SKS_");
}

const char *sks2str_skscmd(uint32_t id)
{
	return ID2STR(id, cmd2str_table, NULL);
}

const char *sks2str_slot_flag(uint32_t id)
{
	return ID2STR(id, slot_flag2str_table, "SKS_TOKEN_");
}

const char *sks2str_token_flag(uint32_t id)
{
	return ID2STR(id, token_flag2str_table, "SKS_TOKEN_");
}
#endif /* CFG_TEE_TA_LOG_LEVEL */
