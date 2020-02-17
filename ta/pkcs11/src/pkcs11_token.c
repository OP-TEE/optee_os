// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <confine_array_index.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "pkcs11_token.h"
#include "pkcs11_helpers.h"
#include "serializer.h"

/* Provide 3 slots/tokens, ID is token index */
#ifndef CFG_PKCS11_TA_TOKEN_COUNT
#define TOKEN_COUNT		3
#else
#define TOKEN_COUNT		CFG_PKCS11_TA_TOKEN_COUNT
#endif

/* Static allocation of tokens runtime instances (reset to 0 at load) */
struct ck_token ck_token[TOKEN_COUNT];

struct ck_token *get_token(unsigned int token_id)
{
	if (token_id < TOKEN_COUNT)
		return &ck_token[confine_array_index(token_id, TOKEN_COUNT)];

	return NULL;
}

unsigned int get_token_id(struct ck_token *token)
{
	ptrdiff_t id = token - ck_token;

	assert(id >= 0 && id < TOKEN_COUNT);
	return id;
}

static TEE_Result pkcs11_token_init(unsigned int id)
{
	struct ck_token *token = init_persistent_db(id);

	if (!token)
		return TEE_ERROR_SECURITY;

	if (token->state == PKCS11_TOKEN_RESET) {
		/* As per PKCS#11 spec, token resets to read/write state */
		token->state = PKCS11_TOKEN_READ_WRITE;
		token->session_count = 0;
		token->rw_session_count = 0;
	}

	return TEE_SUCCESS;
}

TEE_Result pkcs11_init(void)
{
	unsigned int id = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	for (id = 0; id < TOKEN_COUNT; id++) {
		ret = pkcs11_token_init(id);
		if (ret)
			return ret;
	}

	return ret;
}

void pkcs11_deinit(void)
{
	unsigned int id = 0;

	for (id = 0; id < TOKEN_COUNT; id++)
		close_persistent_db(get_token(id));
}

uint32_t entry_ck_slot_list(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *out = &params[2];
	uint32_t token_id = 0;
	const size_t out_size = sizeof(token_id) * TOKEN_COUNT;
	uint8_t *id = NULL;

	if (ptypes != exp_pt ||
	    params[0].memref.size != TEE_PARAM0_SIZE_MIN)
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (out->memref.size < out_size) {
		out->memref.size = out_size;

		if (out->memref.buffer)
			return PKCS11_CKR_BUFFER_TOO_SMALL;
		else
			return PKCS11_CKR_OK;
	}

	for (token_id = 0, id = out->memref.buffer; token_id < TOKEN_COUNT;
	     token_id++, id += sizeof(token_id))
		TEE_MemMove(id, &token_id, sizeof(token_id));

	out->memref.size = out_size;

	return PKCS11_CKR_OK;
}

static void pad_str(uint8_t *str, size_t size)
{
	int n = strnlen((char *)str, size);

	TEE_MemFill(str + n, ' ', size - n);
}

uint32_t entry_ck_slot_info(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_slot_info info = {
		.slot_description = PKCS11_SLOT_DESCRIPTION,
		.manufacturer_id = PKCS11_SLOT_MANUFACTURER,
		.flags = PKCS11_CKFS_TOKEN_PRESENT,
		.hardware_version = PKCS11_SLOT_HW_VERSION,
		.firmware_version = PKCS11_SLOT_FW_VERSION,
	};

	COMPILE_TIME_ASSERT(sizeof(PKCS11_SLOT_DESCRIPTION) <=
			    sizeof(info.slot_description));
	COMPILE_TIME_ASSERT(sizeof(PKCS11_SLOT_MANUFACTURER) <=
			    sizeof(info.manufacturer_id));

	if (ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	pad_str(info.slot_description, sizeof(info.slot_description));
	pad_str(info.manufacturer_id, sizeof(info.manufacturer_id));

	out->memref.size = sizeof(info);
	TEE_MemMove(out->memref.buffer, &info, out->memref.size);

	return PKCS11_CKR_OK;
}
