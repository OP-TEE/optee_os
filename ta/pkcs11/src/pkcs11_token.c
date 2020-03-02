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
