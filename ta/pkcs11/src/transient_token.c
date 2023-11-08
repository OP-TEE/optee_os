// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>

#include "pkcs11_token.h"

enum pkcs11_rc init_transient_db(struct ck_token *token)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct token_persistent_main *db_main = NULL;

	if (!token)
		return PKCS11_CKR_ARGUMENTS_BAD;

	IMSG("PKCS11 slot %u: init transient token", token->slot->id);

	LIST_INIT(&token->object_list);

	db_main = TEE_Malloc(sizeof(*db_main), TEE_MALLOC_FILL_ZERO);
	if (!db_main) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto error;
	}

	TEE_MemFill(token->token_info->label, '*', sizeof(token->token_info->label));
	db_main->flags = PKCS11_CKFT_SO_PIN_TO_BE_CHANGED |
		PKCS11_CKFT_USER_PIN_TO_BE_CHANGED |
		PKCS11_CKFT_RNG |
		PKCS11_CKFT_LOGIN_REQUIRED;

	token->db_main = db_main;
	token->db_objs = NULL;

	return PKCS11_CKR_OK;

error:
	TEE_Free(db_main);
	return rc;
}
