// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "pkcs11_token.h"
#include "pkcs11_helpers.h"

void close_persistent_db(struct ck_token *token __unused)
{
}

static void init_pin_keys(struct ck_token *token, unsigned int uid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int token_id = get_token_id(token);
	TEE_ObjectHandle key_hdl = TEE_HANDLE_NULL;
	char file[32] = { 0 };
	int n = 0;

	assert(token_id < 10 && uid < 10);

	n = snprintf(file, sizeof(file), "token.db.%1d-pin%1d", token_id, uid);
	if (n < 0 || (size_t)n >= sizeof(file))
		TEE_Panic(0);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       file, sizeof(file), 0, &key_hdl);

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		TEE_Attribute attr = { };
		TEE_ObjectHandle hdl = TEE_HANDLE_NULL;
		uint8_t pin_key[16] = { 0 };

		TEE_MemFill(&attr, 0, sizeof(attr));

		TEE_GenerateRandom(pin_key, sizeof(pin_key));
		TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
				     pin_key, sizeof(pin_key));

		res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &hdl);
		if (res)
			TEE_Panic(0);

		res = TEE_PopulateTransientObject(hdl, &attr, 1);
		if (res)
			TEE_Panic(0);

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 file, sizeof(file), 0, hdl,
						 pin_key, sizeof(pin_key),
						 &key_hdl);
		TEE_CloseObject(hdl);

		if (res == TEE_SUCCESS)
			DMSG("Token %u: PIN key created", token_id);
	}

	if (res)
		TEE_Panic(res);

	TEE_CloseObject(key_hdl);
}

/*
 * Return the token instance, either initialized from reset or initialized
 * from the token persistent state if found.
 */
struct ck_token *init_persistent_db(unsigned int token_id)
{
	struct ck_token *token = get_token(token_id);
	TEE_Result res = TEE_ERROR_GENERIC;
	char db_file[32] = { 0 };
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;
	struct token_persistent_main *db_main = NULL;
	int n = 0;

	if (!token)
		return NULL;

	for (n = 0; n < PKCS11_MAX_USERS; n++)
		init_pin_keys(token, n);

	db_main = TEE_Malloc(sizeof(*db_main), TEE_MALLOC_FILL_ZERO);
	if (!db_main)
		goto error;

	n = snprintf(db_file, sizeof(db_file), "token.db.%1d", token_id);
	if (n < 0 || (size_t)n >= sizeof(db_file))
		TEE_Panic(0);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       db_file, sizeof(db_file),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_ACCESS_WRITE,
				       &db_hdl);
	if (res == TEE_SUCCESS) {
		uint32_t size = 0;

		IMSG("PKCS11 token %u: load db", token_id);

		size = sizeof(*db_main);
		res = TEE_ReadObjectData(db_hdl, db_main, size, &size);
		if (res || size != sizeof(*db_main))
			TEE_Panic(0);
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		IMSG("PKCS11 token %u: init db", token_id);

		TEE_MemFill(db_main, 0, sizeof(*db_main));
		TEE_MemFill(db_main->label, '*', sizeof(db_main->label));

		db_main->flags = PKCS11_CKFT_SO_PIN_TO_BE_CHANGED |
				 PKCS11_CKFT_USER_PIN_TO_BE_CHANGED |
				 PKCS11_CKFT_RNG |
				 PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS |
				 PKCS11_CKFT_LOGIN_REQUIRED;

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 db_file, sizeof(db_file),
						 TEE_DATA_FLAG_ACCESS_READ |
						 TEE_DATA_FLAG_ACCESS_WRITE,
						 TEE_HANDLE_NULL,
						 db_main, sizeof(*db_main),
						 &db_hdl);
		if (res) {
			EMSG("Failed to create db: %"PRIx32, res);
			goto error;
		}
	} else {
		goto error;
	}

	token->db_main = db_main;
	TEE_CloseObject(db_hdl);

	return token;

error:
	TEE_Free(db_main);
	if (db_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(db_hdl);

	return NULL;
}
