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

#define PERSISTENT_OBJECT_ID_LEN	32

/*
 * Token persistent objects
 */
static TEE_Result get_db_file_name(struct ck_token *token,
				   char *name, size_t size)
{
	int n = snprintf(name, size, "token.db.%u", get_token_id(token));

	if (n < 0 || (size_t)n >= size)
		return TEE_ERROR_SECURITY;
	else
		return TEE_SUCCESS;
}

static TEE_Result open_db_file(struct ck_token *token,
			       TEE_ObjectHandle *out_hdl)
{
	char file[PERSISTENT_OBJECT_ID_LEN] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	res = get_db_file_name(token, file, sizeof(file));
	if (res)
		return res;

	return TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, file, sizeof(file),
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE,
					out_hdl);
}

static TEE_Result get_pin_file_name(struct ck_token *token,
				    enum pkcs11_user_type user,
				    char *name, size_t size)
{
	int n = snprintf(name, size,
			 "token.db.%u-pin%d", get_token_id(token), user);

	if (n < 0 || (size_t)n >= size)
		return TEE_ERROR_SECURITY;
	else
		return TEE_SUCCESS;
}

static TEE_Result open_pin_file(struct ck_token *token,
				enum pkcs11_user_type user,
				TEE_ObjectHandle *out_hdl)
{
	char file[PERSISTENT_OBJECT_ID_LEN] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	res = get_pin_file_name(token, user, file, sizeof(file));
	if (res)
		return res;

	return TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, file, sizeof(file),
					0, out_hdl);
}

static void init_pin_keys(struct ck_token *token, unsigned int uid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle key_hdl = TEE_HANDLE_NULL;
	enum pkcs11_user_type user = uid;

	res = open_pin_file(token, user, &key_hdl);

	if (res == TEE_SUCCESS)
		DMSG("PIN key found");

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		TEE_Attribute attr = { };
		TEE_ObjectHandle hdl = TEE_HANDLE_NULL;
		uint8_t pin_key[16] = { };
		char file[PERSISTENT_OBJECT_ID_LEN] = { };

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

		res = get_pin_file_name(token, user, file, sizeof(file));
		if (res)
			TEE_Panic(0);

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 file, sizeof(file), 0, hdl,
						 pin_key, sizeof(pin_key),
						 &key_hdl);
		TEE_CloseObject(hdl);

		if (res == TEE_SUCCESS)
			DMSG("Token %u: PIN key created", get_token_id(token));
	}

	if (res)
		TEE_Panic(res);

	TEE_CloseObject(key_hdl);
}

/*
 * Release resources relate to persistent database
 */
void close_persistent_db(struct ck_token *token __unused)
{
}

/*
 * Return the token instance, either initialized from reset or initialized
 * from the token persistent state if found.
 */
struct ck_token *init_persistent_db(unsigned int token_id)
{
	struct ck_token *token = get_token(token_id);
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;
	/* Copy persistent database: main db and object db */
	struct token_persistent_main *db_main = NULL;

	if (!token)
		return NULL;

	init_pin_keys(token, PKCS11_CKU_SO);
	init_pin_keys(token, PKCS11_CKU_USER);
	COMPILE_TIME_ASSERT(PKCS11_CKU_SO == 0 && PKCS11_CKU_USER == 1 &&
			    PKCS11_MAX_USERS >= 2);

	db_main = TEE_Malloc(sizeof(*db_main), TEE_MALLOC_FILL_ZERO);
	if (!db_main)
		goto error;

	res = open_db_file(token, &db_hdl);

	if (res == TEE_SUCCESS) {
		uint32_t size = 0;

		IMSG("PKCS11 token %u: load db", token_id);

		size = sizeof(*db_main);
		res = TEE_ReadObjectData(db_hdl, db_main, size, &size);
		if (res || size != sizeof(*db_main))
			TEE_Panic(0);
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		char file[PERSISTENT_OBJECT_ID_LEN] = { };

		IMSG("PKCS11 token %u: init db", token_id);

		TEE_MemFill(db_main, 0, sizeof(*db_main));
		TEE_MemFill(db_main->label, '*', sizeof(db_main->label));

		db_main->flags = PKCS11_CKFT_SO_PIN_TO_BE_CHANGED |
				 PKCS11_CKFT_USER_PIN_TO_BE_CHANGED |
				 PKCS11_CKFT_RNG |
				 PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS |
				 PKCS11_CKFT_LOGIN_REQUIRED;

		res = get_db_file_name(token, file, sizeof(file));
		if (res)
			TEE_Panic(0);

		/* 2 files: persistent state + persistent object references */
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 file, sizeof(file),
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
