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

void update_persistent_db(struct ck_token *token)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;

	res = open_db_file(token, &db_hdl);
	if (res) {
		EMSG("Failed to open token persistent db: %#"PRIx32, res);
		TEE_Panic(0);
	}
	res = TEE_WriteObjectData(db_hdl, token->db_main,
				  sizeof(*token->db_main));
	if (res) {
		EMSG("Failed to write to token persistent db: %#"PRIx32, res);
		TEE_Panic(0);
	}

	TEE_CloseObject(db_hdl);
}

static enum pkcs11_rc do_hash(uint32_t user, const uint8_t *pin,
			      size_t pin_size, uint32_t salt,
			      uint8_t hash[TEE_MAX_HASH_SIZE])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle oh = TEE_HANDLE_NULL;
	uint32_t sz = TEE_MAX_HASH_SIZE;

	res = TEE_AllocateOperation(&oh, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res)
		return tee2pkcs_error(res);

	TEE_DigestUpdate(oh, &user, sizeof(user));
	TEE_DigestUpdate(oh, &salt, sizeof(salt));
	res = TEE_DigestDoFinal(oh, pin, pin_size, hash, &sz);
	TEE_FreeOperation(oh);

	if (res)
		return PKCS11_CKR_GENERAL_ERROR;

	memset(hash + sz, 0, TEE_MAX_HASH_SIZE - sz);
	return PKCS11_CKR_OK;
}

enum pkcs11_rc hash_pin(enum pkcs11_user_type user, const uint8_t *pin,
			size_t pin_size, uint32_t *salt,
			uint8_t hash[TEE_MAX_HASH_SIZE])
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint32_t s = 0;

	TEE_GenerateRandom(&s, sizeof(s));
	if (!s)
		s++;

	rc = do_hash(user, pin, pin_size, s, hash);
	if (!rc)
		*salt = s;
	return rc;
}

enum pkcs11_rc verify_pin(enum pkcs11_user_type user, const uint8_t *pin,
			  size_t pin_size, uint32_t salt,
			  const uint8_t hash[TEE_MAX_HASH_SIZE])
{
	uint8_t tmp_hash[TEE_MAX_HASH_SIZE] = { 0 };
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = do_hash(user, pin, pin_size, salt, tmp_hash);
	if (rc)
		return rc;

	if (buf_compare_ct(tmp_hash, hash, TEE_MAX_HASH_SIZE))
		rc = PKCS11_CKR_PIN_INCORRECT;

	return rc;
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
