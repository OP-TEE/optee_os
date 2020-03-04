/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */
#ifndef PKCS11_TA_PKCS11_TOKEN_H
#define PKCS11_TA_PKCS11_TOKEN_H

#include <sys/queue.h>
#include <tee_api_types.h>
#include <tee_internal_api.h>

/* Hard coded description */
#define PKCS11_SLOT_DESCRIPTION		"OP-TEE PKCS11 TA"
#define PKCS11_SLOT_MANUFACTURER	"Linaro"
#define PKCS11_SLOT_HW_VERSION		{ 0, 0 }
#define PKCS11_SLOT_FW_VERSION		{ PKCS11_TA_VERSION_MAJOR, \
					  PKCS11_TA_VERSION_MINOR }

#define PKCS11_TOKEN_LABEL		"OP-TEE PKCS#11 TA token"
#define PKCS11_TOKEN_MANUFACTURER	PKCS11_SLOT_MANUFACTURER
#define PKCS11_TOKEN_MODEL		"OP-TEE TA"
#define PKCS11_TOKEN_SERIAL_NUMBER	"0000000000000000"
#define PKCS11_TOKEN_HW_VERSION		PKCS11_SLOT_HW_VERSION
#define PKCS11_TOKEN_FW_VERSION		PKCS11_SLOT_FW_VERSION

enum pkcs11_token_state {
	PKCS11_TOKEN_RESET = 0,
	PKCS11_TOKEN_READ_WRITE,
	PKCS11_TOKEN_READ_ONLY,
};

#define PKCS11_MAX_USERS		2
#define PKCS11_TOKEN_PIN_SIZE_MAX	128
#define PKCS11_TOKEN_PIN_SIZE_MIN	10

/*
 * Persistent state of the token
 *
 * @version - currently unused...
 * @label - pkcs11 formatted token label, set by client
 * @flags - pkcs11 token flags
 * @so_pin_count - counter on security officer login failure
 * @so_pin_size - byte size of the provisioned SO PIN
 * @so_pin - stores the SO PIN
 * @user_pin_count - counter on user login failure
 * @user_pin_size - byte size of the provisioned user PIN
 * @user_pin - stores the user PIN
 */
struct token_persistent_main {
	uint32_t version;
	uint8_t label[PKCS11_TOKEN_LABEL_SIZE];
	uint32_t flags;
	uint32_t so_pin_count;
	uint32_t so_pin_size;
	uint8_t so_pin[PKCS11_TOKEN_PIN_SIZE_MAX];
	uint32_t user_pin_count;
	uint32_t user_pin_size;
	uint8_t user_pin[PKCS11_TOKEN_PIN_SIZE_MAX];
};

/*
 * Runtime state of the token, complies with pkcs11
 *
 * @state - Pkcs11 login is public, user, SO or custom
 * @session_count - Counter for opened Pkcs11 sessions
 * @rw_session_count - Count for opened Pkcs11 read/write sessions
 * @db_main - Volatile copy of the persistent main database
 */
struct ck_token {
	enum pkcs11_token_state state;
	uint32_t session_count;
	uint32_t rw_session_count;
	/* Copy in RAM of the persistent database */
	struct token_persistent_main *db_main;
};

/* Initialize static token instance(s) from default/persistent database */
TEE_Result pkcs11_init(void);
void pkcs11_deinit(void);

/* Speculation safe lookup of token instance from token identifier */
struct ck_token *get_token(unsigned int token_id);

/* Return token identified from token instance address */
unsigned int get_token_id(struct ck_token *token);

/* Access to persistent database */
struct ck_token *init_persistent_db(unsigned int token_id);
void close_persistent_db(struct ck_token *token);

/* Entry point for the TA commands */
uint32_t entry_ck_slot_list(uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_slot_info(uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_token_info(uint32_t ptypes, TEE_Param *params);

#endif /*PKCS11_TA_PKCS11_TOKEN_H*/
