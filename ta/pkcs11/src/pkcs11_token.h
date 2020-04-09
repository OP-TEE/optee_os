/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */
#ifndef PKCS11_TA_PKCS11_TOKEN_H
#define PKCS11_TA_PKCS11_TOKEN_H

#include <sys/queue.h>
#include <tee_api_types.h>
#include <tee_internal_api.h>
#include <utee_defines.h>

#include "handle.h"

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

TAILQ_HEAD(client_list, pkcs11_client);
TAILQ_HEAD(session_list, pkcs11_session);

struct pkcs11_client;

#define PKCS11_MAX_USERS		2
#define PKCS11_TOKEN_PIN_SIZE_MAX	128
#define PKCS11_TOKEN_PIN_SIZE_MIN	10
#define PKCS11_TOKEN_SO_PIN_COUNT_MAX	7
#define PKCS11_TOKEN_USER_PIN_COUNT_MAX	7

/*
 * Persistent state of the token
 *
 * @version - currently unused...
 * @label - pkcs11 formatted token label, set by client
 * @flags - pkcs11 token flags
 * @so_pin_count - counter on security officer login failure
 * @so_pin_salt - stores salt in hash of SO PIN, 0 if not set
 * @so_pin_hash - stores hash of SO PIN
 * @user_pin_count - counter on user login failure
 * @user_pin_salt - stores salt in hash of user PIN, 0 if not set
 * @user_pin_hash - stores hash of user PIN
 */
struct token_persistent_main {
	uint32_t version;
	uint8_t label[PKCS11_TOKEN_LABEL_SIZE];
	uint32_t flags;
	uint32_t so_pin_count;
	uint32_t so_pin_salt;
	uint8_t so_pin_hash[TEE_MAX_HASH_SIZE];
	uint32_t user_pin_count;
	uint32_t user_pin_salt;
	uint8_t user_pin_hash[TEE_MAX_HASH_SIZE];
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

/*
 * Structure tracking the PKCS#11 sessions
 *
 * @link - List of the session belonging to a client
 * @client - Client the session belongs to
 * @token - Token this session belongs to
 * @handle - Identifier of the session published to the client
 * @state - R/W SO, R/W user, RO user, R/W public, RO public.
 */
struct pkcs11_session {
	TAILQ_ENTRY(pkcs11_session) link;
	struct pkcs11_client *client;
	struct ck_token *token;
	uint32_t handle;
	enum pkcs11_session_state state;
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
void update_persistent_db(struct ck_token *token);
void close_persistent_db(struct ck_token *token);

enum pkcs11_rc hash_pin(enum pkcs11_user_type user, const uint8_t *pin,
			size_t pin_size, uint32_t *salt,
			uint8_t hash[TEE_MAX_HASH_SIZE]);
enum pkcs11_rc verify_pin(enum pkcs11_user_type user, const uint8_t *pin,
			  size_t pin_size, uint32_t salt,
			  const uint8_t hash[TEE_MAX_HASH_SIZE]);

/*
 * Pkcs11 session support
 */
struct pkcs11_client *tee_session2client(void *tee_session);
struct pkcs11_client *register_client(void);
void unregister_client(struct pkcs11_client *client);

struct pkcs11_session *pkcs11_handle2session(uint32_t handle,
					     struct pkcs11_client *client);

static inline bool pkcs11_session_is_read_write(struct pkcs11_session *session)
{
	return session->state == PKCS11_CKS_RW_PUBLIC_SESSION ||
	       session->state == PKCS11_CKS_RW_USER_FUNCTIONS ||
	       session->state == PKCS11_CKS_RW_SO_FUNCTIONS;
}

static inline bool pkcs11_session_is_public(struct pkcs11_session *session)
{
	return session->state == PKCS11_CKS_RO_PUBLIC_SESSION ||
	       session->state == PKCS11_CKS_RW_PUBLIC_SESSION;
}

static inline bool pkcs11_session_is_user(struct pkcs11_session *session)
{
	return session->state == PKCS11_CKS_RO_USER_FUNCTIONS ||
	       session->state == PKCS11_CKS_RW_USER_FUNCTIONS;
}

static inline bool pkcs11_session_is_so(struct pkcs11_session *session)
{
	return session->state == PKCS11_CKS_RW_SO_FUNCTIONS;
}

static inline
struct ck_token *pkcs11_session2token(struct pkcs11_session *session)
{
	return session->token;
}

/* Entry point for the TA commands */
uint32_t entry_ck_slot_list(uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_slot_info(uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_token_info(uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_token_mecha_ids(uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_token_mecha_info(uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_open_session(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_close_session(struct pkcs11_client *client,
				uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_close_all_sessions(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_session_info(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_token_initialize(uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_init_pin(struct pkcs11_client *client,
			   uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_set_pin(struct pkcs11_client *client,
			  uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_login(struct pkcs11_client *client,
			uint32_t ptypes, TEE_Param *params);
uint32_t entry_ck_logout(struct pkcs11_client *client,
			 uint32_t ptypes, TEE_Param *params);

#endif /*PKCS11_TA_PKCS11_TOKEN_H*/
