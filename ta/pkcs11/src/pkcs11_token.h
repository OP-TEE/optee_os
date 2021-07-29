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
#include "object.h"
#include "pkcs11_attributes.h"

/* Hard coded description */
#define PKCS11_SLOT_DESCRIPTION		"OP-TEE PKCS11 TA"
#define PKCS11_SLOT_MANUFACTURER	"Linaro"
#define PKCS11_SLOT_HW_VERSION		{ 0, 0 }
#define PKCS11_SLOT_FW_VERSION		{ PKCS11_TA_VERSION_MAJOR, \
					  PKCS11_TA_VERSION_MINOR }

#define PKCS11_TOKEN_LABEL		"OP-TEE PKCS#11 TA token"
#define PKCS11_TOKEN_MANUFACTURER	PKCS11_SLOT_MANUFACTURER
#define PKCS11_TOKEN_MODEL		"OP-TEE TA"
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
#define PKCS11_TOKEN_PIN_SIZE_MIN	4
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
	union {
		uint8_t so_pin_hash[TEE_MAX_HASH_SIZE];
		TEE_Identity so_identity;
	};
	uint32_t user_pin_count;
	uint32_t user_pin_salt;
	union {
		uint8_t user_pin_hash[TEE_MAX_HASH_SIZE];
		TEE_Identity user_identity;
	};
};

/*
 * Persistent objects in the token
 *
 * @count - number of objects stored in the token
 * @uuids - array of object references/UUIDs (@count items)
 */
struct token_persistent_objs {
	uint32_t count;
	TEE_UUID uuids[];
};

/*
 * Runtime state of the token, complies with pkcs11
 *
 * @state - Pkcs11 login is public, user, SO or custom
 * @session_count - Counter for opened Pkcs11 sessions
 * @rw_session_count - Count for opened Pkcs11 read/write sessions
 * @object_list - List of the objects owned by the token
 * @db_main - Volatile copy of the persistent main database
 * @db_objs - Volatile copy of the persistent object database
 */
struct ck_token {
	enum pkcs11_token_state state;
	uint32_t session_count;
	uint32_t rw_session_count;
	struct object_list object_list;
	/* Copy in RAM of the persistent database */
	struct token_persistent_main *db_main;
	struct token_persistent_objs *db_objs;
};

/*
 * A session can enter a processing state (encrypt, decrypt, digest, ...)
 * only from the initialized state. A session must return the initialized
 * state (from a processing finalization request) before entering another
 * processing state.
 */
enum pkcs11_proc_state {
	PKCS11_SESSION_READY = 0,		/* No active processing */
	PKCS11_SESSION_ENCRYPTING,
	PKCS11_SESSION_DECRYPTING,
	PKCS11_SESSION_DIGESTING,
	PKCS11_SESSION_DIGESTING_ENCRYPTING,	/* case C_DigestEncryptUpdate */
	PKCS11_SESSION_DECRYPTING_DIGESTING,	/* case C_DecryptDigestUpdate */
	PKCS11_SESSION_SIGNING,
	PKCS11_SESSION_SIGNING_ENCRYPTING,	/* case C_SignEncryptUpdate */
	PKCS11_SESSION_VERIFYING,
	PKCS11_SESSION_DECRYPTING_VERIFYING,	/* case C_DecryptVerifyUpdate */
	PKCS11_SESSION_SIGNING_RECOVER,
	PKCS11_SESSION_VERIFYING_RECOVER,
	PKCS11_SESSION_BUSY,
};

/*
 * Context of the active processing in the session
 *
 * @state - ongoing active processing function or ready state
 * @mecha_type - mechanism type of the active processing
 * @always_authen - true if user need to login before each use
 * @relogged - true once client logged since last operation update
 * @op_step - last active operation step - update, final or one-shot
 * @tee_op_handle - handle on active crypto operation or TEE_HANDLE_NULL
 * @tee_hash_algo - hash algorithm identifier.
 * @tee_hash_op_handle - handle on active hashing crypto operation or
 * TEE_HANDLE_NULL
 * @extra_ctx - context for the active processing
 */
struct active_processing {
	enum pkcs11_proc_state state;
	uint32_t mecha_type;
	enum processing_step step;
	bool always_authen;
	bool relogged;
	TEE_OperationHandle tee_op_handle;
	uint32_t tee_hash_algo;
	TEE_OperationHandle tee_hash_op_handle;
	void *extra_ctx;
};

/*
 * Pkcs11 objects search context
 *
 * @attributes - matching attributes list searched (null if no search)
 * @count - number of matching handle found
 * @handles - array of handle of matching objects
 * @next - index of the next object handle to return to C_FindObject
 */
struct pkcs11_find_objects {
	void *attributes;
	size_t count;
	uint32_t *handles;
	size_t next;
};

/*
 * Structure tracking the PKCS#11 sessions
 *
 * @link - List of the session belonging to a client
 * @client - Client the session belongs to
 * @token - Token this session belongs to
 * @handle - Identifier of the session published to the client
 * @object_list - Entry of the session objects list
 * @state - R/W SO, R/W user, RO user, R/W public, RO public.
 * @processing - Reference to initialized processing context if any
 * @find_ctx - Reference to active search context (null if no active search)
 */
struct pkcs11_session {
	TAILQ_ENTRY(pkcs11_session) link;
	struct pkcs11_client *client;
	struct ck_token *token;
	enum pkcs11_mechanism_id handle;
	struct object_list object_list;
	enum pkcs11_session_state state;
	struct active_processing *processing;
	struct pkcs11_find_objects *find_ctx;
};

/* Initialize static token instance(s) from default/persistent database */
TEE_Result pkcs11_init(void);
void pkcs11_deinit(void);

/* Speculation safe lookup of token instance from token identifier */
struct ck_token *get_token(unsigned int token_id);

/* Return token identified from token instance address */
unsigned int get_token_id(struct ck_token *token);

/* Return client's (shared) object handle database associated with session */
struct handle_db *get_object_handle_db(struct pkcs11_session *session);

/* Access to persistent database */
struct ck_token *init_persistent_db(unsigned int token_id);
void update_persistent_db(struct ck_token *token);
void close_persistent_db(struct ck_token *token);

/* Load and release persistent object attributes in memory */
enum pkcs11_rc load_persistent_object_attributes(struct pkcs11_object *obj);
void release_persistent_object_attributes(struct pkcs11_object *obj);
enum pkcs11_rc update_persistent_object_attributes(struct pkcs11_object *obj);

enum pkcs11_rc hash_pin(enum pkcs11_user_type user, const uint8_t *pin,
			size_t pin_size, uint32_t *salt,
			uint8_t hash[TEE_MAX_HASH_SIZE]);
enum pkcs11_rc verify_pin(enum pkcs11_user_type user, const uint8_t *pin,
			  size_t pin_size, uint32_t salt,
			  const uint8_t hash[TEE_MAX_HASH_SIZE]);

#if defined(CFG_PKCS11_TA_AUTH_TEE_IDENTITY)
enum pkcs11_rc setup_so_identity_auth_from_client(struct ck_token *token);
enum pkcs11_rc setup_identity_auth_from_pin(struct ck_token *token,
					    enum pkcs11_user_type user_type,
					    const uint8_t *pin,
					    size_t pin_size);
enum pkcs11_rc verify_identity_auth(struct ck_token *token,
				    enum pkcs11_user_type user_type);
#else
static inline enum pkcs11_rc
setup_so_identity_auth_from_client(struct ck_token *token __unused)
{
	return PKCS11_CKR_PIN_INVALID;
}

static inline enum pkcs11_rc
setup_identity_auth_from_pin(struct ck_token *token __unused,
			     enum pkcs11_user_type user_type __unused,
			     const uint8_t *pin __unused,
			     size_t pin_size __unused)
{
	return PKCS11_CKR_PIN_INVALID;
}

static inline enum pkcs11_rc
verify_identity_auth(struct ck_token *token __unused,
		     enum pkcs11_user_type user_type __unused)
{
	return PKCS11_CKR_PIN_INCORRECT;
}
#endif /* CFG_PKCS11_TA_AUTH_TEE_IDENTITY */

/* Token persistent objects */
enum pkcs11_rc create_object_uuid(struct ck_token *token,
				  struct pkcs11_object *obj);
void destroy_object_uuid(struct ck_token *token, struct pkcs11_object *obj);
enum pkcs11_rc unregister_persistent_object(struct ck_token *token,
					    TEE_UUID *uuid);
enum pkcs11_rc register_persistent_object(struct ck_token *token,
					  TEE_UUID *uuid);
enum pkcs11_rc get_persistent_objects_list(struct ck_token *token,
					   TEE_UUID *array, size_t *size);

/*
 * Pkcs11 session support
 */
struct session_list *get_session_list(struct pkcs11_session *session);
struct pkcs11_client *tee_session2client(void *tee_session);
struct pkcs11_client *register_client(void);
void unregister_client(struct pkcs11_client *client);

struct pkcs11_session *pkcs11_handle2session(uint32_t handle,
					     struct pkcs11_client *client);

static inline bool session_is_active(struct pkcs11_session *session)
{
	return session->processing;
}

enum pkcs11_rc set_processing_state(struct pkcs11_session *session,
				    enum processing_func function,
				    struct pkcs11_object *obj1,
				    struct pkcs11_object *obj2);

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
struct object_list *pkcs11_get_session_objects(struct pkcs11_session *session)
{
	return &session->object_list;
}

static inline
struct ck_token *pkcs11_session2token(struct pkcs11_session *session)
{
	return session->token;
}

/* Entry point for the TA commands */
enum pkcs11_rc entry_ck_slot_list(uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_slot_info(uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_token_info(uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_token_mecha_ids(uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_token_mecha_info(uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_open_session(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_close_session(struct pkcs11_client *client,
				      uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_close_all_sessions(struct pkcs11_client *client,
					   uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_session_info(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_token_initialize(uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_init_pin(struct pkcs11_client *client,
				 uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_set_pin(struct pkcs11_client *client,
				uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_login(struct pkcs11_client *client,
			      uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_logout(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_seed_random(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params);
enum pkcs11_rc entry_ck_generate_random(struct pkcs11_client *client,
					uint32_t ptypes, TEE_Param *params);

#endif /*PKCS11_TA_PKCS11_TOKEN_H*/
