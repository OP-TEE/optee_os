/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_PKCS11_TOKEN_H
#define __SKS_TA_PKCS11_TOKEN_H

#include <sys/queue.h>
#include <tee_internal_api.h>

#include "handle.h"
#include "object.h"

/* Hard coded description */
#define SKS_CRYPTOKI_TOKEN_LABEL		"op-tee pkcs#11 token (dev...)"
#define SKS_CRYPTOKI_TOKEN_MANUFACTURER		"Linaro"
#define SKS_CRYPTOKI_TOKEN_MODEL		"OP-TEE SKS TA"
#define SKS_CRYPTOKI_TOKEN_SERIAL_NUMBER	"0000000000000000"
#define SKS_CRYPTOKI_TOKEN_HW_VERSION		{ 0, 0 }
#define SKS_CRYPTOKI_TOKEN_FW_VERSION		{ 0, 0 }

#define SKS_CRYPTOKI_SLOT_DESCRIPTION		"OP-TEE SKS TA"
#define SKS_CRYPTOKI_SLOT_MANUFACTURER		SKS_CRYPTOKI_TOKEN_MANUFACTURER
#define SKS_CRYPTOKI_SLOT_HW_VERSION		SKS_CRYPTOKI_TOKEN_HW_VERSION
#define SKS_CRYPTOKI_SLOT_FW_VERSION		SKS_CRYPTOKI_TOKEN_FW_VERSION

#define PADDED_STRING_COPY(_dst, _src) \
	do { \
		TEE_MemFill((char *)(_dst), ' ', sizeof(_dst)); \
		TEE_MemMove((char *)(_dst), (_src), \
			    MIN(strlen((char *)(_src)), sizeof(_dst))); \
	} while (0)

enum pkcs11_token_login_state {
	PKCS11_TOKEN_STATE_INVALID = 0,		/* token default state */
	PKCS11_TOKEN_STATE_PUBLIC_SESSIONS,
	PKCS11_TOKEN_STATE_SECURITY_OFFICER,
	PKCS11_TOKEN_STATE_USER_SESSIONS,
	PKCS11_TOKEN_STATE_CONTEXT_SPECIFIC,
};

enum pkcs11_token_session_state {
	PKCS11_TOKEN_STATE_SESSION_NONE = 0,	/* token default state */
	PKCS11_TOKEN_STATE_SESSION_READ_WRITE,
	PKCS11_TOKEN_STATE_SESSION_READ_ONLY,
};

/* List of toen sessions */
LIST_HEAD(session_list, pkcs11_session);

#define SKS_TOKEN_SO_PIN_SIZE		128
#define SKS_TOKEN_USER_PIN_SIZE		128

/*
 * Persistent state of the token
 *
 * @version - currently unused...
 * @label - pkcs11 formatted token label, set by client
 * @flags - pkcs11 token flags
 * @so_pin_count - counter on security officer loggin failure
 * @so_pin_size - byte size of the provisionned SO PIN
 * @so_pin - stores the SO PIN (TODO: store in an encrypted way)
 * @user_pin_count - counter on user loggin failure
 * @user_pin_size - byte size of the provisionned user PIN
 * @user_pin - stores the user PIN (TODO: store in an encrypted way)
 */
struct token_persistent_main {
	uint32_t version;

	uint8_t label[SKS_TOKEN_LABEL_SIZE];
	uint32_t flags;

	uint32_t so_pin_count;
	uint32_t so_pin_size;
	uint8_t so_pin[SKS_TOKEN_SO_PIN_SIZE];	/* TODO: encrypted */

	uint32_t user_pin_count;
	uint32_t user_pin_size;
	uint8_t user_pin[SKS_TOKEN_USER_PIN_SIZE]; /* TODO: encrypted */
};

/*
 * Persistent objects in the token
 *
 * @count - number of object stored in the token
 * @uudis - start of object references/UUIDs (@count items)
 */
struct token_persistent_objs {
	uint32_t count;
	TEE_UUID uuids[];
};

/*
 * Runtime state of the token, complies with pkcs11
 *
 * @login_state - pkcs11 login
 * @session_state - pkcs11 read/write state
 */
struct ck_token {
	uint32_t session_counter;
	uint32_t rw_session_counter;
	uint32_t user_type;			/* SecurityOfficer, User or Public */

	enum pkcs11_token_login_state login_state;
	enum pkcs11_token_session_state	session_state;

	struct session_list session_list;
	struct handle_db session_handle_db;

	TEE_ObjectHandle db_hdl;	/* Opened handle to persistent database */
	struct token_persistent_main *db_main;		/* Copy persistent database */
	struct token_persistent_objs *db_objs;		/* Copy persistent database */

};

/*
 * A session can enter a processing state (encrypt, decrypt, disgest, ...
 * ony from  the inited state. A sesion must return the the inited
 * state (from a processing finalization request) before entering another
 * processing state.
 */
enum pkcs11_session_processing {
	PKCS11_SESSION_READY = 0,		/* session default state */
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
};

/*
 * Structure tracing the PKCS#11 sessions
 *
 * @link - session litsing
 * @token - token/slot this session belongs to
 * @tee_session - TEE session use to create the PLCS session
 * @handle - identifier of the session
 * @readwrite - true if the session is read/write, false if read-only
 * @state - R/W SO, R/W user, RO user, R/W public, RO public. See PKCS11.
 * @processing - ongoing active processing function
 * @tee_op_handle - halde on active crypto operation
 * @sks_proc - SKS ID of the active processing (TODO: args used at final)
 */
struct pkcs11_session {
	LIST_ENTRY(pkcs11_session) link;
	struct ck_token *token;
	int tee_session;
	int handle;
	bool readwrite;
	uint32_t state;
	enum pkcs11_session_processing processing;
	TEE_OperationHandle tee_op_handle;	// HANDLE_NULL or on-going operation
	uint32_t sks_proc;
	struct object_list object_list;
};

/* pkcs11 token Apis */
int pkcs11_init(void);

struct pkcs11_session *get_pkcs_session(uint32_t ck_handle);

int set_pkcs_session_processing_state(struct pkcs11_session *session,
				      enum pkcs11_session_processing state);

int check_pkcs_session_processing_state(struct pkcs11_session *session,
					enum pkcs11_session_processing state);

bool pkcs11_session_is_read_write(struct pkcs11_session *session);

static inline
struct object_list *pkcs11_get_session_objects(struct pkcs11_session *session)
{
	return &session->object_list;
}

static inline
bool pkcs11_session_is_security_officer(struct pkcs11_session *session)
{
	return session->token->login_state ==
		PKCS11_TOKEN_STATE_SECURITY_OFFICER;
}

static inline
struct ck_token *pkcs11_session2token(struct pkcs11_session *session)
{
	return session->token;
}

/* Token instances */
struct ck_token *get_token(unsigned int token_id);
unsigned int get_token_id(struct ck_token *token);
struct ck_token *init_token_db(unsigned int token_id);

/* Token persistent objects */
uint32_t create_object_uuid(struct ck_token *token, struct sks_object *obj);
void destroy_object_uuid(struct ck_token *token, struct sks_object *obj);
uint32_t unregister_persistent_object(struct ck_token *token, TEE_UUID *uuid);
uint32_t register_persistent_object(struct ck_token *token, TEE_UUID *uuid);

/* Handler for most PKCS#11 API functions */
uint32_t ck_slot_list(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
uint32_t ck_slot_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
uint32_t ck_token_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

uint32_t ck_token_initialize(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

uint32_t ck_token_mecha_ids(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
uint32_t ck_token_mecha_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

TEE_Result ck_token_ro_session(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out);
TEE_Result ck_token_rw_session(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out);
TEE_Result ck_token_close_session(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out);
TEE_Result ck_token_close_all(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out);
void ck_token_close_tee_session(int tee_session);

#endif /*__SKS_TA_PKCS11_TOKEN_H*/
