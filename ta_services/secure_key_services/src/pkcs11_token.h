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

#define SKS_TOKEN_SO_PIN_SIZE		128
#define SKS_TOKEN_USER_PIN_SIZE		128

/*
 * Runtime state of the token, complies with pkcs11
 *
 * @label - pkcs11 formatted token label, set by client
 * @flags - pkcs11 token flags
 * @login_state - pkcs11 login
 * @session_state - pkcs11 read/write state
 */
struct ck_token {
	uint8_t label[SKS_TOKEN_LABEL_SIZE];
	uint32_t flags;

	enum pkcs11_token_login_state login_state;
	enum pkcs11_token_session_state	session_state;
};

/* pkcs11 token Apis */
int pkcs11_init(void);

/* Token instances */
struct ck_token *get_token(unsigned int token_id);
unsigned int get_token_id(struct ck_token *token);
struct ck_token *init_token_db(unsigned int token_id);

/* Handler for most PKCS#11 API functions */
uint32_t ck_slot_list(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
uint32_t ck_slot_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
uint32_t ck_token_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

uint32_t ck_token_mecha_ids(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
uint32_t ck_token_mecha_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

#endif /*__SKS_TA_PKCS11_TOKEN_H*/
