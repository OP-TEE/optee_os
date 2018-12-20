/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2018, Linaro Limited */
/* Copyright (c) 2017, GlobalLogic  */

#ifndef __TA_GATEKEEPER_H
#define __TA_GATEKEEPER_H

#include <compiler.h>
#include <tee_internal_api.h>
#include <stdint.h>
#include <util.h>
#include <utee_defines.h>

/*
 * Please keep password_handle_t structure consistent with its counterpart
 * which defined in system/gatekeeper/include/gatekeeper/password_handle.h
 */

#define HANDLE_VERSION			2
#define HANDLE_VERSION_THROTTLE		2
#define HANDLE_FLAG_THROTTLE_SECURE	1

#define HW_AUTH_TOKEN_VERSION		0

#define KM_GET_AUTHTOKEN_KEY		65536

/*
 * Please keep this variable consistent with TA_UUID variable that
 * is defined in Keymaster Android.mk file
 */
#define TA_KEYMASTER_UUID { 0xdba51a17, 0x0563, 0x11e7, \
			{ 0x93, 0xb1, 0x6f, 0xa7, 0xb0, 0x07, 0x1a, 0x51} }

/*
 * Please keep this define consistent with KM_GET_AUTHTOKEN_KEY constant that
 * is defined in Keymaster
 */

typedef uint64_t secure_id_t;
typedef uint64_t salt_t;

struct __packed password_handle {
	uint8_t version;
	secure_id_t user_id;
	uint64_t flags;
	salt_t salt;
	uint8_t signature[TEE_SHA256_HASH_SIZE];
	bool hardware_backed;
};

/*
 * Please keep hw_auth_token_t structure consistent with its counterpart
 * which defined in hardware/libhardware/include/hardware/hw_auth_token.h
 */
enum hw_authenticator {
	HW_AUTH_NONE = 0,
	HW_AUTH_PASSWORD = BIT(0),
	HW_AUTH_FINGERPRINT = BIT(1),
	/* Additional entries should be powers of 2. */
	HW_AUTH_ANY = INT_MAX
};
/*
 * Data format for an authentication record used
 * to prove successful authentication.
 */
struct __packed hw_auth_token {
	uint8_t version;
	uint64_t challenge;
	uint64_t user_id;             /* secure user ID, not Android user ID */
	uint64_t authenticator_id;    /* secure authenticator ID */
	uint32_t authenticator_type;  /* hw_authenticator_type_t */
	uint64_t timestamp;
	uint8_t hmac[TEE_SHA256_HASH_SIZE];
};


#endif /* __TA_GATEKEEPER_H */
