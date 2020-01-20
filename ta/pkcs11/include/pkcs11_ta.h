/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_TA_H
#define PKCS11_TA_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#define PKCS11_TA_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
			 { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

/* PKCS11 trusted application version information */
#define PKCS11_TA_VERSION_MAJOR			0
#define PKCS11_TA_VERSION_MINOR			1
#define PKCS11_TA_VERSION_PATCH			0

/* Attribute specific values */
#define PKCS11_UNAVAILABLE_INFORMATION		UINT32_C(0xFFFFFFFF)
#define PKCS11_UNDEFINED_ID			PKCS11_UNAVAILABLE_INFORMATION
#define PKCS11_FALSE				false
#define PKCS11_TRUE				true

/*
 * Note on PKCS#11 TA commands ABI
 *
 * For evolution of the TA API and to not mess with the GPD TEE 4 parameters
 * constraint, all the PKCS11 TA invocation commands use a subset of available
 * the GPD TEE invocation parameter types.
 *
 * Param#0 is used for the so-called control arguments of the invoked command
 * and for providing a PKCS#11 compliant status code for the request command.
 * Param#0 is an in/out memory reference (aka memref[0]). The input buffer
 * stores the command arguments serialized inside. The output buffer will
 * store the 32bit TA return code for the command. Client shall get this
 * return code and override the GPD TEE Client API legacy TEE_Result value.
 *
 * Param#1 is used for input data arguments of the invoked command.
 * It is unused or is a input memory reference, aka memref[1].
 * Evolution of the API may use memref[1] for output data as well.
 *
 * Param#2 is mostly used for output data arguments of the invoked command
 * and for output handles generated from invoked commands.
 * Few commands uses it for a secondary input data buffer argument.
 * It is unused or is a input/output/in-out memory reference, aka memref[2].
 *
 * Param#3 is currently unused and reserved for evolution of the API.
 */

/*
 * PKCS11_CMD_PING		Acknowledge TA presence and return version info
 *
 * Optinal invocation parameter (if none, command simply returns with success)
 * [out]        memref[2] = [
 *                      32bit version major value,
 *                      32bit version minor value
 *                      32bit version patch value
 *              ]
 */
#define PKCS11_CMD_PING				0

/*
 * Command return codes
 * PKCS11_CKR_<x> relates cryptoki CKR_<x> in meaning if not in value.
 */
enum pkcs11_rc {
	PKCS11_CKR_OK				= 0,
	PKCS11_CKR_GENERAL_ERROR		= 0x0001,
	PKCS11_CKR_DEVICE_MEMORY		= 0x0002,
	PKCS11_CKR_ARGUMENTS_BAD		= 0x0003,
	PKCS11_CKR_BUFFER_TOO_SMALL		= 0x0004,
	PKCS11_CKR_FUNCTION_FAILED		= 0x0005,
	PKCS11_CKR_SIGNATURE_INVALID		= 0x0007,
	PKCS11_CKR_ATTRIBUTE_TYPE_INVALID	= 0x0008,
	PKCS11_CKR_ATTRIBUTE_VALUE_INVALID	= 0x0009,
	PKCS11_CKR_OBJECT_HANDLE_INVALID	= 0x000a,
	PKCS11_CKR_KEY_HANDLE_INVALID		= 0x000b,
	PKCS11_CKR_MECHANISM_INVALID		= 0x000c,
	PKCS11_CKR_SESSION_HANDLE_INVALID	= 0x000d,
	PKCS11_CKR_SLOT_ID_INVALID		= 0x000e,
	PKCS11_CKR_MECHANISM_PARAM_INVALID	= 0x000f,
	PKCS11_CKR_TEMPLATE_INCONSISTENT	= 0x0010,
	PKCS11_CKR_TEMPLATE_INCOMPLETE		= 0x0011,
	PKCS11_CKR_PIN_INCORRECT		= 0x0012,
	PKCS11_CKR_PIN_LOCKED			= 0x0013,
	PKCS11_CKR_PIN_EXPIRED			= 0x0014,
	PKCS11_CKR_PIN_INVALID			= 0x0015,
	PKCS11_CKR_PIN_LEN_RANGE		= 0x0016,
	PKCS11_CKR_SESSION_EXISTS		= 0x0017,
	PKCS11_CKR_SESSION_READ_ONLY		= 0x0018,
	PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS	= 0x0019,
	PKCS11_CKR_OPERATION_ACTIVE		= 0x001a,
	PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED	= 0x001b,
	PKCS11_CKR_OPERATION_NOT_INITIALIZED	= 0x001c,
	PKCS11_CKR_TOKEN_WRITE_PROTECTED	= 0x001d,
	PKCS11_CKR_TOKEN_NOT_PRESENT		= 0x001e,
	PKCS11_CKR_TOKEN_NOT_RECOGNIZED		= 0x001f,
	PKCS11_CKR_ACTION_PROHIBITED		= 0x0020,
	PKCS11_CKR_ATTRIBUTE_READ_ONLY		= 0x0021,
	PKCS11_CKR_PIN_TOO_WEAK			= 0x0022,
	PKCS11_CKR_CURVE_NOT_SUPPORTED		= 0x0023,
	PKCS11_CKR_DOMAIN_PARAMS_INVALID	= 0x0024,
	PKCS11_CKR_USER_ALREADY_LOGGED_IN	= 0x0025,
	PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x0026,
	PKCS11_CKR_USER_NOT_LOGGED_IN		= 0x0027,
	PKCS11_CKR_USER_PIN_NOT_INITIALIZED	= 0x0028,
	PKCS11_CKR_USER_TOO_MANY_TYPES		= 0x0029,
	PKCS11_CKR_USER_TYPE_INVALID		= 0x002a,
	PKCS11_CKR_SESSION_READ_ONLY_EXISTS	= 0x002b,
	PKCS11_CKR_KEY_SIZE_RANGE		= 0x002c,
	PKCS11_CKR_ATTRIBUTE_SENSITIVE		= 0x002d,

	/* Status without strict equivalence in Cryptoki API */
	PKCS11_RV_NOT_FOUND			= 0x1000,
	PKCS11_RV_NOT_IMPLEMENTED		= 0x1001,
};

#endif /*PKCS11_TA_H*/
