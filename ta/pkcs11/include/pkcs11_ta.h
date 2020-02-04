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

enum pkcs11_ta_cmd {
	/*
	 * PKCS11_CMD_PING		Ack TA presence and return version info
	 *
	 * Optinal invocation parameter
	 * [out] memref[2] = [
	 *              32bit version major value,
	 *              32bit version minor value
	 *              32bit version patch value
	 *       ]
	 */
	PKCS11_CMD_PING = 0,

	/*
	 * PKCS11_CMD_SLOT_LIST - Get the table of the valid slot IDs
	 *
	 * [out] memref[2] = 32bit array slot_ids[slot counts]
	 *
	 * The TA instance may represent several PKCS#11 slots and
	 * associated tokens. This commadn reports the IDs of embedded tokens.
	 * This command relates the PKCS#11 API function C_GetSlotList().
	 */
	PKCS11_CMD_SLOT_LIST = 1,

	/*
	 * PKCS11_CMD_SLOT_INFO - Get cryptoki structured slot information
	 *
	 * [in]	 memref[0] = 32bit slot ID
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = (struct pkcs11_slot_info)info
	 *
	 * The TA instance may represent several PKCS#11 slots/tokens.
	 * This command relates the PKCS#11 API function C_GetSlotInfo().
	 */
	PKCS11_CMD_SLOT_INFO = 2,

	/*
	 * PKCS11_CMD_TOKEN_INFO - Get cryptoki structured token information
	 *
	 * [in]	 memref[0] = 32bit slot ID
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = (struct pkcs11_token_info)info
	 *
	 * The TA instance may represent several PKCS#11 slots/tokens.
	 * This command relates the PKCS#11 API function C_GetTokenInfo().
	 */
	PKCS11_CMD_TOKEN_INFO = 3,

	/*
	 * PKCS11_CMD_MECHANISM_IDS - Get list of the supported mechanisms
	 *
	 * [in]	 memref[0] = 32bit slot ID
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = 32bit array mechanism IDs
	 *
	 * This command relates to the PKCS#11 API function
	 * C_GetMechanismList().
	 */
	PKCS11_CMD_MECHANISM_IDS = 4,

	/*
	 * PKCS11_CMD_MECHANISM_INFO - Get information on a specific mechanism
	 *
	 * [in]  memref[0] = [
	 *              32bit slot ID,
	 *              32bit mechanism ID
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = (struct pkcs11_mechanism_info)info
	 *
	 * This command relates to the PKCS#11 API function
	 * C_GetMechanismInfo().
	 */
	PKCS11_CMD_MECHANISM_INFO = 5,

	/*
	 * PKCS11_CMD_INIT_TOKEN - Initialize PKCS#11 token
	 *
	 * [in]  memref[0] = [
	 *              32bit slot ID,
	 *              32bit PIN length,
	 *              byte array label[32]
	 *              byte array PIN[PIN length],
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_InitToken().
	 */
	PKCS11_CMD_INIT_TOKEN = 6,

	/*
	 * PKCS11_CMD_INIT_PIN - Initialize user PIN
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit PIN byte size,
	 *              byte array: PIN data
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_InitPIN().
	 */
	PKCS11_CMD_INIT_PIN = 7,

	/*
	 * PKCS11_CMD_SET_PIN - Change user PIN
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit old PIN byte size,
	 *              32bit new PIN byte size,
	 *              byte array: PIN data,
	 *              byte array: new PIN data,
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_SetPIN().
	 */
	PKCS11_CMD_SET_PIN = 8,

	/*
	 * PKCS11_CMD_LOGIN - Initialize user PIN
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit user identifier,
	 *              32bit PIN byte size,
	 *              byte array: PIN data
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_Login().
	 */
	PKCS11_CMD_LOGIN = 9,

	/*
	 * PKCS11_CMD_LOGOUT - Log out from token
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_Logout().
	 */
	PKCS11_CMD_LOGOUT = 10,

	/*
	 * PKCS11_CMD_OPEN_RO_SESSION - Open read-only session
	 *
	 * [in]  memref[0] = 32bit slot ID
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = 32bit session handle
	 *
	 * This command relates to the PKCS#11 API function C_OpenSession()
	 * for a read-only session.
	 */
	PKCS11_CMD_OPEN_RO_SESSION = 11,

	/*
	 * PKCS11_CMD_OPEN_RW_SESSION - Open read/write session
	 *
	 * [in]  memref[0] = 32bit slot
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = 32bit session handle
	 *
	 * This command relates to the PKCS#11 API function C_OpenSession()
	 * for a read/write session.
	 */
	PKCS11_CMD_OPEN_RW_SESSION = 12,

	/*
	 * PKCS11_CMD_CLOSE_SESSION - Close an opened session
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_CloseSession().
	 */
	PKCS11_CMD_CLOSE_SESSION = 13,

	/*
	 * PKCS11_CMD_SESSION_INFO - Get Cryptoki information on a session
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = (struct pkcs11_ck_session_info)info
	 *
	 * This command relates to the PKCS#11 API function C_GetSessionInfo().
	 */
	PKCS11_CMD_SESSION_INFO = 14,

	/*
	 * PKCS11_CMD_CLOSE_ALL_SESSIONS - Close all client sessions
	 *
	 * [in]  memref[0] = 32bit slot
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function
	 * C_CloseAllSessions().
	 */
	PKCS11_CMD_CLOSE_ALL_SESSIONS = 15,

	/*
	 * PKCS11_CMD_GET_SESSION_STATE - Retrieve session state
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = byte array containing session state binary blob
	 *
	 * This command relates to the PKCS#11 API function
	 * C_GetOperationState().
	 */
	PKCS11_CMD_GET_SESSION_STATE = 16,

	/*
	 * PKCS11_CMD_SET_SESSION_STATE - Restore session state
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [in]  memref[1] = byte array containing session state binary blob
	 *
	 * This command relates to the PKCS#11 API function
	 * C_SetOperationState().
	 */
	PKCS11_CMD_SET_SESSION_STATE = 17,

	/*
	 * PKCS11_CMD_IMPORT_OBJECT - Import a raw object
	 *
	 * [in]	 memref[0] = [
	 *              32bit session handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = 32bit object handle
	 *
	 * This command relates to the PKCS#11 API function C_CreateObject().
	 */
	PKCS11_CMD_IMPORT_OBJECT = 18,

	/*
	 * PKCS11_CMD_COPY_OBJECT - Duplicate an object
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle,
	 *              (struct pkcs11_object_head)attribs + attributes data,
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = 32bit object handle
	 *
	 * This command relates to the PKCS#11 API function C_CopyObject().
	 */
	PKCS11_CMD_COPY_OBJECT = 19,

	/*
	 * PKCS11_CMD_DESTROY_OBJECT - Destroy an object
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_DestroyObject().
	 */
	PKCS11_CMD_DESTROY_OBJECT = 20,

	/*
	 * PKCS11_CMD_FIND_OBJECTS_INIT - Initialize an object search
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_FindOjectsInit().
	 */
	PKCS11_CMD_FIND_OBJECTS_INIT = 21,

	/*
	 * PKCS11_CMD_FIND_OBJECTS - Get handles of matching objects
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = 32bit array object_handle_array[N]
	 *
	 * This command relates to the PKCS#11 API function C_FindOjects().
	 * The size of object_handle_array depends on the size of the output
	 * buffer provided by the client.
	 */
	PKCS11_CMD_FIND_OBJECTS = 22,

	/*
	 * PKCS11_CMD_FIND_OBJECTS_FINAL - Finalize current objects search
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function C_FindOjectsFinal().
	 */
	PKCS11_CMD_FIND_OBJECTS_FINAL = 23,

	/*
	 * PKCS11_CMD_GET_OBJECT_SIZE - Get byte size used by object in the TEE
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = 32bit object_byte_size
	 *
	 * This command relates to the PKCS#11 API function C_GetObjectSize().
	 */
	PKCS11_CMD_GET_OBJECT_SIZE = 24,

	/*
	 * PKCS11_CMD_GET_ATTRIBUTE_VALUE - Get the value of object attribute(s)
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = (struct pkcs11_object_head)attribs + attribs data
	 *
	 * This command relates to the PKCS#11 API function
	 * C_GetAttributeValue().
	 *
	 * Caller provides an attribute template as 3rd argument in memref[0]
	 * (referred here as attribs + attributes data). Upon successful
	 * completion, the TA returns the provided template filled with
	 * expected data through output argument memref[2] (referred here
	 * again as attribs + attributes data).
	 */
	PKCS11_CMD_GET_ATTRIBUTE_VALUE = 25,

	/*
	 * PKCS11_CMD_SET_ATTRIBUTE_VALUE - Set value for object attribute(s)
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * This command relates to the PKCS#11 API function
	 * C_SetAttributeValue().
	 */
	PKCS11_CMD_SET_ATTRIBUTE_VALUE = 26,

	/*
	 * PKCS11_CMD_GENERATE_KEY - Generate symmetric key or domain parameters
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = 32bit object handle
	 *
	 * This command relates to the PKCS#11 API function C_GenerateKey().
	 */
	PKCS11_CMD_GENERATE_KEY = 27,

	/*
	 * PKCS11_CMD_ENCRYPT_INIT - Initialize enryption processing
	 * PKCS11_CMD_DECRYPT_INIT - Initialize decryption processing
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle of the key,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * These commands relate to the PKCS#11 API functions C_EncryptInit()
	 * and C_DecryptInit().
	 */
	PKCS11_CMD_ENCRYPT_INIT = 28,
	PKCS11_CMD_DECRYPT_INIT = 29,

	/*
	 * PKCS11_CMD_ENCRYPT_UPDATE - Update encryption processing
	 * PKCS11_CMD_DECRYPT_UPDATE - Update decryption processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [in]  memref[1] = input data to be processed
	 * [out] memref[2] = output processed data
	 *
	 * These commands relate to the PKCS#11 API functions C_EncryptUpdate()
	 * and C_DecryptUpdate().
	 */
	PKCS11_CMD_ENCRYPT_UPDATE = 30,
	PKCS11_CMD_DECRYPT_UPDATE = 31,

	/*
	 * PKCS11_CMD_ENCRYPT_FINAL - Finalize encryption processing
	 * PKCS11_CMD_DECRYPT_FINAL - Finalize decryption processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = output processed data
	 *
	 * These commands relate to the PKCS#11 API functions C_EncryptFinal()
	 * and C_DecryptFinal().
	 */
	PKCS11_CMD_ENCRYPT_FINAL = 32,
	PKCS11_CMD_DECRYPT_FINAL = 33,

	/*
	 * PKCS11_CMD_ENCRYPT_ONESHOT - Update and finalize encryption
	 * PKCS11_CMD_DECRYPT_ONESHOT - Update and finalize decryption
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [in]  memref[1] = input data to be processed
	 * [out] memref[2] = output processed data
	 *
	 * These commands relate to the PKCS#11 API functions C_Encrypt()
	 * and C_Decrypt().
	 */
	PKCS11_CMD_ENCRYPT_ONESHOT = 34,
	PKCS11_CMD_DECRYPT_ONESHOT = 35,

	/*
	 * PKCS11_CMD_SIGN_INIT - Initialize a signature computation
	 * PKCS11_CMD_VERIFY_INIT - Initialize a signature verification
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit key handle,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params,
	 *       ]
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * These commands relate to the PKCS#11 API functions C_SignInit()
	 * and C_VerifyInit().
	 */
	PKCS11_CMD_SIGN_INIT = 36,
	PKCS11_CMD_VERIFY_INIT = 37,

	/*
	 * PKCS11_CMD_SIGN_UPDATE - Update a signature computation processing
	 * PKCS11_CMD_VERIFY_UPDATE - Update a signature verification processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [in]  memref[1] = input data to be processed
	 * [out] memref[0] = 32bit fine grain return code
	 *
	 * These commands relate to the PKCS#11 API functions C_SignUpdate()
	 * and C_VerifyUpdate().
	 */
	PKCS11_CMD_SIGN_UPDATE = 38,
	PKCS11_CMD_VERIFY_UPDATE = 39,

	/*
	 * PKCS11_CMD_SIGN_FINAL - Finalize a signature computation
	 * PKCS11_CMD_VERIFY_FINAL - Finalize a signature verification
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [out] memref[2] = output processed data
	 *
	 * These commands relate to the PKCS#11 API functions C_SignFinal()
	 * and C_VerifyFinal().
	 */
	PKCS11_CMD_SIGN_FINAL = 40,
	PKCS11_CMD_VERIFY_FINAL = 41,

	/*
	 * PKCS11_CMD_SIGN_ONESHOT - Update and finalize a signature computation
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [in]  memref[1] = input data to be processed
	 * [out] memref[2] = byte array: generated signature
	 *
	 * This command relates to the PKCS#11 API function C_Sign().
	 */
	PKCS11_CMD_SIGN_ONESHOT = 42,

	/*
	 * PKCS11_CMD_VERIFY_ONESHOT - Update and finalize a signature verify
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit fine grain return code
	 * [in]  memref[1] = input data to be processed
	 * [in]  memref[2] = input signature to be processed
	 *
	 * This command relates to the PKCS#11 API function C_Verify().
	 */
	PKCS11_CMD_VERIFY_ONESHOT = 43,
};

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

/*
 * Arguments for PKCS11_CMD_SLOT_INFO
 */
#define PKCS11_SLOT_DESC_SIZE			64
#define PKCS11_SLOT_MANUFACTURER_SIZE		32
#define PKCS11_SLOT_VERSION_SIZE		2

struct pkcs11_slot_info {
	uint8_t slotDescription[PKCS11_SLOT_DESC_SIZE];
	uint8_t manufacturerID[PKCS11_SLOT_MANUFACTURER_SIZE];
	uint32_t flags;
	uint8_t hardwareVersion[PKCS11_SLOT_VERSION_SIZE];
	uint8_t firmwareVersion[PKCS11_SLOT_VERSION_SIZE];
};

/*
 * Values for pkcs11_slot_info::flags.
 * PKCS11_CKFS_<x> corresponds to cryptoki flag CKF_<x> related to slot flags.
 */
#define PKCS11_CKFS_TOKEN_PRESENT		(1U << 0)
#define PKCS11_CKFS_REMOVABLE_DEVICE		(1U << 1)
#define PKCS11_CKFS_HW_SLOT			(1U << 2)

/*
 * Arguments for PKCS11_CMD_TOKEN_INFO
 */
#define PKCS11_TOKEN_LABEL_SIZE			32
#define PKCS11_TOKEN_MANUFACTURER_SIZE		32
#define PKCS11_TOKEN_MODEL_SIZE			16
#define PKCS11_TOKEN_SERIALNUM_SIZE		16

struct pkcs11_token_info {
	uint8_t label[PKCS11_TOKEN_LABEL_SIZE];
	uint8_t manufacturerID[PKCS11_TOKEN_MANUFACTURER_SIZE];
	uint8_t model[PKCS11_TOKEN_MODEL_SIZE];
	uint8_t serialNumber[PKCS11_TOKEN_SERIALNUM_SIZE];
	uint32_t flags;
	uint32_t ulMaxSessionCount;
	uint32_t ulSessionCount;
	uint32_t ulMaxRwSessionCount;
	uint32_t ulRwSessionCount;
	uint32_t ulMaxPinLen;
	uint32_t ulMinPinLen;
	uint32_t ulTotalPublicMemory;
	uint32_t ulFreePublicMemory;
	uint32_t ulTotalPrivateMemory;
	uint32_t ulFreePrivateMemory;
	uint8_t hardwareVersion[2];
	uint8_t firmwareVersion[2];
	uint8_t utcTime[16];
};

/*
 * Values for pkcs11_token_info::flags.
 * PKCS11_CKFT_<x> corresponds to cryptoki CKF_<x> related to token flags.
 */
#define PKCS11_CKFT_RNG					(1U << 0)
#define PKCS11_CKFT_WRITE_PROTECTED			(1U << 1)
#define PKCS11_CKFT_LOGIN_REQUIRED			(1U << 2)
#define PKCS11_CKFT_USER_PIN_INITIALIZED		(1U << 3)
#define PKCS11_CKFT_RESTORE_KEY_NOT_NEEDED		(1U << 4)
#define PKCS11_CKFT_CLOCK_ON_TOKEN			(1U << 5)
#define PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH	(1U << 6)
#define PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS		(1U << 7)
#define PKCS11_CKFT_TOKEN_INITIALIZED			(1U << 8)
#define PKCS11_CKFT_USER_PIN_COUNT_LOW			(1U << 9)
#define PKCS11_CKFT_USER_PIN_FINAL_TRY			(1U << 10)
#define PKCS11_CKFT_USER_PIN_LOCKED			(1U << 11)
#define PKCS11_CKFT_USER_PIN_TO_BE_CHANGED		(1U << 12)
#define PKCS11_CKFT_SO_PIN_COUNT_LOW			(1U << 13)
#define PKCS11_CKFT_SO_PIN_FINAL_TRY			(1U << 14)
#define PKCS11_CKFT_SO_PIN_LOCKED			(1U << 15)
#define PKCS11_CKFT_SO_PIN_TO_BE_CHANGED		(1U << 16)
#define PKCS11_CKFT_ERROR_STATE				(1U << 17)

/*
 * Arguments for PKCS11_CMD_MECHANISM_INFO
 */

struct pkcs11_mechanism_info {
	uint32_t min_key_size;
	uint32_t max_key_size;
	uint32_t flags;
};

/*
 * Values for pkcs11_mechanism_info::flags.
 * PKCS11_CKFM_<x> strictly matches cryptoki CKF_<x> related to mechanism flags.
 */
#define PKCS11_CKFM_HW				(1U << 0)
#define PKCS11_CKFM_ENCRYPT			(1U << 8)
#define PKCS11_CKFM_DECRYPT			(1U << 9)
#define PKCS11_CKFM_DIGEST			(1U << 10)
#define PKCS11_CKFM_SIGN			(1U << 11)
#define PKCS11_CKFM_SIGN_RECOVER		(1U << 12)
#define PKCS11_CKFM_VERIFY			(1U << 13)
#define PKCS11_CKFM_VERIFY_RECOVER		(1U << 14)
#define PKCS11_CKFM_GENERATE			(1U << 15)
#define PKCS11_CKFM_GENERATE_KEY_PAIR		(1U << 16)
#define PKCS11_CKFM_WRAP			(1U << 17)
#define PKCS11_CKFM_UNWRAP			(1U << 18)
#define PKCS11_CKFM_DERIVE			(1U << 19)
#define PKCS11_CKFM_EC_F_P			(1U << 20)
#define PKCS11_CKFM_EC_F_2M			(1U << 21)
#define PKCS11_CKFM_EC_ECPARAMETERS		(1U << 22)
#define PKCS11_CKFM_EC_NAMEDCURVE		(1U << 23)
#define PKCS11_CKFM_EC_UNCOMPRESS		(1U << 24)
#define PKCS11_CKFM_EC_COMPRESS			(1U << 25)

/*
 * Values for user identifier parameter in PKCS11_CMD_LOGIN
 */
#define PKCS11_CKU_SO			0x0
#define PKCS11_CKU_USER			0x1
#define PKCS11_CKU_CONTEXT_SPECIFIC	0x2

/*
 * Agruments for command PKCS11_CMD_SESSION_INFO
 */
struct pkcs11_session_info {
	uint32_t slot_id;
	uint32_t state;
	uint32_t flags;
	uint32_t error_code;
};

/*
 * Agruments for all commands manipulating object attributes, as
 * PKCS11_CMD_IMPORT_OBJECT.
 */

/*
 * pkcs11_object_head - Header of object whose data are serialized in memory
 *
 * An object is made of several attributes. Attributes are stored one next to
 * the other with byte alignment as a serialized byte arrays. Appended
 * attributes byte arrays are prepend with this header structure that
 * defines the number of attribute items and the overall byte size of byte
 * array field pkcs11_object_head::attrs.
 *
 * @attrs_size - byte size of whole byte array attrs[]
 * @attrs_count - number of attribute items stored in attrs[]
 * @attrs - then starts the attributes data
 */
struct pkcs11_object_head {
	uint32_t attrs_size;
	uint32_t attrs_count;
	uint8_t attrs[];
};

/*
 * Attribute reference in the TA ABI. Each attribute starts with a header
 * structure followed by the attribute value. The attribute byte size is
 * defined in the attribute header.
 *
 * @id - the 32bit identificator of the attribute, see PKCS11_CKA_<x>
 * @size - the 32bit value attribute byte size
 * @data - then starts the attribute value
 */
struct pkcs11_attribute_head {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

/*
 * Attribute identification IDs
 * Valid values for struct pkcs11_attribute_head::id
 *
 * PKCS11_CKA_<x> relates to cryptoki CKA_<x>.
 * Value range [0 63] is reserved to boolean value attributes.
 */
#define PKCS11_BOOLPROPH_FLAG		(1U << 31)
#define PKCS11_BOOLPROPS_BASE		0
#define PKCS11_BOOLPROPS_MAX		63

enum pkcs11_attr_id {
	PKCS11_CKA_TOKEN				= 0x00000000,
	PKCS11_CKA_PRIVATE				= 0x00000001,
	PKCS11_CKA_TRUSTED				= 0x00000002,
	PKCS11_CKA_SENSITIVE				= 0x00000003,
	PKCS11_CKA_ENCRYPT				= 0x00000004,
	PKCS11_CKA_DECRYPT				= 0x00000005,
	PKCS11_CKA_WRAP					= 0x00000006,
	PKCS11_CKA_UNWRAP				= 0x00000007,
	PKCS11_CKA_SIGN					= 0x00000008,
	PKCS11_CKA_SIGN_RECOVER				= 0x00000009,
	PKCS11_CKA_VERIFY				= 0x0000000a,
	PKCS11_CKA_VERIFY_RECOVER			= 0x0000000b,
	PKCS11_CKA_DERIVE				= 0x0000000c,
	PKCS11_CKA_EXTRACTABLE				= 0x0000000d,
	PKCS11_CKA_LOCAL				= 0x0000000e,
	PKCS11_CKA_NEVER_EXTRACTABLE			= 0x0000000f,
	PKCS11_CKA_ALWAYS_SENSITIVE			= 0x00000010,
	PKCS11_CKA_MODIFIABLE				= 0x00000011,
	PKCS11_CKA_COPYABLE				= 0x00000012,
	PKCS11_CKA_DESTROYABLE				= 0x00000013,
	PKCS11_CKA_ALWAYS_AUTHENTICATE			= 0x00000014,
	PKCS11_CKA_WRAP_WITH_TRUSTED			= 0x00000015,
	PKCS11_BOOLPROPS_LAST = PKCS11_CKA_WRAP_WITH_TRUSTED,
	PKCS11_BOOLPROPS_END = PKCS11_BOOLPROPS_MAX,
	PKCS11_CKA_LABEL				= 0x00000040,
	PKCS11_CKA_VALUE				= 0x00000041,
	PKCS11_CKA_VALUE_LEN				= 0x00000042,
	PKCS11_CKA_WRAP_TEMPLATE			= 0x00000043,
	PKCS11_CKA_UNWRAP_TEMPLATE			= 0x00000044,
	PKCS11_CKA_DERIVE_TEMPLATE			= 0x00000045,
	PKCS11_CKA_START_DATE				= 0x00000046,
	PKCS11_CKA_END_DATE				= 0x00000047,
	PKCS11_CKA_OBJECT_ID				= 0x00000048,
	PKCS11_CKA_APPLICATION				= 0x00000049,
	PKCS11_CKA_MECHANISM_TYPE			= 0x0000004a,
	PKCS11_CKA_ID					= 0x0000004b,
	PKCS11_CKA_ALLOWED_MECHANISMS			= 0x0000004c,
	PKCS11_CKA_CLASS				= 0x0000004d,
	PKCS11_CKA_KEY_TYPE				= 0x0000004e,
	PKCS11_CKA_EC_POINT				= 0x0000004f,
	PKCS11_CKA_EC_PARAMS				= 0x00000050,
	PKCS11_CKA_MODULUS				= 0x00000051,
	PKCS11_CKA_MODULUS_BITS				= 0x00000052,
	PKCS11_CKA_PUBLIC_EXPONENT			= 0x00000053,
	PKCS11_CKA_PRIVATE_EXPONENT			= 0x00000054,
	PKCS11_CKA_PRIME_1				= 0x00000055,
	PKCS11_CKA_PRIME_2				= 0x00000056,
	PKCS11_CKA_EXPONENT_1				= 0x00000057,
	PKCS11_CKA_EXPONENT_2				= 0x00000058,
	PKCS11_CKA_COEFFICIENT				= 0x00000059,
	PKCS11_CKA_SUBJECT				= 0x0000005a,
	PKCS11_CKA_PUBLIC_KEY_INFO			= 0x0000005b,
	PKCS11_CKA_UNDEFINED_ID				= PKCS11_UNDEFINED_ID,
};

#endif /*PKCS11_TA_H*/
