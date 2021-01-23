/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_TA_H
#define PKCS11_TA_H

#include <stdbool.h>
#include <stdint.h>

#define PKCS11_TA_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
			 { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

/* PKCS11 trusted application version information */
#define PKCS11_TA_VERSION_MAJOR			0
#define PKCS11_TA_VERSION_MINOR			1
#define PKCS11_TA_VERSION_PATCH			0

/* Attribute specific values */
#define PKCS11_CK_UNAVAILABLE_INFORMATION	UINT32_C(0xFFFFFFFF)
#define PKCS11_UNDEFINED_ID			UINT32_C(0xFFFFFFFF)
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
 * stores serialized arguments for the command. The output buffer store the
 * 32bit TA return code for the command. As a consequence, param#0 shall
 * always be an input/output memory reference of at least 32bit, more if
 * the command expects more input arguments.
 *
 * When the TA returns with TEE_SUCCESS result, client shall always get the
 * 32bit value stored in param#0 output buffer and use the value as TA
 * return code for the invoked command.
 *
 * Param#1 can be used for input data arguments of the invoked command.
 * It is unused or is an input memory reference, aka memref[1].
 * Evolution of the API may use memref[1] for output data as well.
 *
 * Param#2 is mostly used for output data arguments of the invoked command
 * and for output handles generated from invoked commands.
 * Few commands uses it for a secondary input data buffer argument.
 * It is unused or is an input/output/in-out memory reference, aka memref[2].
 *
 * Param#3 is currently unused and reserved for evolution of the API.
 */

enum pkcs11_ta_cmd {
	/*
	 * PKCS11_CMD_PING		Ack TA presence and return version info
	 *
	 * [in]  memref[0] = 32bit, unused, must be 0
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
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
	 * [in]  memref[0] = 32bit, unused, must be 0
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
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
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
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
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
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
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
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
	 *              32bit mechanism ID (PKCS11_CKM_*)
	 *       ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_mechanism_info)info
	 *
	 * This command relates to the PKCS#11 API function
	 * C_GetMechanismInfo().
	 */
	PKCS11_CMD_MECHANISM_INFO = 5,

	/*
	 * PKCS11_CMD_OPEN_SESSION - Open a session
	 *
	 * [in]  memref[0] = [
	 *              32bit slot ID,
	 *              32bit session flags,
	 *       ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit session handle
	 *
	 * This command relates to the PKCS#11 API function C_OpenSession().
	 */
	PKCS11_CMD_OPEN_SESSION = 6,

	/*
	 * PKCS11_CMD_CLOSE_SESSION - Close an opened session
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_CloseSession().
	 */
	PKCS11_CMD_CLOSE_SESSION = 7,

	/*
	 * PKCS11_CMD_CLOSE_ALL_SESSIONS - Close all client sessions on token
	 *
	 * [in]	 memref[0] = 32bit slot ID
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function
	 * C_CloseAllSessions().
	 */
	PKCS11_CMD_CLOSE_ALL_SESSIONS = 8,

	/*
	 * PKCS11_CMD_SESSION_INFO - Get Cryptoki information on a session
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_session_info)info
	 *
	 * This command relates to the PKCS#11 API function C_GetSessionInfo().
	 */
	PKCS11_CMD_SESSION_INFO = 9,

	/*
	 * PKCS11_CMD_INIT_TOKEN - Initialize PKCS#11 token
	 *
	 * [in]  memref[0] = [
	 *              32bit slot ID,
	 *              32bit PIN length,
	 *              byte array label[32]
	 *              byte array PIN[PIN length],
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_InitToken().
	 */
	PKCS11_CMD_INIT_TOKEN = 10,

	/*
	 * PKCS11_CMD_INIT_PIN - Initialize user PIN
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit PIN byte size,
	 *              byte array: PIN data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_InitPIN().
	 */
	PKCS11_CMD_INIT_PIN = 11,

	/*
	 * PKCS11_CMD_SET_PIN - Change user PIN
	 *
	 * [in]	 memref[0] = [
	 *              32bit session handle,
	 *              32bit old PIN byte size,
	 *              32bit new PIN byte size,
	 *              byte array: PIN data,
	 *              byte array: new PIN data,
	 *       ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_SetPIN().
	 */
	PKCS11_CMD_SET_PIN = 12,

	/*
	 * PKCS11_CMD_LOGIN - Initialize user PIN
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit user identifier, enum pkcs11_user_type
	 *              32bit PIN byte size,
	 *              byte array: PIN data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_Login().
	 */
	PKCS11_CMD_LOGIN = 13,

	/*
	 * PKCS11_CMD_LOGOUT - Log out from token
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_Logout().
	 */
	PKCS11_CMD_LOGOUT = 14,

	/*
	 * PKCS11_CMD_CREATE_OBJECT - Create a raw client assembled object in
	 *			      the session or token
	 *
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit object handle
	 *
	 * This command relates to the PKCS#11 API function C_CreateObject().
	 */
	PKCS11_CMD_CREATE_OBJECT = 15,

	/*
	 * PKCS11_CMD_DESTROY_OBJECT - Destroy an object
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_DestroyObject().
	 */
	PKCS11_CMD_DESTROY_OBJECT = 16,

	/*
	 * PKCS11_CMD_ENCRYPT_INIT - Initialize encryption processing
	 * PKCS11_CMD_DECRYPT_INIT - Initialize decryption processing
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle of the key,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * These commands relate to the PKCS#11 API functions
	 * C_EncryptInit() and C_DecryptInit().
	 */
	PKCS11_CMD_ENCRYPT_INIT = 17,
	PKCS11_CMD_DECRYPT_INIT = 18,

	/*
	 * PKCS11_CMD_ENCRYPT_UPDATE - Update encryption processing
	 * PKCS11_CMD_DECRYPT_UPDATE - Update decryption processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = input data to be processed
	 * [out] memref[2] = output processed data
	 *
	 * These commands relate to the PKCS#11 API functions
	 * C_EncryptUpdate() and C_DecryptUpdate().
	 */
	PKCS11_CMD_ENCRYPT_UPDATE = 19,
	PKCS11_CMD_DECRYPT_UPDATE = 20,

	/*
	 * PKCS11_CMD_ENCRYPT_FINAL - Finalize encryption processing
	 * PKCS11_CMD_DECRYPT_FINAL - Finalize decryption processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = output processed data
	 *
	 * These commands relate to the PKCS#11 API functions
	 * C_EncryptFinal() and C_DecryptFinal().
	 */
	PKCS11_CMD_ENCRYPT_FINAL = 21,
	PKCS11_CMD_DECRYPT_FINAL = 22,

	/*
	 * PKCS11_CMD_ENCRYPT_ONESHOT - Update and finalize encryption
	 *                              processing
	 * PKCS11_CMD_DECRYPT_ONESHOT - Update and finalize decryption
	 *                              processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = input data to be processed
	 * [out] memref[2] = output processed data
	 *
	 * These commands relate to the PKCS#11 API functions C_Encrypt and
	 * C_Decrypt.
	 */
	PKCS11_CMD_ENCRYPT_ONESHOT = 23,
	PKCS11_CMD_DECRYPT_ONESHOT = 24,

	/*
	 * PKCS11_CMD_SIGN_INIT   - Initialize a signature computation
	 *                          processing
	 * PKCS11_CMD_VERIFY_INIT - Initialize a signature verification
	 *                          processing
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit key handle,
	 *              (struct pkcs11_attribute_head)mechanism +
	 *                                            mechanism params,
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * These commands relate to the PKCS#11 API functions C_SignInit() and
	 * C_VerifyInit().
	 */
	PKCS11_CMD_SIGN_INIT = 25,
	PKCS11_CMD_VERIFY_INIT = 26,

	/*
	 * PKCS11_CMD_SIGN_UPDATE   - Update a signature computation processing
	 * PKCS11_CMD_VERIFY_UPDATE - Update a signature verification processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = input data to be processed
	 *
	 * These commands relate to the PKCS#11 API functions C_SignUpdate() and
	 * C_VerifyUpdate().
	 */
	PKCS11_CMD_SIGN_UPDATE = 27,
	PKCS11_CMD_VERIFY_UPDATE = 28,

	/*
	 * PKCS11_CMD_SIGN_FINAL - Finalize a signature computation processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = output signature
	 *
	 * This command relates to the PKCS#11 API functions C_SignFinal().
	 */
	PKCS11_CMD_SIGN_FINAL = 29,

	/*
	 * PKCS11_CMD_VERIFY_FINAL - Finalize a signature verification
	 *                           processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[2] = input signature to be processed
	 *
	 * This command relates to the PKCS#11 API functions C_VerifyFinal().
	 */
	PKCS11_CMD_VERIFY_FINAL = 30,

	/*
	 * PKCS11_CMD_SIGN_ONESHOT - Compute a signature
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = input data to be processed
	 * [out] memref[2] = byte array: generated signature
	 *
	 * This command relates to the PKCS#11 API function C_Sign().
	 */
	PKCS11_CMD_SIGN_ONESHOT = 31,

	/*
	 * PKCS11_CMD_VERIFY_ONESHOT - Compute and compare a signature
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = input data to be processed
	 * [in]  memref[2] = input signature to be processed
	 *
	 * This command relates to the PKCS#11 API function C_Verify().
	 */
	PKCS11_CMD_VERIFY_ONESHOT = 32,

	/*
	 * PKCS11_CMD_GENERATE_KEY - Generate a symmetric key or domain
	 *                           parameters
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit object handle
	 *
	 * This command relates to the PKCS#11 API function C_GenerateKey().
	 */
	PKCS11_CMD_GENERATE_KEY = 33,

	/*
	 * PKCS11_CMD_FIND_OBJECTS_INIT - Initialize an object search
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_FindOjectsInit().
	 */
	PKCS11_CMD_FIND_OBJECTS_INIT = 34,

	/*
	 * PKCS11_CMD_FIND_OBJECTS - Get handles of matching objects
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit array object_handle_array[N]
	 *
	 * This command relates to the PKCS#11 API function C_FindOjects().
	 * The size of object_handle_array depends on the size of the output
	 * buffer provided by the client.
	 */
	PKCS11_CMD_FIND_OBJECTS = 35,

	/*
	 * PKCS11_CMD_FIND_OBJECTS_FINAL - Finalize current objects search
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_FindOjectsFinal().
	 */
	PKCS11_CMD_FIND_OBJECTS_FINAL = 36,

	/*
	 * PKCS11_CMD_GET_OBJECT_SIZE - Get byte size used by object in the TEE
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit object_byte_size
	 *
	 * This command relates to the PKCS#11 API function C_GetObjectSize().
	 */
	PKCS11_CMD_GET_OBJECT_SIZE = 37,

	/*
	 * PKCS11_CMD_GET_ATTRIBUTE_VALUE - Get the value of object attribute(s)
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_object_head)attribs + attributes
	 *                   data
	 *
	 * This command relates to the PKCS#11 API function C_GetAttributeValue.
	 * Caller provides an attribute template as 3rd argument in memref[0]
	 * (referred here as attribs + attributes data). Upon successful
	 * completion, the TA returns the provided template filled with expected
	 * data through output argument memref[2] (referred here again as
	 * attribs + attributes data).
	 */
	PKCS11_CMD_GET_ATTRIBUTE_VALUE = 38,

	/*
	 * PKCS11_CMD_SET_ATTRIBUTE_VALUE - Set the value of object attribute(s)
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_SetAttributeValue.
	 * Caller provides an attribute template as 3rd argument in memref[0]
	 * (referred here as attribs + attributes data).
	 */
	PKCS11_CMD_SET_ATTRIBUTE_VALUE = 39,

	/*
	 * PKCS11_CMD_COPY_OBJECT - Copies an object, creating a new object for
	 *			    the copy.
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit object handle,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit object handle
	 *
	 * This command relates to the PKCS#11 API function C_CopyObject().
	 * Caller provides an attribute template as 3rd argument in memref[0]
	 * (referred here as attribs + attributes data).
	 */
	PKCS11_CMD_COPY_OBJECT = 40,

	/*
	 * PKCS11_CMD_SEED_RANDOM - Seed random data generator
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = byte array: seed material to feed into the RNG
	 *
	 * This command relates to the PKCS#11 API function C_SeedRandom().
	 */
	PKCS11_CMD_SEED_RANDOM = 41,

	/*
	 * PKCS11_CMD_GENERATE_RANDOM - Generate random data
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = byte array: generated random
	 *
	 * This command relates to the PKCS#11 API function C_GenerateRandom().
	 */
	PKCS11_CMD_GENERATE_RANDOM = 42,

	/*
	 * PKCS11_CMD_DERIVE_KEY - Derive a key from a parent key.
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit parent key handle,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit object handle
	 *
	 * This command relates to the PKCS#11 API function C_DeriveKey().
	 */
	PKCS11_CMD_DERIVE_KEY = 43,

	/*
	 * PKCS11_CMD_RELEASE_ACTIVE_PROCESSING - Release active processing
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit enum pkcs11_ta_cmd
	 *       ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command is used to release active processing in case of
	 * Cryptoki API invocation error is detected in user space processing.
	 * Function derived from pkcs11_ta_cmd is used to verify that active
	 * processing matches.
	 */
	PKCS11_CMD_RELEASE_ACTIVE_PROCESSING = 44,

	/*
	 * PKCS11_CMD_DIGEST_INIT - Initialize a digest computation processing
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_DigestInit().
	 */
	PKCS11_CMD_DIGEST_INIT = 45,

	/*
	 * PKCS11_CMD_DIGEST_KEY - Update digest with a key
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit key handle
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 *
	 * This command relates to the PKCS#11 API function C_DigestKey().
	 */
	PKCS11_CMD_DIGEST_KEY = 46,

	/*
	 * PKCS11_CMD_DIGEST_UPDATE - Update digest with data
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = input data to be processed
	 *
	 * This command relates to the PKCS#11 API function C_DigestUpdate().
	 */
	PKCS11_CMD_DIGEST_UPDATE = 47,

	/*
	 * PKCS11_CMD_DIGEST_FINAL - Finalize a digest computation processing
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = output digest
	 *
	 * This command relates to the PKCS#11 API function C_DigestFinal().
	 */
	PKCS11_CMD_DIGEST_FINAL = 48,

	/*
	 * PKCS11_CMD_DIGEST_ONESHOT - Compute a digest
	 *
	 * [in]  memref[0] = 32bit session handle
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = input data to be processed
	 * [out] memref[2] = byte array: generated digest
	 *
	 * This command relates to the PKCS#11 API function C_Digest().
	 */
	PKCS11_CMD_DIGEST_ONESHOT = 49,

	/*
	 * PKCS11_CMD_GENERATE_KEY_PAIR - Generate an asymmetric key pair
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params,
	 *              (struct pkcs11_object_head)public key attribs +
	 *              attributes data,
	 *              (struct pkcs11_object_head)private key attribs +
	 *              attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = [
	 *              32bit public key object handle,
	 *              32bit private key object handle
	 *	 ]
	 *
	 * This command relates to the PKCS#11 API function
	 * C_GenerateKeyPair().
	 */
	PKCS11_CMD_GENERATE_KEY_PAIR = 50,

	/*
	 * PKCS11_CMD_WRAP_KEY - Wraps a private or secret key.
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit wrapping key handle,
	 *              32bit key handle,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = wrapped key
	 *
	 * This command relates to the PKCS#11 API function C_WrapKey().
	 */
	PKCS11_CMD_WRAP_KEY = 51,

	/*
	 * PKCS11_CMD_UNWRAP_KEY - Unwraps a wrapped key, creating a new
	 *                         private or secret key object.
	 *
	 * [in]  memref[0] = [
	 *              32bit session handle,
	 *              32bit unwrapping key handle,
	 *              (struct pkcs11_attribute_head)mechanism + mecha params,
	 *              (struct pkcs11_object_head)attribs + attributes data
	 *	 ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [in]  memref[1] = wrapped key
	 * [out] memref[2] = 32bit object handle
	 *
	 * This command relates to the PKCS#11 API function C_UnwrapKey().
	 */
	PKCS11_CMD_UNWRAP_KEY = 52,
};

/*
 * Command return codes
 * PKCS11_<x> relates CryptoKi client API CKR_<x>
 */
enum pkcs11_rc {
	PKCS11_CKR_OK				= 0,
	PKCS11_CKR_CANCEL			= 0x0001,
	PKCS11_CKR_SLOT_ID_INVALID		= 0x0003,
	PKCS11_CKR_GENERAL_ERROR		= 0x0005,
	PKCS11_CKR_FUNCTION_FAILED		= 0x0006,
	PKCS11_CKR_ARGUMENTS_BAD		= 0x0007,
	PKCS11_CKR_ATTRIBUTE_READ_ONLY		= 0x0010,
	PKCS11_CKR_ATTRIBUTE_SENSITIVE		= 0x0011,
	PKCS11_CKR_ATTRIBUTE_TYPE_INVALID	= 0x0012,
	PKCS11_CKR_ATTRIBUTE_VALUE_INVALID	= 0x0013,
	PKCS11_CKR_ACTION_PROHIBITED		= 0x001b,
	PKCS11_CKR_DATA_INVALID			= 0x0020,
	PKCS11_CKR_DATA_LEN_RANGE		= 0x0021,
	PKCS11_CKR_DEVICE_ERROR			= 0x0030,
	PKCS11_CKR_DEVICE_MEMORY		= 0x0031,
	PKCS11_CKR_DEVICE_REMOVED		= 0x0032,
	PKCS11_CKR_ENCRYPTED_DATA_INVALID	= 0x0040,
	PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE	= 0x0041,
	PKCS11_CKR_KEY_HANDLE_INVALID		= 0x0060,
	PKCS11_CKR_KEY_SIZE_RANGE		= 0x0062,
	PKCS11_CKR_KEY_TYPE_INCONSISTENT	= 0x0063,
	PKCS11_CKR_KEY_INDIGESTIBLE		= 0x0067,
	PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED	= 0x0068,
	PKCS11_CKR_KEY_NOT_WRAPPABLE		= 0x0069,
	PKCS11_CKR_KEY_UNEXTRACTABLE		= 0x006a,
	PKCS11_CKR_MECHANISM_INVALID		= 0x0070,
	PKCS11_CKR_MECHANISM_PARAM_INVALID	= 0x0071,
	PKCS11_CKR_OBJECT_HANDLE_INVALID	= 0x0082,
	PKCS11_CKR_OPERATION_ACTIVE		= 0x0090,
	PKCS11_CKR_OPERATION_NOT_INITIALIZED	= 0x0091,
	PKCS11_CKR_PIN_INCORRECT		= 0x00a0,
	PKCS11_CKR_PIN_INVALID			= 0x00a1,
	PKCS11_CKR_PIN_LEN_RANGE		= 0x00a2,
	PKCS11_CKR_PIN_EXPIRED			= 0x00a3,
	PKCS11_CKR_PIN_LOCKED			= 0x00a4,
	PKCS11_CKR_SESSION_CLOSED		= 0x00b0,
	PKCS11_CKR_SESSION_COUNT		= 0x00b1,
	PKCS11_CKR_SESSION_HANDLE_INVALID	= 0x00b3,
	PKCS11_CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x00b4,
	PKCS11_CKR_SESSION_READ_ONLY		= 0x00b5,
	PKCS11_CKR_SESSION_EXISTS		= 0x00b6,
	PKCS11_CKR_SESSION_READ_ONLY_EXISTS	= 0x00b7,
	PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS	= 0x00b8,
	PKCS11_CKR_SIGNATURE_INVALID		= 0x00c0,
	PKCS11_CKR_SIGNATURE_LEN_RANGE		= 0x00c1,
	PKCS11_CKR_TEMPLATE_INCOMPLETE		= 0x00d0,
	PKCS11_CKR_TEMPLATE_INCONSISTENT	= 0x00d1,
	PKCS11_CKR_TOKEN_NOT_PRESENT		= 0x00e0,
	PKCS11_CKR_TOKEN_NOT_RECOGNIZED		= 0x00e1,
	PKCS11_CKR_TOKEN_WRITE_PROTECTED	= 0x00e2,
	PKCS11_CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x00f0,
	PKCS11_CKR_UNWRAPPING_KEY_SIZE_RANGE	= 0x00f1,
	PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x00f2,
	PKCS11_CKR_USER_ALREADY_LOGGED_IN	= 0x0100,
	PKCS11_CKR_USER_NOT_LOGGED_IN		= 0x0101,
	PKCS11_CKR_USER_PIN_NOT_INITIALIZED	= 0x0102,
	PKCS11_CKR_USER_TYPE_INVALID		= 0x0103,
	PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x0104,
	PKCS11_CKR_USER_TOO_MANY_TYPES		= 0x0105,
	PKCS11_CKR_WRAPPED_KEY_INVALID		= 0x0110,
	PKCS11_CKR_WRAPPED_KEY_LEN_RANGE	= 0x0112,
	PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID  = 0x0113,
	PKCS11_CKR_WRAPPING_KEY_SIZE_RANGE	= 0x0114,
	PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x0115,
	PKCS11_CKR_RANDOM_SEED_NOT_SUPPORTED	= 0x0120,
	PKCS11_CKR_RANDOM_NO_RNG		= 0x0121,
	PKCS11_CKR_DOMAIN_PARAMS_INVALID	= 0x0130,
	PKCS11_CKR_CURVE_NOT_SUPPORTED		= 0x0140,
	PKCS11_CKR_BUFFER_TOO_SMALL		= 0x0150,
	PKCS11_CKR_SAVED_STATE_INVALID		= 0x0160,
	PKCS11_CKR_INFORMATION_SENSITIVE	= 0x0170,
	PKCS11_CKR_STATE_UNSAVEABLE		= 0x0180,
	PKCS11_CKR_PIN_TOO_WEAK			= 0x01b8,
	PKCS11_CKR_PUBLIC_KEY_INVALID		= 0x01b9,
	PKCS11_CKR_FUNCTION_REJECTED		= 0x0200,
	/* Vendor specific IDs not returned to client */
	PKCS11_RV_NOT_FOUND			= 0x80000000,
	PKCS11_RV_NOT_IMPLEMENTED		= 0x80000001,
};

/*
 * Arguments for PKCS11_CMD_SLOT_INFO
 */
#define PKCS11_SLOT_DESC_SIZE			64
#define PKCS11_SLOT_MANUFACTURER_SIZE		32
#define PKCS11_SLOT_VERSION_SIZE		2

struct pkcs11_slot_info {
	uint8_t slot_description[PKCS11_SLOT_DESC_SIZE];
	uint8_t manufacturer_id[PKCS11_SLOT_MANUFACTURER_SIZE];
	uint32_t flags;
	uint8_t hardware_version[PKCS11_SLOT_VERSION_SIZE];
	uint8_t firmware_version[PKCS11_SLOT_VERSION_SIZE];
};

/*
 * Values for pkcs11_slot_info::flags.
 * PKCS11_CKFS_<x> reflects CryptoKi client API slot flags CKF_<x>.
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
	uint8_t manufacturer_id[PKCS11_TOKEN_MANUFACTURER_SIZE];
	uint8_t model[PKCS11_TOKEN_MODEL_SIZE];
	uint8_t serial_number[PKCS11_TOKEN_SERIALNUM_SIZE];
	uint32_t flags;
	uint32_t max_session_count;
	uint32_t session_count;
	uint32_t max_rw_session_count;
	uint32_t rw_session_count;
	uint32_t max_pin_len;
	uint32_t min_pin_len;
	uint32_t total_public_memory;
	uint32_t free_public_memory;
	uint32_t total_private_memory;
	uint32_t free_private_memory;
	uint8_t hardware_version[2];
	uint8_t firmware_version[2];
	uint8_t utc_time[16];
};

/*
 * Values for pkcs11_token_info::flags.
 * PKCS11_CKFT_<x> reflects CryptoKi client API token flags CKF_<x>.
 */
#define PKCS11_CKFT_RNG					(1U << 0)
#define PKCS11_CKFT_WRITE_PROTECTED			(1U << 1)
#define PKCS11_CKFT_LOGIN_REQUIRED			(1U << 2)
#define PKCS11_CKFT_USER_PIN_INITIALIZED		(1U << 3)
#define PKCS11_CKFT_RESTORE_KEY_NOT_NEEDED		(1U << 5)
#define PKCS11_CKFT_CLOCK_ON_TOKEN			(1U << 6)
#define PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH	(1U << 8)
#define PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS		(1U << 9)
#define PKCS11_CKFT_TOKEN_INITIALIZED			(1U << 10)
#define PKCS11_CKFT_SECONDARY_AUTHENTICATION		(1U << 11)
#define PKCS11_CKFT_USER_PIN_COUNT_LOW			(1U << 16)
#define PKCS11_CKFT_USER_PIN_FINAL_TRY			(1U << 17)
#define PKCS11_CKFT_USER_PIN_LOCKED			(1U << 18)
#define PKCS11_CKFT_USER_PIN_TO_BE_CHANGED		(1U << 19)
#define PKCS11_CKFT_SO_PIN_COUNT_LOW			(1U << 20)
#define PKCS11_CKFT_SO_PIN_FINAL_TRY			(1U << 21)
#define PKCS11_CKFT_SO_PIN_LOCKED			(1U << 22)
#define PKCS11_CKFT_SO_PIN_TO_BE_CHANGED		(1U << 23)
#define PKCS11_CKFT_ERROR_STATE				(1U << 24)

/* Values for user identity */
enum pkcs11_user_type {
	PKCS11_CKU_SO = 0x000,
	PKCS11_CKU_USER = 0x001,
	PKCS11_CKU_CONTEXT_SPECIFIC = 0x002,
};

/*
 * TEE Identity based authentication for tokens
 *
 * When configuration CFG_PKCS11_TA_AUTH_TEE_IDENTITY is enabled TEE Identity
 * based authentication scheme is enabled.
 *
 * Feature enablement per token basis is controlled by token flag:
 * pkcs11_token_info->flags & PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH
 *
 * When calling C_InitToken() mode is determined based on SO PIN value.
 * - If the PIN is empty (or NULL_PTR) then active client TEE Identity will be
 *   used as SO TEE Identity
 * - If the PIN is given then normal PIN behavior is used
 *
 * Once TEE Identity based authentication is activated following operational
 * changes happen:
 * - PIN failure counters are disabled to prevent token authentication lockups
 * - Switching to different authentication mode needs C_InitToken()
 * - When C_Login() or so is performed actual PIN value is ignored and active
 *   client TEE Identity will be used
 *
 * Different types of TEE Identity authentication methods can be configured:
 * - Configured with C_InitToken(), C_InitPIN() or by C_SetPIN()
 * - PIN value follows below PIN syntax
 *
 * TEE Identity based authenticate PIN syntax:
 * - PIN value: NULL_PTR or empty
 *   - Use active client TEE Identity
 * - PIN value: public
 *   - TEE public login
 * - PIN value: user:<client UUID string>
 *   - TEE user login with client UUID matching user credentials
 * - PIN value: group:<client UUID string>
 *   - TEE group login with client UUID matching group credentials
 */

/* Keywords for protected authenticated path PIN parser */
#define PKCS11_AUTH_TEE_IDENTITY_PUBLIC	"public"
#define PKCS11_AUTH_TEE_IDENTITY_USER	"user:"
#define PKCS11_AUTH_TEE_IDENTITY_GROUP	"group:"

/*
 * Values for 32bit session flags argument to PKCS11_CMD_OPEN_SESSION
 * and pkcs11_session_info::flags.
 * PKCS11_CKFSS_<x> reflects CryptoKi client API session flags CKF_<x>.
 */
#define PKCS11_CKFSS_RW_SESSION				(1U << 1)
#define PKCS11_CKFSS_SERIAL_SESSION			(1U << 2)

/*
 * Arguments for PKCS11_CMD_SESSION_INFO
 */

struct pkcs11_session_info {
	uint32_t slot_id;
	uint32_t state;
	uint32_t flags;
	uint32_t device_error;
};

/* Valid values for pkcs11_session_info::state */
enum pkcs11_session_state {
	PKCS11_CKS_RO_PUBLIC_SESSION = 0,
	PKCS11_CKS_RO_USER_FUNCTIONS = 1,
	PKCS11_CKS_RW_PUBLIC_SESSION = 2,
	PKCS11_CKS_RW_USER_FUNCTIONS = 3,
	PKCS11_CKS_RW_SO_FUNCTIONS = 4,
};

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
 * PKCS11_CKFM_<x> reflects CryptoKi client API mechanism flags CKF_<x>.
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
 * pkcs11_object_head - Header of object whose data are serialized in memory
 *
 * An object is made of several attributes. Attributes are stored one next to
 * the other with byte alignment as a serialized byte array. The byte array
 * of serialized attributes is prepended with the size of the attrs[] array
 * in bytes and the number of attributes in the array, yielding the struct
 * pkcs11_object_head.
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
 * @id - the 32bit identifier of the attribute, see PKCS11_CKA_<x>
 * @size - the 32bit value attribute byte size
 * @data - then starts the attribute value
 */
struct pkcs11_attribute_head {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

/*
 * Attribute identification IDs as of v2.40 excluding deprecated IDs.
 * Valid values for struct pkcs11_attribute_head::id
 * PKCS11_CKA_<x> reflects CryptoKi client API attribute IDs CKA_<x>.
 */
enum pkcs11_attr_id {
	PKCS11_CKA_CLASS			= 0x0000,
	PKCS11_CKA_TOKEN			= 0x0001,
	PKCS11_CKA_PRIVATE			= 0x0002,
	PKCS11_CKA_LABEL			= 0x0003,
	PKCS11_CKA_APPLICATION			= 0x0010,
	PKCS11_CKA_VALUE			= 0x0011,
	PKCS11_CKA_OBJECT_ID			= 0x0012,
	PKCS11_CKA_CERTIFICATE_TYPE		= 0x0080,
	PKCS11_CKA_ISSUER			= 0x0081,
	PKCS11_CKA_SERIAL_NUMBER		= 0x0082,
	PKCS11_CKA_AC_ISSUER			= 0x0083,
	PKCS11_CKA_OWNER			= 0x0084,
	PKCS11_CKA_ATTR_TYPES			= 0x0085,
	PKCS11_CKA_TRUSTED			= 0x0086,
	PKCS11_CKA_CERTIFICATE_CATEGORY		= 0x0087,
	PKCS11_CKA_JAVA_MIDP_SECURITY_DOMAIN	= 0x0088,
	PKCS11_CKA_URL				= 0x0089,
	PKCS11_CKA_HASH_OF_SUBJECT_PUBLIC_KEY	= 0x008a,
	PKCS11_CKA_HASH_OF_ISSUER_PUBLIC_KEY	= 0x008b,
	PKCS11_CKA_NAME_HASH_ALGORITHM		= 0x008c,
	PKCS11_CKA_CHECK_VALUE			= 0x0090,
	PKCS11_CKA_KEY_TYPE			= 0x0100,
	PKCS11_CKA_SUBJECT			= 0x0101,
	PKCS11_CKA_ID				= 0x0102,
	PKCS11_CKA_SENSITIVE			= 0x0103,
	PKCS11_CKA_ENCRYPT			= 0x0104,
	PKCS11_CKA_DECRYPT			= 0x0105,
	PKCS11_CKA_WRAP				= 0x0106,
	PKCS11_CKA_UNWRAP			= 0x0107,
	PKCS11_CKA_SIGN				= 0x0108,
	PKCS11_CKA_SIGN_RECOVER			= 0x0109,
	PKCS11_CKA_VERIFY			= 0x010a,
	PKCS11_CKA_VERIFY_RECOVER		= 0x010b,
	PKCS11_CKA_DERIVE			= 0x010c,
	PKCS11_CKA_START_DATE			= 0x0110,
	PKCS11_CKA_END_DATE			= 0x0111,
	PKCS11_CKA_MODULUS			= 0x0120,
	PKCS11_CKA_MODULUS_BITS			= 0x0121,
	PKCS11_CKA_PUBLIC_EXPONENT		= 0x0122,
	PKCS11_CKA_PRIVATE_EXPONENT		= 0x0123,
	PKCS11_CKA_PRIME_1			= 0x0124,
	PKCS11_CKA_PRIME_2			= 0x0125,
	PKCS11_CKA_EXPONENT_1			= 0x0126,
	PKCS11_CKA_EXPONENT_2			= 0x0127,
	PKCS11_CKA_COEFFICIENT			= 0x0128,
	PKCS11_CKA_PUBLIC_KEY_INFO		= 0x0129,
	PKCS11_CKA_PRIME			= 0x0130,
	PKCS11_CKA_SUBPRIME			= 0x0131,
	PKCS11_CKA_BASE				= 0x0132,
	PKCS11_CKA_PRIME_BITS			= 0x0133,
	PKCS11_CKA_SUBPRIME_BITS		= 0x0134,
	PKCS11_CKA_VALUE_BITS			= 0x0160,
	PKCS11_CKA_VALUE_LEN			= 0x0161,
	PKCS11_CKA_EXTRACTABLE			= 0x0162,
	PKCS11_CKA_LOCAL			= 0x0163,
	PKCS11_CKA_NEVER_EXTRACTABLE		= 0x0164,
	PKCS11_CKA_ALWAYS_SENSITIVE		= 0x0165,
	PKCS11_CKA_KEY_GEN_MECHANISM		= 0x0166,
	PKCS11_CKA_MODIFIABLE			= 0x0170,
	PKCS11_CKA_COPYABLE			= 0x0171,
	PKCS11_CKA_DESTROYABLE			= 0x0172,
	PKCS11_CKA_EC_PARAMS			= 0x0180,
	PKCS11_CKA_EC_POINT			= 0x0181,
	PKCS11_CKA_ALWAYS_AUTHENTICATE		= 0x0202,
	PKCS11_CKA_WRAP_WITH_TRUSTED		= 0x0210,
	/*
	 * The leading 4 comes from the PKCS#11 spec or:ing with
	 * CKF_ARRAY_ATTRIBUTE = 0x40000000.
	 */
	PKCS11_CKA_WRAP_TEMPLATE		= 0x40000211,
	PKCS11_CKA_UNWRAP_TEMPLATE		= 0x40000212,
	PKCS11_CKA_DERIVE_TEMPLATE		= 0x40000213,
	PKCS11_CKA_OTP_FORMAT			= 0x0220,
	PKCS11_CKA_OTP_LENGTH			= 0x0221,
	PKCS11_CKA_OTP_TIME_INTERVAL		= 0x0222,
	PKCS11_CKA_OTP_USER_FRIENDLY_MODE	= 0x0223,
	PKCS11_CKA_OTP_CHALLENGE_REQUIREMENT	= 0x0224,
	PKCS11_CKA_OTP_TIME_REQUIREMENT		= 0x0225,
	PKCS11_CKA_OTP_COUNTER_REQUIREMENT	= 0x0226,
	PKCS11_CKA_OTP_PIN_REQUIREMENT		= 0x0227,
	PKCS11_CKA_OTP_COUNTER			= 0x022e,
	PKCS11_CKA_OTP_TIME			= 0x022f,
	PKCS11_CKA_OTP_USER_IDENTIFIER		= 0x022a,
	PKCS11_CKA_OTP_SERVICE_IDENTIFIER	= 0x022b,
	PKCS11_CKA_OTP_SERVICE_LOGO		= 0x022c,
	PKCS11_CKA_OTP_SERVICE_LOGO_TYPE	= 0x022d,
	PKCS11_CKA_GOSTR3410_PARAMS		= 0x0250,
	PKCS11_CKA_GOSTR3411_PARAMS		= 0x0251,
	PKCS11_CKA_GOST28147_PARAMS		= 0x0252,
	PKCS11_CKA_HW_FEATURE_TYPE		= 0x0300,
	PKCS11_CKA_RESET_ON_INIT		= 0x0301,
	PKCS11_CKA_HAS_RESET			= 0x0302,
	PKCS11_CKA_PIXEL_X			= 0x0400,
	PKCS11_CKA_PIXEL_Y			= 0x0401,
	PKCS11_CKA_RESOLUTION			= 0x0402,
	PKCS11_CKA_CHAR_ROWS			= 0x0403,
	PKCS11_CKA_CHAR_COLUMNS			= 0x0404,
	PKCS11_CKA_COLOR			= 0x0405,
	PKCS11_CKA_BITS_PER_PIXEL		= 0x0406,
	PKCS11_CKA_CHAR_SETS			= 0x0480,
	PKCS11_CKA_ENCODING_METHODS		= 0x0481,
	PKCS11_CKA_MIME_TYPES			= 0x0482,
	PKCS11_CKA_MECHANISM_TYPE		= 0x0500,
	PKCS11_CKA_REQUIRED_CMS_ATTRIBUTES	= 0x0501,
	PKCS11_CKA_DEFAULT_CMS_ATTRIBUTES	= 0x0502,
	PKCS11_CKA_SUPPORTED_CMS_ATTRIBUTES	= 0x0503,
	/*
	 * The leading 4 comes from the PKCS#11 spec or:ing with
	 * CKF_ARRAY_ATTRIBUTE = 0x40000000.
	 */
	PKCS11_CKA_ALLOWED_MECHANISMS		= 0x40000600,
	/* Vendor extension: reserved for undefined ID (~0U) */
	PKCS11_CKA_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * Valid values for attribute PKCS11_CKA_CLASS
 * PKCS11_CKO_<x> reflects CryptoKi client API object class IDs CKO_<x>.
 */
enum pkcs11_class_id {
	PKCS11_CKO_DATA				= 0x000,
	PKCS11_CKO_CERTIFICATE			= 0x001,
	PKCS11_CKO_PUBLIC_KEY			= 0x002,
	PKCS11_CKO_PRIVATE_KEY			= 0x003,
	PKCS11_CKO_SECRET_KEY			= 0x004,
	PKCS11_CKO_HW_FEATURE			= 0x005,
	PKCS11_CKO_DOMAIN_PARAMETERS		= 0x006,
	PKCS11_CKO_MECHANISM			= 0x007,
	PKCS11_CKO_OTP_KEY			= 0x008,
	/* Vendor extension: reserved for undefined ID (~0U) */
	PKCS11_CKO_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * Valid values for attribute PKCS11_CKA_KEY_TYPE
 * PKCS11_CKK_<x> reflects CryptoKi client API key type IDs CKK_<x>.
 * Note that this is only a subset of the PKCS#11 specification.
 */
enum pkcs11_key_type {
	PKCS11_CKK_RSA				= 0x000,
	PKCS11_CKK_DSA				= 0x001,
	PKCS11_CKK_DH				= 0x002,
	PKCS11_CKK_EC				= 0x003,
	PKCS11_CKK_GENERIC_SECRET		= 0x010,
	PKCS11_CKK_AES				= 0x01f,
	PKCS11_CKK_MD5_HMAC			= 0x027,
	PKCS11_CKK_SHA_1_HMAC			= 0x028,
	PKCS11_CKK_SHA256_HMAC			= 0x02b,
	PKCS11_CKK_SHA384_HMAC			= 0x02c,
	PKCS11_CKK_SHA512_HMAC			= 0x02d,
	PKCS11_CKK_SHA224_HMAC			= 0x02e,
	/* Vendor extension: reserved for undefined ID (~0U) */
	PKCS11_CKK_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * Valid values for attribute PKCS11_CKA_CERTIFICATE_TYPE
 */
enum pkcs11_certificate_type {
	PKCS11_CKC_X_509		= 0x00000000UL,
	PKCS11_CKC_X_509_ATTR_CERT	= 0x00000001UL,
	PKCS11_CKC_WTLS			= 0x00000002UL,
	/* Vendor extension: reserved for undefined ID (~0U) */
	PKCS11_CKC_UNDEFINED_ID		= PKCS11_UNDEFINED_ID,
};

/*
 * Valid values for attribute PKCS11_CKA_CERTIFICATE_CATEGORY
 */
enum pkcs11_certificate_category {
	PKCS11_CK_CERTIFICATE_CATEGORY_UNSPECIFIED	= 0UL,
	PKCS11_CK_CERTIFICATE_CATEGORY_TOKEN_USER	= 1UL,
	PKCS11_CK_CERTIFICATE_CATEGORY_AUTHORITY	= 2UL,
	PKCS11_CK_CERTIFICATE_CATEGORY_OTHER_ENTITY	= 3UL,
};

/*
 * Valid values for mechanism IDs
 * PKCS11_CKM_<x> reflects CryptoKi client API mechanism IDs CKM_<x>.
 * Note that this will be extended as needed.
 */
enum pkcs11_mechanism_id {
	PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN	= 0x00000,
	PKCS11_CKM_RSA_PKCS			= 0x00001,
	PKCS11_CKM_MD5_RSA_PKCS			= 0x00005,
	PKCS11_CKM_SHA1_RSA_PKCS		= 0x00006,
	PKCS11_CKM_RSA_PKCS_OAEP		= 0x00009,
	PKCS11_CKM_RSA_PKCS_PSS			= 0x0000d,
	PKCS11_CKM_SHA1_RSA_PKCS_PSS		= 0x0000e,
	PKCS11_CKM_SHA256_RSA_PKCS		= 0x00040,
	PKCS11_CKM_SHA384_RSA_PKCS		= 0x00041,
	PKCS11_CKM_SHA512_RSA_PKCS		= 0x00042,
	PKCS11_CKM_SHA256_RSA_PKCS_PSS		= 0x00043,
	PKCS11_CKM_SHA384_RSA_PKCS_PSS		= 0x00044,
	PKCS11_CKM_SHA512_RSA_PKCS_PSS		= 0x00045,
	PKCS11_CKM_SHA224_RSA_PKCS		= 0x00046,
	PKCS11_CKM_SHA224_RSA_PKCS_PSS		= 0x00047,
	PKCS11_CKM_MD5				= 0x00210,
	PKCS11_CKM_MD5_HMAC			= 0x00211,
	PKCS11_CKM_MD5_HMAC_GENERAL		= 0x00212,
	PKCS11_CKM_SHA_1			= 0x00220,
	PKCS11_CKM_SHA_1_HMAC			= 0x00221,
	PKCS11_CKM_SHA_1_HMAC_GENERAL		= 0x00222,
	PKCS11_CKM_SHA256			= 0x00250,
	PKCS11_CKM_SHA256_HMAC			= 0x00251,
	PKCS11_CKM_SHA256_HMAC_GENERAL		= 0x00252,
	PKCS11_CKM_SHA224			= 0x00255,
	PKCS11_CKM_SHA224_HMAC			= 0x00256,
	PKCS11_CKM_SHA224_HMAC_GENERAL		= 0x00257,
	PKCS11_CKM_SHA384			= 0x00260,
	PKCS11_CKM_SHA384_HMAC			= 0x00261,
	PKCS11_CKM_SHA384_HMAC_GENERAL		= 0x00262,
	PKCS11_CKM_SHA512			= 0x00270,
	PKCS11_CKM_SHA512_HMAC			= 0x00271,
	PKCS11_CKM_SHA512_HMAC_GENERAL		= 0x00272,
	PKCS11_CKM_GENERIC_SECRET_KEY_GEN	= 0x00350,
	PKCS11_CKM_EC_KEY_PAIR_GEN		= 0x01040,
	PKCS11_CKM_ECDSA			= 0x01041,
	PKCS11_CKM_ECDSA_SHA1			= 0x01042,
	PKCS11_CKM_ECDSA_SHA224			= 0x01043,
	PKCS11_CKM_ECDSA_SHA256			= 0x01044,
	PKCS11_CKM_ECDSA_SHA384			= 0x01045,
	PKCS11_CKM_ECDSA_SHA512			= 0x01046,
	PKCS11_CKM_AES_KEY_GEN			= 0x01080,
	PKCS11_CKM_AES_ECB			= 0x01081,
	PKCS11_CKM_AES_CBC			= 0x01082,
	PKCS11_CKM_AES_CBC_PAD			= 0x01085,
	PKCS11_CKM_AES_CTR			= 0x01086,
	PKCS11_CKM_AES_CTS			= 0x01089,
	PKCS11_CKM_AES_CMAC			= 0x0108a,
	PKCS11_CKM_AES_CMAC_GENERAL		= 0x0108b,
	PKCS11_CKM_AES_ECB_ENCRYPT_DATA		= 0x01104,
	PKCS11_CKM_AES_CBC_ENCRYPT_DATA		= 0x01105,
	/*
	 * Vendor extensions below.
	 * PKCS11 added IDs for operation not related to a CK mechanism ID
	 */
	PKCS11_PROCESSING_IMPORT		= 0x80000000,
	PKCS11_CKM_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * PKCS11_CKD_<x> reflects CryptoKi client API key diff function IDs CKD_<x>.
 */
enum pkcs11_keydiff_id {
	PKCS11_CKD_NULL				= 0x0001,
	/* Vendor extension: reserved for undefined ID (~0U) */
	PKCS11_CKD_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * Valid values MG function identifiers
 * PKCS11_CKG_<x> reflects CryptoKi client API MG function IDs CKG_<x>.
 */
enum pkcs11_mgf_id {
	PKCS11_CKG_MGF1_SHA1			= 0x0001,
	PKCS11_CKG_MGF1_SHA224			= 0x0005,
	PKCS11_CKG_MGF1_SHA256			= 0x0002,
	PKCS11_CKG_MGF1_SHA384			= 0x0003,
	PKCS11_CKG_MGF1_SHA512			= 0x0004,
	/* Vendor extension: reserved for undefined ID (~0U) */
	PKCS11_CKG_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * Valid values for RSA PKCS/OAEP source type identifier
 * PKCS11_CKZ_<x> reflects CryptoKi client API source type IDs CKZ_<x>.
 */
#define PKCS11_CKZ_DATA_SPECIFIED		0x0001

#endif /*PKCS11_TA_H*/
