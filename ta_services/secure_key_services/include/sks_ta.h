/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#ifndef __SKS_TA_H__
#define __SKS_TA_H__

#include <sys/types.h>
#include <stdint.h>
#include <util.h>

#define TA_SKS_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
			{ 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

/* SKS trusted application version information */
#define SKS_VERSION_ID0		0
#define SKS_VERSION_ID1		0

/*
 * SKS_CMD_PING		Acknowledge TA presence and return TA version info
 *
 * Optinal invocation parameter:
 *
 * [out]        memref[2] = [
 *                      32bit version0 value,
 *                      32bit version1 value
 *              ]
 */
#define SKS_CMD_PING			0x00000000

/*
 * SKS_CMD_CK_SLOT_LIST - Get the table of the valid slot IDs
 *
 * [out]        memref[2] = 32bit array slot_ids[slot counts]
 *
 * The TA instance may represent several PKCS#11 slots and associated tokens.
 * This command relates the PKCS#11 API function C_GetSlotList and return the
 * valid IDs recognized by the trsuted application.
 */
#define SKS_CMD_CK_SLOT_LIST		0x00000001

/*
 * SKS_CMD_CK_SLOT_INFO - Get cryptoki structured slot information
 *
 * [in]		memref[0] = 32bit slot ID
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]        memref[2] = (struct sks_ck_slot_info)info
 *
 * The TA instance may represent several PKCS#11 slots and associated tokens.
 * This command relates the PKCS#11 API function C_GetSlotInfo and return the
 * information abut the target slot.
 */
#define SKS_CMD_CK_SLOT_INFO		0x00000002

struct sks_slot_info {
	uint8_t slotDescription[64];
	uint8_t manufacturerID[32];
	uint32_t flags;
	uint8_t hardwareVersion[2];
	uint8_t firmwareVersion[2];
};

/*
 * Values for sks_token_info::flags.
 * SKS_CKFS_<x> corresponds to cryptoki flag CKF_<x> related to slot flags.
 */
#define SKS_CKFS_TOKEN_PRESENT		(1U << 0)
#define SKS_CKFS_REMOVABLE_DEVICE	(1U << 1)
#define SKS_CKFS_HW_SLOT		(1U << 2)

/*
 * SKS_CMD_CK_TOKEN_INFO - Get cryptoki structured token information
 *
 * [in]		memref[0] = 32bit slot ID
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]        memref[2] = (struct sks_ck_token_info)info
 *
 * The TA instance may represent several PKCS#11 slots and associated tokens.
 * This command relates the PKCS#11 API function C_GetTokenInfo and return the
 * information abut the target represented token.
 */
#define SKS_CMD_CK_TOKEN_INFO		0x00000003

#define SKS_TOKEN_LABEL_SIZE		32
#define SKS_TOKEN_MANUFACTURER_SIZE	32
#define SKS_TOKEN_MODEL_SIZE		16
#define SKS_TOKEN_SERIALNUM_SIZE	16

struct sks_token_info {
	uint8_t label[SKS_TOKEN_LABEL_SIZE];
	uint8_t manufacturerID[SKS_TOKEN_MANUFACTURER_SIZE];
	uint8_t model[SKS_TOKEN_MODEL_SIZE];
	uint8_t serialNumber[SKS_TOKEN_SERIALNUM_SIZE];
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
 * Values for sks_token_info::flags.
 * SKS_CKFT_<x> corresponds to cryptoki CKF_<x> related to token flags.
 */
#define SKS_CKFT_RNG					(1U << 0)
#define SKS_CKFT_WRITE_PROTECTED			(1U << 1)
#define SKS_CKFT_LOGIN_REQUIRED				(1U << 2)
#define SKS_CKFT_USER_PIN_INITIALIZED			(1U << 3)
#define SKS_CKFT_RESTORE_KEY_NOT_NEEDED			(1U << 4)
#define SKS_CKFT_CLOCK_ON_TOKEN				(1U << 5)
#define SKS_CKFT_PROTECTED_AUTHENTICATION_PATH		(1U << 6)
#define SKS_CKFT_DUAL_CRYPTO_OPERATIONS			(1U << 7)
#define SKS_CKFT_TOKEN_INITIALIZED			(1U << 8)
#define SKS_CKFT_USER_PIN_COUNT_LOW			(1U << 9)
#define SKS_CKFT_USER_PIN_FINAL_TRY			(1U << 10)
#define SKS_CKFT_USER_PIN_LOCKED			(1U << 11)
#define SKS_CKFT_USER_PIN_TO_BE_CHANGED			(1U << 12)
#define SKS_CKFT_SO_PIN_COUNT_LOW			(1U << 13)
#define SKS_CKFT_SO_PIN_FINAL_TRY			(1U << 14)
#define SKS_CKFT_SO_PIN_LOCKED				(1U << 15)
#define SKS_CKFT_SO_PIN_TO_BE_CHANGED			(1U << 16)
#define SKS_CKFT_ERROR_STATE				(1U << 17)

/*
 * SKS_CMD_CK_MECHANISM_IDS - Get list of the supported mechanisms
 *
 * [in]		memref[0] = 32bit slot ID
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]        memref[2] = 32bit array mechanism IDs
 *
 * This commands relates to the PKCS#11 API function C_GetMechanismList.
 */
#define SKS_CMD_CK_MECHANISM_IDS	0x00000004

/*
 * SKS_CMD_CK_MECHANISM_INFO - Get information on a specific mechanism
 *
 * [in]		memref[0] = [
 *			32bit slot ID,
 *			32bit mechanism ID
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]        memref[2] = (struct sks_mecha_info)info
 *
 * This commands relates to the PKCS#11 API function C_GetMechanismInfo.
 */
#define SKS_CMD_CK_MECHANISM_INFO	0x00000005

struct sks_mechanism_info {
	uint32_t min_key_size;
	uint32_t max_key_size;
	uint32_t flags;
};

/*
 * Values for sks_mechanism_info::flags.
 * SKS_CKFM_<x> strictly matches cryptoki CKF_<x> related to mechanism flags.
 */
#define SKS_CKFM_HW			(1U << 0)
#define SKS_CKFM_ENCRYPT		(1U << 8)
#define SKS_CKFM_DECRYPT		(1U << 9)
#define SKS_CKFM_DIGEST			(1U << 10)
#define SKS_CKFM_SIGN			(1U << 11)
#define SKS_CKFM_SIGN_RECOVER		(1U << 12)
#define SKS_CKFM_VERIFY			(1U << 13)
#define SKS_CKFM_VERIFY_RECOVER		(1U << 14)
#define SKS_CKFM_GENERATE		(1U << 15)
#define SKS_CKFM_GENERATE_PAIR		(1U << 16)
#define SKS_CKFM_WRAP			(1U << 17)
#define SKS_CKFM_UNWRAP			(1U << 18)
#define SKS_CKFM_DERIVE			(1U << 19)

/*
 * SKS_CMD_CK_INIT_TOKEN - Initialiaze PKCS#11 token
 *
 * [in]		memref[0] = [
 *			32bit slot ID,
 *			32bit pin length,
 *			8bit array pin[pin length],
 *			8bit array label[32]
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * This commands relates to the PKCS#11 API function C_InitToken().
 */
#define SKS_CMD_CK_INIT_TOKEN		0x00000006

/*
 * SKS_CMD_CK_INIT_PIN - Initialiaze PKCS#11 token PIN
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit pin length,
 *			8bit array pin[pin length]
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * This commands relates to the PKCS#11 API function C_InitPIN().
 */
#define SKS_CMD_CK_INIT_PIN		0x00000007

/*
 * SKS_CMD_CK_SET_PIN - Set PKCS#11 token PIN
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit old_pin_length,
 *			8bit array old_pin[old_pin_length],
 *			32bit new_pin_length,
 *			8bit array new_pin[new_pin_length]
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * This commands relates to the PKCS#11 API function C_SetPIN()
 */
#define SKS_CMD_CK_SET_PIN		0x00000008

/*
 * SKS_CMD_CK_OPEN_RO_SESSION - Open read-only session
 *
 * [in]		memref[0] = 32bit slot ID
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[0] = 32bit session handle
 *
 * This commands relates to the PKCS#11 API function C_OpenSession() for a
 * read-only session.
 */
#define SKS_CMD_CK_OPEN_RO_SESSION	0x00000009

/*
 * SKS_CMD_CK_OPEN_RW_SESSION - Open read/write session
 *
 * [in]		memref[0] = 32bit slot
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[0] = 32bit session handle
 *
 * This commands relates to the PKCS#11 API function C_OpenSession() for a
 * read/Write session.
 */
#define SKS_CMD_CK_OPEN_RW_SESSION	0x0000000a

/*
 * SKS_CMD_CK_CLOSE_SESSION - Close an opened session
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * This commands relates to the PKCS#11 API function C_CloseSession().
 */
#define SKS_CMD_CK_CLOSE_SESSION	0x0000000b

/*
 * SKS_CMD_CK_SESSION_INFO - Get Cryptoki information on a session
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]        memref[2] = (struct sks_ck_session_info)info
 *
 * This commands relates to the PKCS#11 API function C_GetSessionInfo().
 */
#define SKS_CMD_CK_SESSION_INFO		0x0000000c

struct sks_session_info {
	uint32_t slot_id;
	uint32_t state;
	uint32_t flags;
	uint32_t error_code;
};

/*
 * SKS_CMD_CK_CLOSE_ALL_SESSIONS - Close all slot's pending sessions
 *
 * [in]		memref[0] = 32bit slot
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * This commands relates to the PKCS#11 API function C_CloseAllSessions().
 */
#define SKS_CMD_CK_CLOSE_ALL_SESSIONS	0x0000000d

/*
 * SKS_CMD_IMPORT_OBJECT - Import a raw object in the session or token
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct sks_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = 32bit object handle
 *
 * This commands relates to the PKCS#11 API function C_ImportObject().
 */
#define SKS_CMD_IMPORT_OBJECT		0x0000000e

/**
 * Serialization of object attributes
 */

/*
 * sks_object_head - Header of object whose data are serialized in memory
 *
 * An object in made of several attributes. Attributes are store one next to
 * the other with byte alignment as serialized blobs. Attributes data are
 * prepend with this header structure that defines the number of blobs
 * (of attributes) and the overall byte size of the serialized blobs.
 *
 * @blobs_size - byte size of whole byte array blobs[]
 * @blobs_count - number of attribute items stored in blobs[]
 * @blobs - then starts the blobs binary data starting with first attribute
 */
struct sks_object_head {
	uint32_t blobs_size;
	uint32_t blobs_count;
	uint8_t blobs[];
};

/*
 * Attribute reference in the TA ABI. Each attribute start with the header
 * structure followed by the attribute value, its byte size being defined
 * in the attribute header.
 *
 * @id - the 32bit identificator of the attribute, see SKS_CKA_<x>
 * @size - the 32bit value attribute byte size
 * @data - then starts the attribute value
 */
struct sks_attr_head {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

/*
 * SKS_CMD_DESTROY_OBJECT - Destroy an object
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * This commands relates to the PKCS#11 API function C_DestroyObject().
 */
#define SKS_CMD_DESTROY_OBJECT		0x0000000f

/*
 * SKS_CMD_ENCRYPT_INIT - Initialize decryption processing
 * SKS_CMD_DECRYPT_INIT - Initialize encryption processing
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct sks_attr_head)mechanism + mechanism parameters
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * These commands relate to the PKCS#11 API functions C_EncryptInit() and
 * C_DecryptInit.
 */
#define SKS_CMD_ENCRYPT_INIT		0x00000010
#define SKS_CMD_DECRYPT_INIT		0x00000011

/*
 * SKS_CMD_ENCRYPT_UPDATE - Update encryption processing
 * SKS_CMD_DECRYPT_UPDATE - Update decryption processing
 *
 * [in]		memref[0] = 32bit session handle
 * [in]		memref[1] = input data to be processed
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = output processed data
 *
 * These commands relate to the PKCS#11 API functions C_EncryptUpdate() and
 * C_DecryptUpdate.
 */
#define SKS_CMD_ENCRYPT_UPDATE		0x00000012
#define SKS_CMD_DECRYPT_UPDATE		0x00000013

/*
 * SKS_CMD_ENCRYPT_FINAL - Finalize encryption processing
 * SKS_CMD_DECRYPT_FINAL - Finalize decryption processing
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = output processed data
 *
 * These commands relate to the PKCS#11 API functions C_EncryptFinal() and
 * C_DecryptFinal.
 */
#define SKS_CMD_ENCRYPT_FINAL		0x00000014
#define SKS_CMD_DECRYPT_FINAL		0x00000015

/*
 * SKS_CMD_GENERATE_SYMM_KEY - Generate a symmetric key
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct sks_attr_head)mechanism + mechanism parameters,
 *			(struct sks_object_head)attribs + attributes data
 *		]
 * [in]		memref[1] = input data to be processed
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = 32bit key handle
 *
 * This command relates to the PKCS#11 API functions C_GenerateKey() and
 * C_DecryptInit.
 */
#define SKS_CMD_GENERATE_SYMM_KEY	0x00000016

/*
 * SKS_CMD_SIGN_INIT - Initialize a signature computation processing
 * SKS_CMD_VERIFY_INIT - Initialize a signature verification processing
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit key handle,
 *			(struct sks_attr_head)mechanism + mechanism parameters,
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * These commands relate to the PKCS#11 API functions C_SignInit() and
 * C_VerifyInit.
 */
#define SKS_CMD_SIGN_INIT		0x00000017
#define SKS_CMD_VERIFY_INIT		0x00000018

/*
 * SKS_CMD_SIGN_UPDATE - Initialize a signature computation processing
 * SKS_CMD_VERIFY_UPDATE - Initialize a signature verification processing
 *
 * [in]		memref[0] = 32bit session handle
 * [in]		memref[1] = input data to be processed
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * These commands relate to the PKCS#11 API functions C_SignUpdate() and
 * C_VerifyUpdate.
 */
#define SKS_CMD_SIGN_UPDATE		0x00000019
#define SKS_CMD_VERIFY_UPDATE		0x0000001a

/*
 * SKS_CMD_SIGN_FINAL - Initialize a signature computation processing
 * SKS_CMD_VERIFY_FINAL - Initialize a signature verification processing
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = output processed data
 *
 * These commands relate to the PKCS#11 API functions C_SignFinal() and
 * C_SignFinal.
 */
#define SKS_CMD_SIGN_FINAL		0x0000001b
#define SKS_CMD_VERIFY_FINAL		0x0000001c

/*
 * SKS_CMD_FIND_OBJECTS_INIT - Initialize a objects search
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct sks_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * This command relates to the PKCS#11 API function C_FindOjectsInit().
 */
#define SKS_CMD_FIND_OBJECTS_INIT	0x0000001d

/*
 * SKS_CMD_FIND_OBJECTS - Get handles of matching objects
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = 32bit array object_handle_array[N]
 *
 * This command relates to the PKCS#11 API function C_FindOjects().
 * The size of object_handle_array depends output buffer size
 * provided by the client.
 */
#define SKS_CMD_FIND_OBJECTS		0x0000001e

/*
 * SKS_CMD_FIND_OBJECTS_FINAL - Finalize current objects search
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain retrun code
 *
 * This command relates to the PKCS#11 API function C_FindOjectsFinal().
 */
#define SKS_CMD_FIND_OBJECTS_FINAL	0x0000001f

/*
 * SKS_CMD_GET_OBJECT_SIZE - Get size used by object in the TEE
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit key handle
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = 32bit object_byte_size
 */
#define SKS_CMD_GET_OBJECT_SIZE		0x00000020

/*
 * SKS_CMD_GET_ATTRIBUTE_VALUE - Get the value of object attrbiute(s)
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle,
 *			(struct sks_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = (struct sks_object_head)attribs + attributes data
 */
#define SKS_CMD_GET_ATTRIBUTE_VALUE	0x00000021

/*
 * SKS_CMD_SET_ATTRIBUTE_VALUE - Set the value for object attrbiute(s)
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle,
 *			(struct sks_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = (struct sks_object_head)attribs + attributes data
 */
#define SKS_CMD_SET_ATTRIBUTE_VALUE	0x00000022

/*
 * SKS_CMD_DERIVE_KEY - Create a key by derivation of a provisionned parent key
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct sks_attr_head)mechanism + mechanism parameters,
 *			32bit key handle,
 *			(struct sks_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain retrun code
 * [out]	memref[2] = 32bit object handle
 */
#define SKS_CMD_DERIVE_KEY		0x00000023

/*
 * Command return codes
 * SKS_CKR_<x> relates cryptoki CKR_<x> in meaning if not in value.
 */
#define SKS_CKR_OK				0x00000000
#define SKS_CKR_GENERAL_ERROR			0x00000001
#define SKS_CKR_DEVICE_MEMORY			0x00000002
#define SKS_CKR_ARGUMENT_BAD			0x00000003
#define SKS_CKR_BUFFER_TOO_SMALL		0x00000004
#define SKS_CKR_FUNCTION_FAILED			0x00000005
#define SKS_CKR_SIGNATURE_INVALID		0x00000007
#define SKS_CKR_ATTRIBUTE_TYPE_INVALID		0x00000008
#define SKS_CKR_ATTRIBUTE_VALUE_INVALID		0x00000009
#define SKS_CKR_OBJECT_HANDLE_INVALID		0x0000000a
#define SKS_CKR_KEY_HANDLE_INVALID		0x0000000b
#define SKS_CKR_MECHANISM_INVALID		0x0000000c
#define SKS_CKR_SESSION_HANDLE_INVALID		0x0000000d
#define SKS_CKR_SLOT_ID_INVALID			0x0000000e
#define SKS_CKR_MECHANISM_PARAM_INVALID		0x0000000f
#define SKS_CKR_TEMPLATE_INCONSISTENT		0x00000010
#define SKS_CKR_TEMPLATE_INCOMPLETE		0x00000011
#define SKS_CKR_PIN_INCORRECT			0x00000012
#define SKS_CKR_PIN_LOCKED			0x00000013
#define SKS_CKR_PIN_EXPIRED			0x00000014
#define SKS_CKR_PIN_INVALID			0x00000015
#define SKS_CKR_PIN_LEN_RANGE			0x00000016
#define SKS_CKR_SESSION_EXISTS			0x00000017
#define SKS_CKR_SESSION_READ_ONLY		0x00000018
#define SKS_CKR_SESSION_READ_WRITE_SO_EXISTS	0x00000019
#define SKS_CKR_OPERATION_ACTIVE		0x0000001a
#define SKS_CKR_KEY_FUNCTION_NOT_PERMITTED	0x0000001b
#define SKS_CKR_OPERATION_NOT_INITIALIZED	0x0000001c
/* Statuc without strict equivalence in cryptoki */
#define SKS_NOT_FOUND				0x00001000
#define SKS_NOT_IMPLEMENTED			0x00001001

/* Attribute specific values */
#define SKS_UNDEFINED_ID			((uint32_t)0xFFFFFFFF)
#define SKS_FALSE				0
#define SKS_TRUE				1

/*
 * SKS Generic Boolean Attributes of Secure Objects
 *
 * The bit flags use to define common boolean properties (boolprop) of the
 * objects. These flags are all inited. Almost all match a boolean attribute
 * from the PKCS#11 2.40. They are stored in the header structure of serialized
 * object used by SKS.
 */
#define SKS_PERSISTENT_SHIFT		0UL	/* CKA_TOKEN */
#define SKS_NEED_AUTHEN_SHIFT		1UL	/* CKA_PRIVATE */
#define SKS_TRUSTED_SHIFT		2UL	/* CKA_TRUSTED */
#define SKS_SENSITIVE_SHIFT		3UL	/* CKA_SENSITIVE */
#define SKS_ENCRYPT_SHIFT		4UL	/* CKA_ENCRYPT */
#define SKS_DECRYPT_SHIFT		5UL	/* CKA_DECRYPT */
#define SKS_WRAP_SHIFT			6UL	/* CKA_WRAP */
#define SKS_UNWRAP_SHIFT		7UL	/* CKA_UNWRAP */
#define SKS_SIGN_SHIFT			8UL	/* CKA_SIGN */
#define SKS_SIGN_RECOVER_SHIFT		9UL	/* CKA_SIGN_RECOVER */
#define SKS_VERIFY_SHIFT		10UL	/* CKA_VERIFY */
#define SKS_VERIFY_RECOVER_SHIFT	11UL	/* CKA_VERIFY_RECOVER */
#define SKS_DERIVE_SHIFT		12UL	/* CKA_DERIVE */
#define SKS_EXTRACTABLE_SHIFT		13UL	/* CKA_EXTRACTABLE */
#define SKS_LOCALLY_GENERATED_SHIFT	14UL	/* CKA_LOCAL */
#define SKS_NEVER_EXTRACTABLE_SHIFT	15UL	/* CKA_NEVER_EXTRACTABLE */
#define SKS_ALWAYS_SENSITIVE_SHIFT	16UL	/* CKA_ALWAYS_SENSITIVE */
#define SKS_MODIFIABLE_SHIFT		17UL	/* CKA_MODIFIABLE */
#define SKS_COPYABLE_SHIFT		18UL	/* CKA_COPYABLE */
#define SKS_DESTROYABLE_SHIFT		19UL	/* CKA_DESTROYABLE */
#define SKS_ALWAYS_AUTHEN_SHIFT		20UL	/* CKA_ALWAYS_AUTHENTICATE */
#define SKS_WRAP_FROM_TRUSTED_SHIFT	21UL	/* CKA_WRAP_WITH_TRUSTED */
#define SKS_BOOLPROP_LAST_SHIFT		21UL

#define SKS_BP_PERSISTENT		BIT(SKS_PERSISTENT_SHIFT)
#define SKS_BP_NEED_AUTHEN		BIT(SKS_NEED_AUTHEN_SHIFT)
#define SKS_BP_TRUSTED			BIT(SKS_TRUSTED_SHIFT)
#define SKS_BP_SENSITIVE		BIT(SKS_SENSITIVE_SHIFT)
#define SKS_BP_ENCRYPT			BIT(SKS_ENCRYPT_SHIFT)
#define SKS_BP_DECRYPT			BIT(SKS_DECRYPT_SHIFT)
#define SKS_BP_WRAP			BIT(SKS_WRAP_SHIFT)
#define SKS_BP_UNWRAP			BIT(SKS_UNWRAP_SHIFT)
#define SKS_BP_SIGN			BIT(SKS_SIGN_SHIFT)
#define SKS_BP_SIGN_RECOVER		BIT(SKS_SIGN_RECOVER_SHIFT)
#define SKS_BP_VERIFY			BIT(SKS_VERIFY_SHIFT)
#define SKS_BP_VERIFY_RECOVER		BIT(SKS_VERIFY_RECOVER_SHIFT)
#define SKS_BP_DERIVE			BIT(SKS_DERIVE_SHIFT)
#define SKS_BP_EXTRACTABLE		BIT(SKS_EXTRACTABLE_SHIFT)
#define SKS_BP_LOCALLY_GENERATED	BIT(SKS_LOCALLY_GENERATED_SHIFT)
#define SKS_BP_NEVER_EXTRACTABLE	BIT(SKS_NEVER_EXTRACTABLE_SHIFT)
#define SKS_BP_ALWAYS_SENSITIVE		BIT(SKS_ALWAYS_SENSITIVE_SHIFT)
#define SKS_BP_MODIFIABLE		BIT(SKS_MODIFIABLE_SHIFT)
#define SKS_BP_COPYABLE			BIT(SKS_COPYABLE_SHIFT)
#define SKS_BP_DESTROYABLE		BIT(SKS_DESTROYABLE_SHIFT)
#define SKS_BP_ALWAYS_AUTHEN		BIT(SKS_ALWAYS_AUTHEN_SHIFT)
#define SKS_BP_WRAP_FROM_TRUSTED	BIT(SKS_WRAP_FROM_TRUSTED_SHIFT)

/*
 * Attribute IDs: field @id in struct sks_reference
 */
#define SKS_LABEL			0x00000000	/* Object label */
#define SKS_VALUE			0x00000001	/* Object value */
#define SKS_VALUE_LEN			0x00000002	/* Object value size */
#define SKS_WRAP_ATTRIBS		0x00000003	/* Attribute list */
#define SKS_UNWRAP_ATTRIBS		0x00000004	/* Attribute list */
#define SKS_DERIVE_ATTRIBS		0x00000005	/* Attribute list */
#define SKS_ACTIVATION_DATE		0x00000006	/* UTC time */
#define SKS_REVOKATION_DATE		0x00000007	/* UTC time */
#define SKS_OBJECT_ID			0x00000008	/* CKA_OBJECT_ID */
#define SKS_APPLICATION_ID		0x00000009	/* CKA_APPLICATION */
#define SKS_PROCESSING_ID		0x0000000a	/* CKA_MECHANISM_T.. */
#define SKS_KEY_ID			0x0000000b	/* CKA_ID */
#define SKS_ALLOWED_PROCESSINGS		0x0000000c	/* CKA_ALLOWED_ME... */

/* Range [0x100 - 0x1ff] is reserved to generic attributes (stored in head) */
#define SKS_GENERIC_BASE		0x00000100
#define SKS_BOOLPROPS_BASE		0x00000100
#define SKS_BOOLPROPS_LAST		0x0000013F
#define SKS_GENERIC_LAST		0x000001FF
#define SKS_BP_ATTR(id)			(SKS_BOOLPROPS_BASE + id)
#define SKS_CLASS			0x000001F0
#define SKS_TYPE			0x000001F1

#define SKS_PERSISTENT			SKS_BP_ATTR(SKS_PERSISTENT_SHIFT)
#define SKS_NEED_AUTHEN			SKS_BP_ATTR(SKS_NEED_AUTHEN_SHIFT)
#define SKS_TRUSTED			SKS_BP_ATTR(SKS_TRUSTED_SHIFT)
#define SKS_SENSITIVE			SKS_BP_ATTR(SKS_SENSITIVE_SHIFT)
#define SKS_ENCRYPT			SKS_BP_ATTR(SKS_ENCRYPT_SHIFT)
#define SKS_DECRYPT			SKS_BP_ATTR(SKS_DECRYPT_SHIFT)
#define SKS_WRAP			SKS_BP_ATTR(SKS_WRAP_SHIFT)
#define SKS_UNWRAP			SKS_BP_ATTR(SKS_UNWRAP_SHIFT)
#define SKS_SIGN			SKS_BP_ATTR(SKS_SIGN_SHIFT)
#define SKS_SIGN_RECOVER		SKS_BP_ATTR(SKS_SIGN_RECOVER_SHIFT)
#define SKS_VERIFY			SKS_BP_ATTR(SKS_VERIFY_SHIFT)
#define SKS_VERIFY_RECOVER		SKS_BP_ATTR(SKS_VERIFY_RECOVER_SHIFT)
#define SKS_DERIVE			SKS_BP_ATTR(SKS_DERIVE_SHIFT)
#define SKS_EXTRACTABLE			SKS_BP_ATTR(SKS_EXTRACTABLE_SHIFT)
#define SKS_LOCALLY_GENERATED		SKS_BP_ATTR(SKS_LOCALLY_GENERATED_SHIFT)
#define SKS_NEVER_EXTRACTABLE		SKS_BP_ATTR(SKS_NEVER_EXTRACTABLE_SHIFT)
#define SKS_ALWAYS_SENSITIVE		SKS_BP_ATTR(SKS_ALWAYS_SENSITIVE_SHIFT)
#define SKS_MODIFIABLE			SKS_BP_ATTR(SKS_MODIFIABLE_SHIFT)
#define SKS_COPYABLE			SKS_BP_ATTR(SKS_COPYABLE_SHIFT)
#define SKS_DESTROYABLE			SKS_BP_ATTR(SKS_DESTROYABLE_SHIFT)
#define SKS_ALWAYS_AUTHEN		SKS_BP_ATTR(SKS_ALWAYS_AUTHEN_SHIFT)
#define SKS_WRAP_FROM_TRUSTED		SKS_BP_ATTR(SKS_WRAP_FROM_TRUSTED_SHIFT)

/*
 * SKS supported object class
 */
#define SKS_OBJ_SYM_KEY				0
#define SKS_OBJ_PUB_KEY				1
#define SKS_OBJ_PRIV_KEY			2
#define SKS_OBJ_OTP_KEY				3
#define SKS_OBJ_CERTIFICATE			4
#define SKS_OBJ_RAW_DATA			5
#define SKS_OBJ_CK_DOMAIN_PARAMS		6
#define SKS_OBJ_CK_HW_FEATURES			7
#define SKS_OBJ_CK_MECHANISM			8

/*
 * SKS supported types for SKS_OBJ_SYM_KEY
 */
#define SKS_KEY_AES				0
#define SKS_GENERIC_SECRET			1
#define SKS_KEY_HMAC_MD5			2
#define SKS_KEY_HMAC_SHA1			3
#define SKS_KEY_HMAC_SHA224			4
#define SKS_KEY_HMAC_SHA256			5
#define SKS_KEY_HMAC_SHA384			6
#define SKS_KEY_HMAC_SHA512			7

/*
 * SKS supported type for SKS_OBJ_CK_MECHANISM
 */
#define SKS_PROC_AES_ECB_NOPAD			0	/* NIST AES ECB */
#define SKS_PROC_AES_CBC_NOPAD			1	/* NIST AES CBC */
#define SKS_PROC_AES_CBC_PAD			2	/* AES CBC/PKCS#7 */
#define SKS_PROC_AES_CTS			3	/* NIST AES CBC/CTS */
#define SKS_PROC_AES_CTR			4	/* NIST AES CTR */
#define SKS_PROC_AES_GCM			5	/* NIST AES GCM */
#define SKS_PROC_AES_CCM			6	/* NIST AES CCM  */
#define SKS_PROC_AES_GMAC			7	/* NIST AES GCM/AAD */
#define SKS_PROC_AES_CMAC			8	/* AES Block CMAC */
#define SKS_PROC_AES_CMAC_GENERAL		9	/* Sized AES CMAC */
#define SKS_PROC_AES_DERIVE_BY_ECB		10	/* NIST AES ECB */
#define SKS_PROC_AES_DERIVE_BY_CBC		11	/* NIST AES CBC */
#define SKS_PROC_AES_GENERATE			12	/* Generate key */

#define SKS_PROC_GENERIC_GENERATE		13	/* Generic secret */

#define SKS_PROC_RAW_IMPORT			14	/* Importing key */
#define SKS_PROC_RAW_COPY			15	/* Copying key */

#define SKS_PROC_HMAC_MD5			20
#define SKS_PROC_HMAC_SHA1			21
#define SKS_PROC_HMAC_SHA224			22
#define SKS_PROC_HMAC_SHA256			23
#define SKS_PROC_HMAC_SHA384			24
#define SKS_PROC_HMAC_SHA512			25
#define SKS_PROC_AES_CBC_MAC			26

/*
 * Processing parameters
 *
 * These can hardly be described by ANSI-C structures since some field of the
 * structure have a size specify by a previous field. Therefore the format of
 * the parameter binary data for each supported processing is define here from
 * this comment rather than using C structures. Processing parameters are used
 * as argument the C_EncryptInit and friends using the struct sks_reference
 * format where field 'type' is the SKS processing ID and field 'size' is the
 * parameter byte size. Below is shown the head struct sks_reference fields
 * and the trailling data (the effective parameters binary blob).
 *
 * AES ECB
 *   head:	32bit type = SKS_PROC_AES_ECB_NOPAD
 *		32bit params byte size = 0
 *
 * AES CBC, CBC_NOPAD and CTS
 *   head:	32bit type = SKS_PROC_AES_CBC
 *			  or SKS_PROC_AES_CBC_NOPAD
 *			  or SKS_PROC_AES_CTS
 *		32bit params byte size = 16
 *  params:	16byte inivial vector
 *
 * AES CTR
 *   head:	32bit type = SKS_PROC_AES_CTR
 *		32bit params byte size = 20
 *  params:	32bit counter bit increment
 *		16byte inivial vector
 *
 * AES GCM
 *   head:	32bit type = SKS_PROC_AES_GCM
 *		32bit params byte size
 *  params:	32bit IV_byte_size
 *		byte array: IV data (IV_byte_size bytes)
 *		32bit AAD_byte_size
 *		byte array: AAD data (AAD_byte_size bytes)
 *		32bit tag bit size
 *
 * AES CCM
 *   head:	32bit type = SKS_PROC_AES_CCM
 *		32bit params byte size
 *  params:	32bit data_byte_size
 *		32bit nonce_byte_size
 *		byte array: nonce data (nonce_byte_size bytes)
 *		32bit AAD_byte_size
 *		byte array: AAD data (AAD_byte_size bytes)
 *		32bit MAC byte size
 *
 * AES GMAC
 *   head:	32bit type = SKS_PROC_AES_GMAC
 *		32bit params byte size = 12
 *  params:	12byte initial vector

 * AES CMAC with general length
 *   head:	32bit type = SKS_PROC_AES_CMAC_GENERAL
 *		32bit params byte size = 12
 *  params:	32bit byte size of the output CMAC data
 *
 * AES CMAC fixed size (16byte CMAC)
 *   head:	32bit type = SKS_PROC_AES_CMAC_GENERAL
 *		32bit size = 0
 *
 * AES derive by ECB
 *   head:	32bit type = SKS_PROC_AES_DERIVE_BY_ECB
 *		32bit params byte size
 *  params:	32bit byte size of the data to encrypt
 *		byte array: data to encrypt
 *
 * AES derive by CBC
 *   head:	32bit type = SKS_PROC_AES_DERIVE_BY_CBC
 *		32bit params byte size
 *  params:	16byte inivial vector
 *		32bit byte size of the data to encrypt
 *		byte array: data to encrypt
 *
 * AES and generic secret generation
 *   head:	32bit type = SKS_PROC_AES_GENERATE
 *			  or SKS_PROC_GENERIC_GENERATE
 *		32bit size = 0
 */

#endif /*__SKS_TA_H__*/
