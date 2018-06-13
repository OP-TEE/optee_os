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
 * SKS trusted application may receive requests requesting a number of
 * parameters that may not suit the GPD 4 parameters directives.
 * To factorize the use of GPD parameters for SKS services, the current
 * API uses the 4 GPD invocation parameters as following:
 *
 * - Parameter #0 is not used or is used as an input memory reference argument.
 * The referred buffer hold the command directives arguments (handlers,
 * ids, ...) expected by the command. When several arguments are expected,
 * they are serialized with byte alignment in the single control buffer.
 *
 * When caller defines parameter #0 as an in/out memory reference, the
 * parameter #0 is used to feedback caller with a detailed 32bit return
 * code that allow to return finer error reporting to client than the GPD
 * TEE API allows a TA to return. For this reason, the invocation commands
 * below mark parameter #0 as "in(*)-memref" in the command description
 * comments.
 *
 * - Parameter #1 is not used or is an input memory reference. It refers to
 * the input data provided for the invoked service.
 *
 * - Parameter #2 is not used or is an output memory reference. It refers to
 * the output buffer expected to be filled with the output data requested
 * by the caller. These data can be a object handle, a ciphered stream, etc.
 *
 * - Parameter #3 is not used.
 */

/*
 * SKS_CMD_PING		Acknowledge TA presence and return TA versioning info
 *
 * param#0: none
 * param#1: none
 * param#2: none | out-memref : [uint32_t version1]
 *				[uint32_t version2]
 * param#3: none
 */
#define SKS_CMD_PING			0x00000000

/*
 * SKS_CMD_CK_SLOT_LIST - Get the table of the valid slot IDs
 *
 * param#0: none
 * param#1: none
 * param#2: out-memref : [uint32_t slot_ids]
 * param#3: none
 *
 * The TA instance may represent several PKCS#11 slots and associated tokens.
 * This command relates the PKCS#11 API function C_GetSlotList and return the
 * valid IDs recognized by the trsuted application.
 */
#define SKS_CMD_CK_SLOT_LIST		0x00000001

/*
 * SKS_CMD_CK_SLOT_INFO - Get cryptoki structured slot information
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [struct sks_ck_slot_info info]
 * param#3: none
 *
 * The TA instance may represent several PKCS#11 slots and associated tokens.
 * This command relates the PKCS#11 API function C_GetSlotInfo and return the
 * information abut the target slot.
 */
#define SKS_CMD_CK_SLOT_INFO		0x00000002

struct sks_ck_slot_info {
	uint8_t slotDescription[64];
	uint8_t manufacturerID[32];
	uint32_t flags;
	uint8_t hardwareVersion[2];
	uint8_t firmwareVersion[2];
};

/* Slot flags reflecting the pkcs11 flags */
#define SKS_TOKEN_PRESENT		BIT(0UL)
#define SKS_TOKEN_REMOVABLE		BIT(1UL)
#define SKS_TOKEN_HW			BIT(2UL)

/*
 * SKS_CMD_CK_TOKEN_INFO - Get cryptoki structured token information
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [struct sks_ck_token_info info]
 * param#3: none
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

struct sks_ck_token_info {
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

/* Flags (reflect the cryptoki flags) */
#define SKS_TOKEN_HAS_RNG		BIT(0UL)	/* CKF_RNG */
#define SKS_TOKEN_IS_READ_ONLY		BIT(1UL)	/* CKF_WRITE_PRO... */
#define SKS_TOKEN_REQUIRE_LOGIN		BIT(2UL)	/* CKF_LOGIN_REQ... */
#define SKS_TOKEN_HAS_USER_PIN		BIT(3UL)	/* CKF_USER_PIN_... */
#define SKS_TOKEN_FULLY_RESTORABLE	BIT(4UL)	/* CKF_RESTORE_K... */
#define SKS_TOKEN_HAS_CLOCK		BIT(5UL)	/* CKF_CLOCK_ON_... */
#define SKS_TOKEN_ALT_AUTHENT		BIT(6UL)	/* CKF_PROTECTED... */
#define SKS_TOKEN_CAN_DUAL_PROC		BIT(7UL)	/* CKF_DUAL_CRYP... */
#define SKS_TOKEN_INITED		BIT(8UL)	/* CKF_TOKEN_INI... */
#define SKS_TOKEN_USR_PIN_FAILURE	BIT(9UL)	/* CKF_USER_PIN_... */
#define SKS_TOKEN_USR_PIN_LAST		BIT(10UL)	/* CKF_USER_PIN_... */
#define SKS_TOKEN_USR_PIN_LOCKED	BIT(11UL)	/* CKF_USER_PIN_... */
#define SKS_TOKEN_USR_PIN_TO_CHANGE	BIT(12UL)	/* CKF_USER_PIN_... */
#define SKS_TOKEN_SO_PIN_FAILURE	BIT(13UL)	/* CKF_SO_PIN_CO... */
#define SKS_TOKEN_SO_PIN_LAST		BIT(14UL)	/* CKF_SO_PIN_FI... */
#define SKS_TOKEN_SO_PIN_LOCKED		BIT(15UL)	/* CKF_SO_PIN_LO... */
#define SKS_TOKEN_SO_PIN_TO_CHANGE	BIT(16UL)	/* CKF_SO_PIN_TO... */
#define SKS_TOKEN_BAD_STATE		BIT(17UL)	/* CKF_ERROR_STATE */

/*
 * SKS_CMD_CK_MECHANISM_IDS - Get list of the supported mechanisms
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [struct sks_ck_mecha_id mecha_ids[N]]
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_GetMechanismList.
 */
#define SKS_CMD_CK_MECHANISM_IDS	0x00000004

struct sks_ck_mecha_id {
	uint32_t mecha_id;
};

/*
 * SKS_CMD_CK_MECHANISM_INFO - Get information on a specific mechanism
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 *			   [struct sks_ck_mecha_id mecha_id]
 * param#1: none
 * param#2: out-memref : [struct sks_ck_mecha_info info]
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_GetMechanismInfo.
 */
#define SKS_CMD_CK_MECHANISM_INFO	0x00000005

struct sks_ck_mecha_info {
	uint32_t min_key_size;
	uint32_t max_key_size;
	uint32_t flags;
};

/* flags */
#define SKS_PROC_HW			BIT(0UL)
#define SKS_PROC_ENCRYPT		BIT(1UL)
#define SKS_PROC_DECRYPT		BIT(2UL)
#define SKS_PROC_DIGEST			BIT(3UL)
#define SKS_PROC_SIGN			BIT(4UL)
#define SKS_PROC_SIGN_RECOVER		BIT(5UL)
#define SKS_PROC_VERIFY			BIT(6UL)
#define SKS_PROC_VERFIY_RECOVER		BIT(7UL)
#define SKS_PROC_GENERATE		BIT(8UL)
#define SKS_PROC_GENERATE_PAIR		BIT(9UL)
#define SKS_PROC_WRAP			BIT(10UL)
#define SKS_PROC_UNWRAP			BIT(11UL)
#define SKS_PROC_DERIVE			BIT(12UL)

/*
 * SKS_CMD_CK_INIT_TOKEN - Initialiaze PKCS#11 token
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 *			   [uint32_t pin_len]
 *			   [uint8_t pin[pin_len]]
 *			   [uint8_t label[32]]
 * param#1: none
 * param#2: none
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_InitToken().
 */
#define SKS_CMD_CK_INIT_TOKEN		0x00000006

struct sks_item_length {
	uint32_t byte_size;
};

/*
 * SKS_CMD_CK_INIT_PIN - Initialiaze PKCS#11 token PIN
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [uint32_t pin_len]
 *			   [uint8_t pin[pin_len]]
 * param#1: none
 * param#2: none
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_InitPIN().
 */
#define SKS_CMD_CK_INIT_PIN		0x00000007

struct sks_handle {
	uint32_t handle;
};

/*
 * SKS_CMD_CK_SET_PIN - Set PKCS#11 token PIN
 *
 * param#0: in(*)-memref : [uint32_t session_id]
 *			   [uint32_t old_pin_len]
 *			   [uint8_t old_pin[old_pin_len]]
 *			   [uint32_t new_pin_len]
 *			   [uint8_t new_pin[new_pin_len]]
 * param#1: none
 * param#2: none
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_SetPIN()
 */
#define SKS_CMD_CK_SET_PIN		0x00000008

/*
 * SKS_CMD_CK_OPEN_RO_SESSION - Open Read-only Session
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [uint32_t session_handle]
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_OpenSession() for a
 * read-only session.
 */
#define SKS_CMD_CK_OPEN_RO_SESSION	0x00000009

/*
 * SKS_CMD_CK_OPEN_RW_SESSION - Open Read/Write Session
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [uint32_t session_handle]
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_OpenSession() for a
 * read/Write session.
 */
#define SKS_CMD_CK_OPEN_RW_SESSION	0x0000000a

/*
 * SKS_CMD_CK_CLOSE_SESSION - Open Read/Write Session
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: none
 * param#2: none
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_CloseSession().
 */
#define SKS_CMD_CK_CLOSE_SESSION	0x0000000b

/*
 * SKS_CMD_CK_SESSION_INFO - Get Cryptoki information on a session
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: none
 * param#2: out-memref : [struct sks_ck_session_info]
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_GetSessionInfo().
 */
#define SKS_CMD_CK_SESSION_INFO		0x0000000c

struct sks_ck_session_info {
	uint32_t slot_id;
	uint32_t state;
	uint32_t flags;
	uint32_t error_code;
};

/*
 * SKS_CMD_CK_CLOSE_ALL_SESSIONS - Close all slot's pending sessions
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: none
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_CloseAllSessions().
 */
#define SKS_CMD_CK_CLOSE_ALL_SESSIONS	0x0000000d

/*
 * SKS_CMD_IMPORT_OBJECT - Open Read/Write Session
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [struct sks_object_head attribs + attributes data]
 * param#1: none
 * param#2: out-memref : [uint32_t object_handle]
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_ImportObject().
 */
#define SKS_CMD_IMPORT_OBJECT		0x0000000e

/**
 * Serialization of object attributes
 *
 * An object is defined by the list of its attributes among which identifiers
 * for the type of the object (symmetric key, asymmetric key, ...) and the
 * object value (i.e the AES key value). Other attributes define the use of
 * the object and structured values of the object.
 *
 * All in one an object is a list of attributes. This is represented in the TA
 * API by a header structure introducing the attribute list followed by the
 * object attributes serialized one after the other. The header defines the
 * number of attributes of the object. Each attribute is defined by 3 serialized
 * fields, see struct sks_reference.
 */

/*
 * sks_object_head - Header of object whose data are serialized in memory
 *
 * @blobs_size - byte size of the serialized data
 * @blobs_count - number of items in the blob
 * @blobs - then starts the blob binary data
 */
struct sks_object_head {
	uint32_t blobs_size;
	uint32_t blobs_count;
	uint8_t blobs[];
};

/*
 * Attribute reference in the TA ABI
 *
 * @id - the 32bit identificator of the attribute, see SKS attribute IDs
 * @size - the 32bit value attribute byte size
 * @data - location defines base memory of the attribute effective value
 */
struct sks_reference {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

/*
 * SKS_CMD_DESTROY_OBJECT - Destroy an object
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [uint32_t object_handle]
 * param#1: none
 * param#2: none
 * param#3: none
 *
 * This commands relates to the PKCS#11 API function C_DestroyObject().
 */
#define SKS_CMD_DESTROY_OBJECT		0x0000000f

/*
 * SKS_CMD_ENCRYPT_INIT - Initialize decryption processing
 * SKS_CMD_DECRYPT_INIT - Initialize encryption processing
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [struct sks_reference proc + proc parameters data]
 * param#1: none
 * param#2: none
 * param#3: none
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
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: in-memref : [input-data]
 * param#2: out-memref : [output-data]
 * param#3: none
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
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: none
 * param#2: out-memref : [output-data]
 * param#3: none
 *
 * These commands relate to the PKCS#11 API functions C_EncryptFinal() and
 * C_DecryptFinal.
 */
#define SKS_CMD_ENCRYPT_FINAL		0x00000014
#define SKS_CMD_DECRYPT_FINAL		0x00000015

/*
 * SKS_CMD_GENERATE_SYMM_KEY - Generate a symmetric key
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [struct sks_reference proc + proc parameters data]
 *			   [struct sks_object_head attribs + attributes data]
 * param#1: none
 * param#2: out-memref : [uint32_t object_handle]
 * param#3: none
 *
 * This command relates to the PKCS#11 API functions C_GenerateKey() and
 * C_DecryptInit.
 */
#define SKS_CMD_GENERATE_SYMM_KEY	0x00000016

/*
 * SKS_CMD_SIGN_INIT - Initialize a signature computation processing
 * SKS_CMD_VERIFY_INIT - Initialize a signature verification processing
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [uint32_t key_handle]
 *			   [struct sks_reference proc + proc parameters data]
 * param#1: none
 * param#2: none
 * param#3: none
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
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: in-memref : [input-data]
 * param#2: none
 * param#3: none
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
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: none
 * param#2: out-memref : [output-data]
 * param#3: none
 *
 * These commands relate to the PKCS#11 API functions C_SignFinal() and
 * C_SignFinal.
 */
#define SKS_CMD_SIGN_FINAL		0x0000001b
#define SKS_CMD_VERIFY_FINAL		0x0000001c

/*
 * SKS_CMD_FIND_OBJECTS_INIT - Initialize a objects search
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [struct sks_object_head attribs + attributes data]
 * param#1: none
 * param#2: none
 * param#3: none
 *
 * This command relates to the PKCS#11 API function C_FindOjectsInit().
 */
#define SKS_CMD_FIND_OBJECTS_INIT	0x0000001d

/*
 * SKS_CMD_FIND_OBJECTS - Get handles of matching objects
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: none
 * param#2: out-memref : [uint32_t object_handle[max_handles_number]]
 * param#3: none
 *
 * This command relates to the PKCS#11 API function C_FindOjects().
 */
#define SKS_CMD_FIND_OBJECTS		0x0000001e

/*
 * SKS_CMD_FIND_OBJECTS_FINAL - Finalize current objects search
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: none
 * param#2: none
 * param#3: none
 *
 * This command relates to the PKCS#11 API function C_FindOjectsFinal().
 */
#define SKS_CMD_FIND_OBJECTS_FINAL	0x0000001f

/*
 * SKS_CMD_GET_OBJECT_SIZE - Get size used by object in the TEE
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [uint32_t key_handle]
 * param#1: none
 * param#2: out-memref : [uint32_t object_byte_size]
 * param#3: none
 */
#define SKS_CMD_GET_OBJECT_SIZE		0x00000020

/*
 * SKS_CMD_GET_ATTRIBUTE_VALUE - Get the value of object attrbiute(s)
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [uint32_t key_handle]
 *			   [struct sks_object_head attribs + attributes data]
 * param#1: none
 * param#2: out-memref : [struct sks_object_head attribs + attributes data]
 * param#3: none
 */
#define SKS_CMD_GET_ATTRIBUTE_VALUE	0x00000021

/*
 * SKS_CMD_SET_ATTRIBUTE_VALUE - Set the value for object attrbiute(s)
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [uint32_t key_handle]
 *			   [struct sks_object_head attribs + attributes data]
 * param#1: none
 * param#2: out-memref : [struct sks_object_head attribs + attributes data]
 * param#3: none
 */
#define SKS_CMD_SET_ATTRIBUTE_VALUE	0x00000022

/*
 * SKS_CMD_DERIVE_KEY - Create a key by derivation of a provisionned parent key
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 *			   [struct sks_reference proc + proc parameters data]
 *			   [uint32_t key_handle]
 *			   [struct sks_object_head attribs + attributes data]
 * param#1: none
 * param#2: out-memref : [uint32_t object_handle]
 * param#3: none
 */
#define SKS_CMD_DERIVE_KEY		0x00000023

/*
 * Return codes
 */
#define SKS_OK				0x00000000	/* Success */
#define SKS_ERROR			0x00000001	/* Badly failed */
#define SKS_MEMORY			0x00000002	/* Memory exhausted */
#define SKS_BAD_PARAM			0x00000003	/* Incorrect args */
#define SKS_SHORT_BUFFER		0x00000004	/* Buffer too small */
#define SKS_FAILED			0x00000005	/* Nicely failed */
#define SKS_NOT_FOUND			0x00000006	/* Item not found */
#define SKS_VERIFY_FAILED		0x00000007	/* AE verif failed */
/* Errors returned when provided invalid identifiers */
#define SKS_INVALID_ATTRIBUTES		0x00000100	/* Attr do not match */
#define SKS_INVALID_TYPE		0x00000101	/* Type identifier */
#define SKS_INVALID_VALUE		0x00000102	/* Inconsistent value */
#define SKS_INVALID_OBJECT		0x00000103	/* Object handle */
#define SKS_INVALID_KEY			0x00000104	/* Key handle */
#define SKS_INVALID_PROC		0x00000105	/* Processing ID */
#define SKS_INVALID_SESSION		0x00000106	/* Session handle */
#define SKS_INVALID_SLOT		0x00000107	/* Slot id */
#define SKS_INVALID_PROC_PARAM		0x00000108	/* Processing args */
#define SKS_NOT_IMPLEMENTED		0x00000109
/* Report on Pin management */
#define SKS_PIN_INCORRECT		0x00000200	/* Authent. failed */
#define SKS_PIN_LOCKED			0x00000201	/* Authent. is locked */
#define SKS_PIN_EXPIRED			0x00000202	/* PIN to be renewed */
#define SKS_PIN_INVALID			0x00000203	/* PIN update failed */
/* PKCS#11 specific error codes */
#define SKS_CK_SESSION_PENDING		0x00001000
#define SKS_CK_SESSION_IS_READ_ONLY	0x00001001
#define SKS_CK_SO_IS_LOGGED_READ_WRITE	0x00001002
#define SKS_PROCESSING_ACTIVE		0x00001003
#define SKS_CK_NOT_PERMITTED		0x00001004
#define SKS_PROCESSING_INACTIVE		0x00001005

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
