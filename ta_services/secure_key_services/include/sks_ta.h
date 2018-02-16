/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_H__
#define __SKS_TA_H__

#include <sys/types.h>
#include <stdint.h>
#include <util.h>

#define TA_SKS_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
                        { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

#define CK_VENDOR_INVALID_ID		0xffffffff

/*
 * SKS trusted application may recieve requests requesting a number of
 * parameters that may not suit the GPD 4 parameters directives.
 * To factorize the use of GPD parameters for SKS services, the current
 * API uses the 4 GPD invocation parameters as following:
 *
 * - Parameter #0 is not used or is used as an input or in/out memory reference
 *   argument. It refers to the control directives for the invoked service. When several
 *   parameters are to be passed, there are serialized in the single
 *   control buffer.
 *
 *   When caller defines parameter #0 as an in/out memory reference, the
 *   parameter #0 is used to feedback caller with a detailed 32 bit return
 *   code that allow to return more detail error cases than the GPD TEE API
 *   allows a TA to generically return.
 *   This is the purpose of the mark "in(*)-memref" in the command comments below.
 *
 * - Parameter #1 is not used or is an input memory reference. It refers to
 *   the input data provided for the invoked service.
 *
 * - Parameter #2 is not used or is an output memory reference. It refers to
 *   the output buffer expected to be filled with the output data requested
 *   by the caller. These data can be a object handle, a ciphered stream, etc.
 *
 * - Parameter #3 is not used.
 */

/*
 * SKS_CMD_PING		Acknowledge TA presence
 *
 * param#0: none
 * param#1: none
 * param#2: none
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
 */
#define SKS_CMD_CK_SLOT_LIST		0x00000001

/*
 * SKS_CMD_CK_SLOT_INFO - Get cryptoki structured slot information
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [struct sks_ck_slot_info info]
 * param#3: none
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

/* flags (reflect the cryptoki flags) */
#define SKS_TOKEN_HAS_RNG		BIT(0UL)	/* CKF_RNG */
#define SKS_TOKEN_IS_READ_ONLY		BIT(1UL)	/* CKF_WRITE_PROTECTED */
#define SKS_TOKEN_REQUIRE_LOGIN		BIT(2UL)	/* CKF_LOGIN_REQUIRED */
#define SKS_TOKEN_HAS_USER_PIN		BIT(3UL)	/* CKF_USER_PIN_INITIALIZED */
#define SKS_TOKEN_FULLY_RESTORABLE	BIT(4UL)	/* CKF_RESTORE_KEY_NOT_NEEDED */
#define SKS_TOKEN_HAS_CLOCK		BIT(5UL)	/* CKF_CLOCK_ON_TOKEN */
#define SKS_TOKEN_ALT_AUTHENT		BIT(6UL)	/* CKF_PROTECTED_AUTHENTICATION_PATH */
#define SKS_TOKEN_CAN_DUAL_PROC		BIT(7UL)	/* CKF_DUAL_CRYPTO_OPERATIONS */
#define SKS_TOKEN_INITED		BIT(8UL)	/* CKF_TOKEN_INITIALIZED */
#define SKS_TOKEN_USR_PIN_FAILURE	BIT(9UL)	/* CKF_USER_PIN_COUNT_LOW */
#define SKS_TOKEN_USR_PIN_LAST		BIT(10UL)	/* CKF_USER_PIN_FINAL_TRY */
#define SKS_TOKEN_USR_PIN_LOCKED	BIT(11UL)	/* CKF_USER_PIN_LOCKED */
#define SKS_TOKEN_USR_PIN_TO_CHANGE	BIT(12UL)	/* CKF_USER_PIN_TO_BE_CHANGED */
#define SKS_TOKEN_SO_PIN_FAILURE	BIT(13UL)	/* CKF_SO_PIN_COUNT_LOW */
#define SKS_TOKEN_SO_PIN_LAST		BIT(14UL)	/* CKF_SO_PIN_FINAL_TRY */
#define SKS_TOKEN_SO_PIN_LOCKED		BIT(15UL)	/* CKF_SO_PIN_LOCKED */
#define SKS_TOKEN_SO_PIN_TO_CHANGE	BIT(16UL)	/* CKF_SO_PIN_TO_BE_CHANGED */
#define SKS_TOKEN_BAD_STATE		BIT(17UL)	/* CKF_ERROR_STATE */

/*
 * SKS_CMD_CK_MECHANISM_IDS - Get list of the supported mechanisms
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [struct sks_ck_mecha_id mecha_ids[N]]
 * param#3: none
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
 */
#define SKS_CMD_CK_MECHANISM_INFO	0x00000005

struct sks_ck_mecha_info {
    uint32_t    min_key_size;
    uint32_t    max_key_size;
    uint32_t    flags;
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
 */
#define SKS_CMD_CK_SET_PIN		0x00000008

/*
 * SKS_CMD_CK_OPEN_RO_SESSION - Open Read-only Session
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [uint32_t session_handle]
 * param#3: none
 */
#define SKS_CMD_CK_OPEN_RO_SESSION	0x00000009

/*
 * SKS_CMD_CK_OPEN_RW_SESSION - Open Read/Write Session
 *
 * param#0: in(*)-memref : [uint32_t slot_id]
 * param#1: none
 * param#2: out-memref : [uint32_t session_handle]
 * param#3: none
 */
#define SKS_CMD_CK_OPEN_RW_SESSION	0x0000000a

/*
 * SKS_CMD_CK_CLOSE_SESSION - Open Read/Write Session
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: none
 * param#2: none
 * param#3: none
 */
#define SKS_CMD_CK_CLOSE_SESSION	0x0000000b

/*
 * SKS_CMD_CK_SESSION_INFO - Get Cryptoki information on a session
 *
 * param#0: in(*)-memref : [uint32_t session_handle]
 * param#1: none
 * param#2: out-memref : [struct sks_ck_session_info]
 * param#3: none
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
 * fields:
 * - the 32bit identificator of the attribute
 * - the 32bit value attribute byte size
 * - the effective value of the attribute (variable size)
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
 */
#define SKS_CMD_GENERATE_SYMM_KEY	0x00000016

/*
 * Return codes
 */
#define SKS_OK				0x00000000	/* Success */
#define SKS_ERROR			0x00000001	/* Bad failure */
#define SKS_MEMORY			0x00000002	/* Memory exhausted */
#define SKS_BAD_PARAM			0x00000003	/* incorrect arg */
#define SKS_SHORT_BUFFER		0x00000004	/* Give a bigger buf */
#define SKS_FAILED			0x00000005	/* Nicely failed */
#define SKS_NOT_FOUND			0x00000006	/* Item not found */
/* Errors returned when provided invalid identifiers */
#define SKS_INVALID_ATTRIBUTES		0x00000100	/* Attr do not match */
#define SKS_INVALID_TYPE		0x00000101	/* type identifier */
#define SKS_INVALID_VALUE		0x00000102	/* inconsistent value */
#define SKS_INVALID_OBJECT		0x00000103	/* object handle */
#define SKS_INVALID_KEY			0x00000104	/* key handle */
#define SKS_INVALID_PROC		0x00000105	/* processing ID (mechanism) */
#define SKS_INVALID_SESSION		0x00000106	/* session handle */
#define SKS_INVALID_SLOT		0x00000107	/* slot id */
#define SKS_INVALID_PROC_PARAM		0x00000108	/* processing parameters */

/* Report on Pin management */
#define SKS_PIN_INCORRECT		0x00000200
#define SKS_PIN_LOCKED			0x00000201
#define SKS_PIN_EXPIRED			0x00000202
#define SKS_PIN_INVALID			0x00000203
/* PKCS#11 specifc error codes */
#define SKS_CK_SESSION_PENDING		0x00001000
#define SKS_CK_SESSION_IS_READ_ONLY	0x00001001
#define SKS_CK_SO_IS_LOGGED_READ_WRITE	0x00001002
#define SKS_PROCESSING_ACTIVE		0x00001003
#define SKS_CK_NOT_PERMITTED		0x00001004	/* SKS_NOT_PERMITED? */
#define SKS_PROCESSING_INACTIVE		0x00001005
#define SKS_BAD_PROCESSING_PARAM	0x00001006

/* Attribute specifc values */
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
#define SKS_PERSISTENT_SHIFT		0UL	/* Equiv for pkcs11 CKA_TOKEN */
#define SKS_NEED_AUTHEN_SHIFT		1UL	/* Equiv for pkcs11 CKA_PRIVATE */
#define SKS_TRUSTED_SHIFT		3UL	/* Equiv for pkcs11 CKA_TRUSTED */
#define SKS_SENSITIVE_SHIFT		4UL	/* Equiv for pkcs11 CKA_SENSITIVE */
#define SKS_ENCRYPT_SHIFT		5UL	/* Equiv for pkcs11 CKA_ENCRYPT */
#define SKS_DECRYPT_SHIFT		6UL	/* Equiv for pkcs11 CKA_DECRYPT */
#define SKS_WRAP_SHIFT			7UL	/* Equiv for pkcs11 CKA_WRAP */
#define SKS_UNWRAP_SHIFT		8UL	/* Equiv for pkcs11 CKA_UNWRAP */
#define SKS_SIGN_SHIFT			9UL	/* Equiv for pkcs11 CKA_SIGN */
#define SKS_SIGN_RECOVER_SHIFT		10UL	/* Equiv for pkcs11 CKA_SIGN_RECOVER */
#define SKS_VERIFY_SHIFT		11UL	/* Equiv for pkcs11 CKA_VERIFY */
#define SKS_VERIFY_RECOVER_SHIFT	12UL	/* Equiv for pkcs11 CKA_VERIFY_RECOVER */
#define SKS_DERIVE_SHIFT		13UL	/* Equiv for pkcs11 CKA_DERIVE */
#define SKS_EXTRACTABLE_SHIFT		14UL	/* Equiv for pkcs11 CKA_EXTRACTABLE */
#define SKS_LOCALLY_GENERATED_SHIFT	15UL	/* Equiv for pkcs11 CKA_LOCAL */
#define SKS_NEVER_EXTRACTABLE_SHIFT	16UL	/* Equiv for pkcs11 CKA_NEVER_EXTRACTABLE */
#define SKS_ALWAYS_SENSITIVE_SHIFT	17UL	/* Equiv for pkcs11 CKA_ALWAYS_SENSITIVE */
#define SKS_MODIFIABLE_SHIFT		18UL	/* Equiv for pkcs11 CKA_MODIFIABLE */
#define SKS_COPYABLE_SHIFT		19UL	/* Equiv for pkcs11 CKA_COPYABLE */
#define SKS_DESTROYABLE_SHIFT		20UL	/* Equiv for pkcs11 CKA_DESTROYABLE */
#define SKS_ALWAYS_AUTHEN_SHIFT		21UL	/* Equiv for pkcs11 CKA_ALWAYS_AUTHENTICATE */
#define SKS_WRAP_FROM_TRUSTED_SHIFT	22UL	/* Equiv for pkcs11 CKA_WRAP_WITH_TRUSTED */
#define SKS_BOOLPROP_LAST_SHIFT		22UL

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
#define SKS_LABEL			0x00000000	/* Object identifying label */
#define SKS_VALUE			0x00000001	/* Object value */
#define SKS_VALUE_LEN			0x00000002	/* Size of object value (???) */
#define SKS_WRAP_ATTRIBS		0x00000003	/* Attribute list */
#define SKS_UNWRAP_ATTRIBS		0x00000004	/* Attribute list */
#define SKS_DERIVE_ATTRIBS		0x00000005	/* Attribute list */
#define SKS_ACTIVATION_DATE		0x00000006	/* UTC time */
#define SKS_REVOKATION_DATE		0x00000007	/* UTC time */
#define SKS_OBJECT_ID			0x00000008	/* pkcs#11 CKA_OBJECT_ID */
#define SKS_APPLICATION_ID		0x00000009	/* pkcs#11 CKA_APPLICATION */
#define SKS_PROCESSING_ID		0x0000000a	/* CKA_MECHANISM_TYPE */
#define SKS_KEY_ID			0x0000000b	/* pkcs#11 CKA_ID */
#define SKS_ALLOWED_PROCESSINGS		0x0000000c	/* pkcs#11 CKA_ALLOWED_MECHANISM */

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
#define SKS_OBJ_SYM_KEY				0 // TODO rename SKS_SYMMETRIC_KEY
#define SKS_OBJ_PUB_KEY				1 // TODO rename SKS_PUBLIC_KEY
#define SKS_OBJ_PRIV_KEY			2 // TODO rename SKS_PRIVATE_KEY
#define SKS_OBJ_OTP_KEY				3 // TODO rename SKS_OTP_KEY
#define SKS_OBJ_CERTIFICATE			4 // TODO rename SKS_CERTIFICATE
#define SKS_OBJ_RAW_DATA			5 // TODO rename SKS_RAW_DATA
#define SKS_OBJ_CK_DOMAIN_PARAMS		6 // TODO rename SKS_CK_DOMAIN_PARAMS
#define SKS_OBJ_CK_HW_FEATURES			7 // TODO rename SKS_CK_HW_FEATURES
#define SKS_OBJ_CK_MECHANISM			8 // TODO rename SKS_MECHANISM

/*
 * SKS supported types for SKS_OBJ_SYM_KEY
 * TODO: other key types...
 */
#define SKS_KEY_AES				0
#define SKS_GENERIC_SECRET			1

/*
 * SKS supported type for SKS_OBJ_CK_MECHANISM
 * TODO: other than AES...
 */
#define SKS_PROC_AES_ECB_NOPAD			0	/* NIST AES ECB (See PKCS#11 2.40-e01) */
#define SKS_PROC_AES_CBC_NOPAD			1	/* NIST AES CBC (See PKCS#11 2.40-e01) */
#define SKS_PROC_AES_CBC_PAD			2	/* NIST AES CBC with PKCS#7 padding (See PKCS#11 2.40-e01)*/
#define SKS_PROC_AES_CTS			3	/* NIST AES CBC with CTS (See PKCS#11 2.40-e01) */
#define SKS_PROC_AES_CTR			4	/* NIST AES with Counter (CTR) (See PKCS#11 2.40-e01)*/
#define SKS_PROC_AES_GCM			5	/* NIST AES GCM (See PKCS#11 2.40-e01) */
#define SKS_PROC_AES_CCM			6	/* NIST AES CCM [RFC3610]. (See PKCS#11 2.40-e01) */
#define SKS_PROC_AES_GMAC			7	/* NIST AES GCM with AAD authen only (See PKCS#11 2.40-e01) */
#define SKS_PROC_AES_CMAC			8	/* AES Block aligned CMAC */
#define SKS_PROC_AES_CMAC_GENERAL		9	/* Any sized AES CMAC */
#define SKS_PROC_AES_DERIVE_BY_ECB		10	/* Generate key by data AES ECB ciphering */
#define SKS_PROC_AES_DERIVE_BY_CBC		11	/* Generate key by data AES CBC ciphering */
#define SKS_PROC_AES_GENERATE			12	/* Generate key CKM_AES_KEY_GEN */
#define SKS_PROC_GENERIC_GENERATE		13	/* CKM_GENERIC_SECRET_KEY_GEN */
#define SKS_PROC_RAW_IMPORT			14	/* Not exported to TA API */
#define SKS_PROC_RAW_COPY			15	/* Not exported to TA API */

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
 *		32bit size = 0
 *
 * AES CBC, CBC_NOPAD and CTS
 *   head:	32bit type = SKS_PROC_AES_CBC
 *			  or SKS_PROC_AES_CBC_NOPAD
 *			  or SKS_PROC_AES_CTS
 *		32bit size = 16
 *  params:	16byte inivial vector
 *
 * AES CTR
 *   head:	32bit type = SKS_PROC_AES_CTR
 *		32bit size = 20
 *  params:	32bit counter bit increment
 *		16byte inivial vector
 *
 * AES GCM
 *   head:	32bit type = SKS_PROC_AES_GCM
 *		32bit size
 *  params:	32bit IV_byte_size
 *		byte array: IV data (IV_byte_size bytes)
 *		32bit IV_bit_size
 *		32bit AAD_byte_size
 *		byte array: AAD data (AAD_byte_size bytes)
 *		32bit tag byte size
 *
 * AES CCM
 *   head:	32bit type = SKS_PROC_AES_CCM
 *		32bit size
 *  params:	32bit data_byte_size
 *		32bit nonce_byte_size
 *		byte array: nonce data (nonce_byte_size bytes)
 *		32bit AAD_byte_size
 *		byte array: AAD data (AAD_byte_size bytes)
 *		32bit MAC byte size
 *
 * AES GMAC
 *   head:	32bit type = SKS_PROC_AES_GMAC
 *		32bit size = 12
 *  params:	12byte initial vector

 * AES CMAC with general length
 *   head:	32bit type = SKS_PROC_AES_CMAC_GENERAL
 *		32bit size = 12
 *  params:	32bit byte size of the output CMAC data
 *
 * AES CMAC fixed size (16byte CMAC)
 *   head:	32bit type = SKS_PROC_AES_CMAC_GENERAL
 *		32bit size = 0
 *
 * AES derive by ECB
 *   head:	32bit type = SKS_PROC_AES_DERIVE_BY_ECB
 *		32bit size
 *  params:	32bit byte size of the data to encrypt
 *		byte array: data to encrypt
 *
 * AES derive by CBC
 *   head:	32bit type = SKS_PROC_AES_DERIVE_BY_CBC
 *		32bit size
 *  params:	16byte inivial vector
 *		32bit byte size of the data to encrypt
 *		byte array: data to encrypt
 *
 * AES and generic secret generation
 *   head:	32bit type = SKS_PROC_AES_GENERATE
 *			  or SKS_PROC_GENERIC_GENERATE
 *		32bit size = 0
 */

#endif /* __SKS_TA_H */
