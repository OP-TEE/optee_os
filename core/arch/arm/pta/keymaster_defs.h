/*
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef KEYMASTER_DEFS_H_
#define KEYMASTER_DEFS_H_

typedef struct {
	uint8_t *data;
	size_t data_length;
} keymaster_blob_t;

/**
 * Structures and enums have been taken from keymaster_defs.h
 */
typedef enum {
	KM_INVALID = (int)0u << 28, /* Invalid type, used to designate a tag as uninitialized */
	KM_ENUM = (int)1u << 28,
	KM_ENUM_REP = (int)2u << 28, /* Repeatable enumeration value. */
	KM_UINT = (int)3u << 28,
	KM_UINT_REP = (int)4u << 28, /* Repeatable integer value */
	KM_ULONG = (int)5u << 28,
	KM_DATE = (int)6u << 28,
	KM_BOOL = (int)7u << 28,
	KM_BIGNUM = (int)(8u << 28),
	KM_BYTES = (int)(9u << 28),
	KM_ULONG_REP = (int)(10u << 28), /* Repeatable long value */
} keymaster_tag_type_t;

typedef enum {
	KM_TAG_INVALID = KM_INVALID | 0,
	/*
	 * Tags that must be semantically enforced by hardware and software
	 * implementations.
	 */
	/* Crypto parameters */
	KM_TAG_PURPOSE = KM_ENUM_REP | 1,    /* keymaster_purpose_t. */
	KM_TAG_ALGORITHM = KM_ENUM | 2,      /* keymaster_algorithm_t. */
	KM_TAG_KEY_SIZE = KM_UINT | 3,       /* Key size in bits. */
	KM_TAG_BLOCK_MODE = KM_ENUM_REP | 4, /* keymaster_block_mode_t. */
	KM_TAG_DIGEST = KM_ENUM_REP | 5,     /* keymaster_digest_t. */
	KM_TAG_PADDING = KM_ENUM_REP | 6,    /* keymaster_padding_t. */
	KM_TAG_CALLER_NONCE = KM_BOOL | 7,   /* Allow caller to specify nonce or
					      * IV.
					      */
	KM_TAG_MIN_MAC_LENGTH = KM_UINT | 8, /* Minimum length of MAC or AEAD
					      * authentication tag in bits.
					      */
	KM_TAG_KDF = KM_ENUM_REP | 9,        /* keymaster_kdf_t (keymaster2) */
	KM_TAG_EC_CURVE = KM_ENUM | 10,      /* keymaster_ec_curve_t (keymaster2) */
	/* Algorithm-specific. */
	KM_TAG_RSA_PUBLIC_EXPONENT = KM_ULONG | 200,
	KM_TAG_ECIES_SINGLE_HASH_MODE = KM_BOOL | 201, /* Whether the ephemeral
							* public key is fed into
							* the KDF
							*/
	KM_TAG_INCLUDE_UNIQUE_ID = KM_BOOL | 202,      /* If true, attestation
							* certificates for this
							* key will contain an
							* application-scoped
							* and time-bounded
							* device-unique ID.
							* (keymaster2)
							*/
	/* Other hardware-enforced. */
	KM_TAG_BLOB_USAGE_REQUIREMENTS = KM_ENUM | 301, /* keymaster_key_blob_usage_requirements_t */
	KM_TAG_BOOTLOADER_ONLY = KM_BOOL | 302,         /* Usable only by
							 * bootloader
							 */
	/*
	 * Tags that should be semantically enforced by hardware if possible and
	 * will otherwise be enforced by software (keystore).
	 */
	/* Key validity period */
	KM_TAG_ACTIVE_DATETIME = KM_DATE | 400,             /* Start of validity */
	KM_TAG_ORIGINATION_EXPIRE_DATETIME = KM_DATE | 401, /* Date when new
							     * "messages" should
							     * no longer be
							     * created.
							     */
	KM_TAG_USAGE_EXPIRE_DATETIME = KM_DATE | 402,       /* Date when
							     * existing
							     * "messages"
							     * should no longer
							     * be trusted.
							     */
	KM_TAG_MIN_SECONDS_BETWEEN_OPS = KM_UINT | 403,     /* Minimum elapsed
							     * time between
							     * cryptographic
							     * operations with
							     * the key.
							     */
	KM_TAG_MAX_USES_PER_BOOT = KM_UINT | 404,           /* Number of times
							     * the key can be
							     * used per boot.
							     */
	/* User authentication */
	KM_TAG_ALL_USERS = KM_BOOL | 500,           /* Reserved for future use
						     * -- ignore
						     */
	KM_TAG_USER_ID = KM_UINT | 501,             /* Reserved for future use
						     * -- ignore
						     */
	KM_TAG_USER_SECURE_ID = KM_ULONG_REP | 502, /* Secure ID of authorized
						     * user or authenticator(s).
						     * Disallowed if
						     * KM_TAG_ALL_USERS or
						     * KM_TAG_NO_AUTH_REQUIRED
						     * is present.
						     */
	KM_TAG_NO_AUTH_REQUIRED = KM_BOOL | 503,    /* If key is usable without
						     * authentication.
						     */
	KM_TAG_USER_AUTH_TYPE = KM_ENUM | 504,      /* Bitmask of authenticator
						     * types allowed when
						     * KM_TAG_USER_SECURE_ID
						     * contains a secure user
						     * ID, rather than a secure
						     * authenticator ID.
						     * Defined in
						     * hw_authenticator_type_t
						     * in hw_auth_token.h.
						     */
	KM_TAG_AUTH_TIMEOUT = KM_UINT | 505,        /* Required freshness of
						     * user authentication for
						     * private/secret key
						     * operations, in seconds.
						     * Public key operations
						     * require no
						     * authentication. If absent
						     * , authentication is
						     * required for every use.
						     * Authentication state is
						     * lost when the device is
						     * powered off.
						     */
	KM_TAG_ALLOW_WHILE_ON_BODY = KM_BOOL | 506, /* Allow key to be used
						     * after authentication
						     * timeout if device is
						     * still on-body (requires
						     * secure on-body sensor.
						     */
	/* Application access control */
	KM_TAG_ALL_APPLICATIONS = KM_BOOL | 600, /* Specified to indicate key
						  * is usable by all
						  * applications.
						  */
	KM_TAG_APPLICATION_ID = KM_BYTES | 601,  /* Byte string identifying the
						  * authorized application.
						  */
	KM_TAG_EXPORTABLE = KM_BOOL | 602,       /* If true, private/secret key
						  * can be exported, but only if
						  * all access control
						  * requirements for use are
						  * met. (keymaster2)
						  */
	/*
	 * Semantically unenforceable tags, either because they have no specific
	 * meaning or because they're informational only.
	 */
	KM_TAG_APPLICATION_DATA = KM_BYTES | 700,      /* Data provided by
							* authorized application
							*/
	KM_TAG_CREATION_DATETIME = KM_DATE | 701,      /* Key creation time */
	KM_TAG_ORIGIN = KM_ENUM | 702,                 /* keymaster_key_origin_t */
	KM_TAG_ROLLBACK_RESISTANT = KM_BOOL | 703,     /* Whether key is
							* rollback-resistant.
							*/
	KM_TAG_ROOT_OF_TRUST = KM_BYTES | 704,         /* Root of trust ID. */
	KM_TAG_OS_VERSION = KM_UINT | 705,             /* Version of system
							* (keymaster2)
							*/
	KM_TAG_OS_PATCHLEVEL = KM_UINT | 706,          /* Patch level of system
							* (keymaster2)
							*/
	KM_TAG_UNIQUE_ID = KM_BYTES | 707,             /* Used to provide unique
							* ID in attestation
							*/
	KM_TAG_ATTESTATION_CHALLENGE = KM_BYTES | 708, /* Used to provide
							* challenge in
							* attestation
							*/
	KM_TAG_ATTESTATION_APPLICATION_ID = KM_BYTES | 709, /* Used to identify
							     * the set of
							     * possible
							     * applications of
							     * which one has
							     * initiated a  key
							     * attestation
							     */
	/* Tags used only to provide data to or receive data from operations */
	KM_TAG_ASSOCIATED_DATA = KM_BYTES | 1000, /* Used to provide associated
						   * data for AEAD modes.
						   */
	KM_TAG_NONCE = KM_BYTES | 1001,           /* Nonce or Initialization
						   * Vector
						   */
	KM_TAG_AUTH_TOKEN = KM_BYTES | 1002,      /* Authentication token that
						   * proves secure user
						   * authentication has been
						   * performed. Structure
						   * defined in hw_auth_token_t
						   * in hw_auth_token.h.
						   */
	KM_TAG_MAC_LENGTH = KM_UINT | 1003,       /* MAC or AEAD authentication
						   * tag length in bits.
						   */
	KM_TAG_RESET_SINCE_ID_ROTATION = KM_BOOL | 1004, /* Whether the device
							  * has beeen factory
							  * reset since the last
							  * unique ID rotation.
							  * Used for key
							  * attestation.
							  */
} keymaster_tag_t;

typedef struct {
	keymaster_tag_t tag;
	union {
		uint32_t enumerated;   /* KM_ENUM and KM_ENUM_REP */
		bool boolean;          /* KM_BOOL */
		uint32_t integer;      /* KM_INT and KM_INT_REP */
		uint64_t long_integer; /* KM_LONG */
		uint64_t date_time;    /* KM_DATE */
		keymaster_blob_t blob; /* KM_BIGNUM and KM_BYTES*/
	} key_param;
} keymaster_key_param_t;

typedef struct {
	keymaster_key_param_t *params;
	size_t length;
} keymaster_key_param_set_t;

typedef struct {
	keymaster_key_param_set_t hw_enforced;
	keymaster_key_param_set_t sw_enforced;
} keymaster_key_characteristics_t;

/**
 * Possible purposes of a key (or pair).
 */
typedef enum {
	KM_PURPOSE_ENCRYPT = 0,    /* Usable with RSA, EC and AES keys. */
	KM_PURPOSE_DECRYPT = 1,    /* Usable with RSA, EC and AES keys. */
	KM_PURPOSE_SIGN = 2,       /* Usable with RSA, EC and HMAC keys. */
	KM_PURPOSE_VERIFY = 3,     /* Usable with RSA, EC and HMAC keys. */
	KM_PURPOSE_DERIVE_KEY = 4, /* Usable with EC keys. */
} keymaster_purpose_t;

/**
 * Digests provided by keymaster implementations.
 */
typedef enum {
	KM_DIGEST_NONE = 0,
	KM_DIGEST_MD5 = 1, /* Optional, may not be implemented in hardware, will
			    * be handled in software if needed.
			    */
	KM_DIGEST_SHA1 = 2,
	KM_DIGEST_SHA_2_224 = 3,
	KM_DIGEST_SHA_2_256 = 4,
	KM_DIGEST_SHA_2_384 = 5,
	KM_DIGEST_SHA_2_512 = 6,
} keymaster_digest_t;

typedef enum {
	KM_PAD_NONE = 1, /* deprecated */
	KM_PAD_RSA_OAEP = 2,
	KM_PAD_RSA_PSS = 3,
	KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4,
	KM_PAD_RSA_PKCS1_1_5_SIGN = 5,
	KM_PAD_PKCS7 = 64,
} keymaster_padding_t;

#endif /* KEYMASTER_DEFS_H_ */
