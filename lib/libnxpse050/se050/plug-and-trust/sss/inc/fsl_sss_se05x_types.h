/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_APIS_INC_FSL_SSS_SE05X_TYPES_H_
#define SSS_APIS_INC_FSL_SSS_SE05X_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sss_api.h>
#include <fsl_sss_policy.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
#include "nxScp03_Types.h"
#include "se05x_const.h"
#include "se05x_tlv.h"
#include "sm_api.h"
#if (__GNUC__ && !AX_EMBEDDED)
#include <pthread.h>
/* Only for base session with os */
#endif

/*!
 * @addtogroup sss_sw_se05x
 * @{
 */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/** Are we using SE05X as crypto subsystem? */
#define SSS_SUBSYSTEM_TYPE_IS_SE05X(subsystem) (subsystem == kType_SSS_SE_SE05x)

/** Are we using SE05X as crypto subsystem? */
#define SSS_SESSION_TYPE_IS_SE05X(session) (session && SSS_SUBSYSTEM_TYPE_IS_SE05X(session->subsystem))

/** Are we using SE05X as crypto subsystem? */
#define SSS_KEY_STORE_TYPE_IS_SE05X(keyStore) (keyStore && SSS_SESSION_TYPE_IS_SE05X(keyStore->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_OBJECT_TYPE_IS_SE05X(pObject) (pObject && SSS_KEY_STORE_TYPE_IS_SE05X(pObject->keyStore))

/** Are we using SE05X as crypto subsystem? */
#define SSS_ASYMMETRIC_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_DERIVE_KEY_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_SYMMETRIC_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_MAC_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_RNG_CONTEXT_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_DIGEST_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_AEAD_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_TUNNEL_CONTEXT_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/** Are we using SE05X as crypto subsystem? */
#define SSS_TUNNEL_TYPE_IS_SE05X(context) (context && SSS_SESSION_TYPE_IS_SE05X(context->session))

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

struct _sss_se05x_session;

/** @copydoc sss_tunnel_t */
typedef struct _sss_se05x_tunnel_context
{
    /** Pointer to the base SE050 SEssion */
    struct _sss_se05x_session *se05x_session;
    /** Where exectly this tunner terminate to */
    sss_tunnel_dest_t tunnelDest;
#if (__GNUC__ && !AX_EMBEDDED)
    /** For systems where we potentially have multi-threaded operations, have a lock */
    pthread_mutex_t channelLock;
#endif
} sss_se05x_tunnel_context_t;

/** @copydoc sss_session_t */
typedef struct _sss_se05x_session
{
    /** Indicates which security subsystem is selected to be used. */
    sss_type_t subsystem;

    /** Connection context to SE050 */

    Se05xSession_t s_ctx;

    /** In case connection is tunneled, context to the tunnel */

    sss_se05x_tunnel_context_t *ptun_ctx;
} sss_se05x_session_t;

struct _sss_se05x_object;

/** @copydoc sss_key_store_t */
typedef struct
{
    /** Pointer to the session */
    sss_se05x_session_t *session;
    /** In case the we are using Key Wrapping while injecting the keys, pointer to key used for wrapping */
    struct _sss_se05x_object *kekKey;

} sss_se05x_key_store_t;

/** @copydoc sss_object_t */
typedef struct _sss_se05x_object
{
    /** key store holding the data and other properties */
    sss_se05x_key_store_t *keyStore;
    /** @copydoc sss_object_t::objectType */
    uint32_t objectType;
    /** @copydoc sss_object_t::cipherType */
    uint32_t cipherType;
    /** Application specific key identifier. The keyId is kept in the key  store
     * along with the key data and other properties. */
    uint32_t keyId;

    /** If this is an ECC Key, the Curve ID of the key */
#if APPLET_SE050_VER_MAJOR_MINOR >= 20000u
    SE05x_ECCurve_t curve_id;
#else
    uint32_t curve_id;
#endif

    /** Whether this is a persistant or tansient object */
    uint8_t isPersistant : 1;

} sss_se05x_object_t;

/** @copydoc sss_derive_key_t */
typedef struct
{
    /** @copydoc sss_derive_key_t::session */
    sss_se05x_session_t *session;
    /** @copydoc sss_derive_key_t::keyObject */
    sss_se05x_object_t *keyObject;
    /** @copydoc sss_derive_key_t::algorithm */
    sss_algorithm_t algorithm;
    /** @copydoc sss_derive_key_t::mode */
    sss_mode_t mode;

} sss_se05x_derive_key_t;

/** @copydoc sss_asymmetric_t */
typedef struct
{
    /** @copydoc sss_asymmetric_t::session */
    sss_se05x_session_t *session;
    /** @copydoc sss_asymmetric_t::keyObject */
    sss_se05x_object_t *keyObject;
    /** @copydoc sss_asymmetric_t::algorithm */
    sss_algorithm_t algorithm;
    /** @copydoc sss_asymmetric_t::mode */
    sss_mode_t mode;

} sss_se05x_asymmetric_t;

/** @copydoc sss_symmetric_t */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_se05x_session_t *session;
    /** Reference to key and it's properties. */
    sss_se05x_object_t *keyObject;
    /** @copydoc sss_symmetric_t::algorithm */
    sss_algorithm_t algorithm;
    /** @copydoc sss_symmetric_t::mode */
    sss_mode_t mode;

    /* Implementation specific part */

    /** Used crypto object ID for this operation */
    SE05x_CryptoObjectID_t cryptoObjectId;
    /** Since underlying system conly only process in fixed chunks, chache them on host
     * to complete the operation sanely */
    uint8_t cache_data[16];
    /** Length of bytes cached on host */
    size_t cache_data_len;
} sss_se05x_symmetric_t;

/** @copydoc sss_mac_t */
typedef struct
{
    /** copydoc sss_mac_t::session */
    sss_se05x_session_t *session;
    /** copydoc sss_mac_t::keyObject */
    sss_se05x_object_t *keyObject;

    /** copydoc sss_mac_t::algorithm */
    sss_algorithm_t algorithm;
    /** copydoc sss_mac_t::mode */
    sss_mode_t mode;
    /* Implementation specific part */

    /** Used crypto object ID for this operation */
    SE05x_CryptoObjectID_t cryptoObjectId;
} sss_se05x_mac_t;

/** @copydoc sss_aead_t */
typedef struct
{
    /** @copydoc sss_aead_t::session */
    sss_se05x_session_t *session;
    /** @copydoc sss_aead_t::keyObject */
    sss_se05x_object_t *keyObject;
    /** @copydoc sss_aead_t::algorithm */
    sss_algorithm_t algorithm;
    /** @copydoc sss_aead_t::mode */
    sss_mode_t mode;

    /** Implementation specific part */
    SE05x_CryptoObjectID_t cryptoObjectId;
    /** Cache in case of un-alined inputs */
    uint8_t cache_data[16];
    /** How much we have cached  */
    size_t cache_data_len;
} sss_se05x_aead_t;

/** @copydoc sss_digest_t */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_se05x_session_t *session;
    /** @copydoc sss_digest_t::algorithm */
    sss_algorithm_t algorithm;
    /** @copydoc sss_digest_t::mode */
    sss_mode_t mode;
    /** @copydoc sss_digest_t::digestFullLen */
    size_t digestFullLen;
    /** Implementation specific part */

    SE05x_CryptoObjectID_t cryptoObjectId;
} sss_se05x_digest_t;

/** @copydoc sss_rng_context_t */
typedef struct
{
    /** @copydoc sss_rng_context_t::session */
    sss_se05x_session_t *session;
} sss_se05x_rng_context_t;

/** SE050 Properties that can be represented as an array */
typedef enum
{
    kSSS_SE05x_SessionProp_CertUID = kSSS_SessionProp_au8_Proprietary_Start + 1,
} sss_s05x_sesion_prop_au8_t;

/** SE050 Properties that can be represented as 32bit numbers */
typedef enum
{
    kSSS_SE05x_SessionProp_CertUIDLen = kSSS_SessionProp_u32_Optional_Start + 1,
} sss_s05x_sesion_prop_u32_t;

/** deprecated : Used only for backwards compatibility */
#define SE05x_Connect_Ctx_t SE_Connect_Ctx_t
/** deprecated : Used only for backwards compatibility */
#define se05x_auth_context_t SE_Connect_Ctx_t

/** Used to enable Applet Features via ``sss_se05x_set_feature`` */
typedef struct
{
    /** Use of curve TPM_ECC_BN_P256 */
    uint8_t AppletConfig_ECDAA : 1;
    /** EC DSA and DH support */
    uint8_t AppletConfig_ECDSA_ECDH_ECDHE : 1;
    /** Use of curve RESERVED_ID_ECC_ED_25519 */
    uint8_t AppletConfig_EDDSA : 1;
    /** Use of curve RESERVED_ID_ECC_MONT_DH_25519 */
    uint8_t AppletConfig_DH_MONT : 1;
    /** Writing HMACKey objects */
    uint8_t AppletConfig_HMAC : 1;
    /** Writing RSAKey objects */
    uint8_t AppletConfig_RSA_PLAIN : 1;
    /** Writing RSAKey objects */
    uint8_t AppletConfig_RSA_CRT : 1;
    /** Writing AESKey objects */
    uint8_t AppletConfig_AES : 1;
    /** Writing DESKey objects */
    uint8_t AppletConfig_DES : 1;
    /** PBKDF2 */
    uint8_t AppletConfig_PBKDF : 1;
    /** TLS Handshake support commands (see 4.16) in APDU Spec*/
    uint8_t AppletConfig_TLS : 1;
    /** Mifare DESFire support (see 4.15)  in APDU Spec*/
    uint8_t AppletConfig_MIFARE : 1;
    /** Allocated value undefined and reserved for future use */
    uint8_t AppletConfig_RFU1 : 1;
    /** I2C Master support (see 4.17)  in APDU Spec*/
    uint8_t AppletConfig_I2CM : 1;
    /** RFU */
    uint8_t AppletConfig_RFU21 : 1;
} SE05x_Applet_Feature_t;

/** Used to disable Applet Features via ``sss_se05x_set_feature`` */
typedef struct
{
    /** Disable feature ECDH B2b8 */
    uint8_t EXTCFG_FORBID_ECDH : 1;
    /** Disable feature ECDAA B2b7 */
    uint8_t EXTCFG_FORBID_ECDAA : 1;
    /** Disable feature RSA_LT_2K B6b8 */
    uint8_t EXTCFG_FORBID_RSA_LT_2K : 1;
    /** Disable feature RSA_SHA1 B6b7 */
    uint8_t EXTCFG_FORBID_RSA_SHA1 : 1;
    /** Disable feature AES_GCM B8b8 */
    uint8_t EXTCFG_FORBID_AES_GCM : 1;
    /** Disable feature AES_GCM_EXT_IV B8b7 */
    uint8_t EXTCFG_FORBID_AES_GCM_EXT_IV : 1;
    /** Disable feature HKDF_EXTRACT B10b7 */
    uint8_t EXTCFG_FORBID_HKDF_EXTRACT : 1;
} SE05x_Applet_Feature_Disable_t;

/** Attestation data */
typedef struct
{
    /** Random used during attestation */
    uint8_t outrandom[16];
    /** length of outrandom */
    size_t outrandomLen;
    /** time stamp */
    SE05x_TimeStamp_t timeStamp;
    /** Length of timeStamp */
    size_t timeStampLen;
    /** Uinquie ID of SE050 */
    uint8_t chipId[SE050_MODULE_UNIQUE_ID_LEN];
    /** Lenght of the Unique ID */
    size_t chipIdLen;
    /** Attributes */
    uint8_t attribute[MAX_POLICY_BUFFER_SIZE + 15];
    /** Length of Attribute */
    size_t attributeLen;
    /** Signature for attestation */
    uint8_t signature[256];
    /** Lenght of signature */
    size_t signatureLen;
} sss_se05x_attst_comp_data_t;

/** Data to be read with attestation */
typedef struct
{
    /** Whle reading RSA Objects, modulus and public exporent get attested separately, */
    sss_se05x_attst_comp_data_t data[SE05X_MAX_ATTST_DATA];
    /** How many entries to attest */
    uint8_t valid_number;
} sss_se05x_attst_data_t;

/** @} */

/** @addtogroup se050_i2cm
 *
 * @{ */

/** Types of entries in an I2CM Transaction */
typedef enum
{
    /** Do nothing */
    kSE05x_I2CM_None = 0,
    /** Configure the address, baudrate  */
    kSE05x_I2CM_Configure,
    /** Write to I2C Slave  */
    kSE05x_I2CM_Write = 3,
    /** Read from I2C Slave  */
    kSE05x_I2CM_Read,

    /** Response from SE05x that there is something wrong */
    kSE05x_I2CM_StructuralIssue = 0xFF
} SE05x_I2CM_TLV_type_t;

/** Status of I2CM Transaction */
typedef enum
{
    kSE05x_I2CM_Success               = 0x5A,
    kSE05x_I2CM_I2C_Nack_Fail         = 0x01,
    kSE05x_I2CM_I2C_Write_Error       = 0x02,
    kSE05x_I2CM_I2C_Read_Error        = 0x03,
    kSE05x_I2CM_I2C_Time_Out_Error    = 0x05,
    kSE05x_I2CM_Invalid_Tag           = 0x11,
    kSE05x_I2CM_Invalid_Length        = 0x12,
    kSE05x_I2CM_Invalid_Length_Encode = 0x13,
    kSE05x_I2CM_I2C_Config            = 0x21
} SE05x_I2CM_status_t;

/** Additional operation on data read by I2C */
typedef enum
{
    kSE05x_Security_None = 0,
    kSE05x_Sign_Request,
    kSE05x_Sign_Enc_Request,
} SE05x_I2CM_securityReq_t;

/** Configuration for I2CM */
typedef enum
{
    kSE05x_I2CM_Baud_Rate_100Khz = 0,
    kSE05x_I2CM_Baud_Rate_400Khz,
} SE05x_I2CM_Baud_Rate_t;

/** Data Configuration for I2CM */
typedef struct
{
    /** 7 Bit address of I2C slave */
    uint8_t I2C_addr;
    /** What baud rate */
    SE05x_I2CM_Baud_Rate_t I2C_baudRate;
    /** return status  of the config operation */
    SE05x_I2CM_status_t status;
} SE05x_I2CM_configData_t;

/** @brief Security Configuration for I2CM */
typedef struct
{
    /**  @copydoc SE05x_I2CM_securityReq_t */
    SE05x_I2CM_securityReq_t operation;
    /** object used for the operation */
    uint32_t keyObject;
} SE05x_I2CM_securityData_t;

/** @brief Write From I2CM to I2C Slave */
typedef struct
{
    /** How many bytes to write */
    uint8_t writeLength;
    /** [Out] status of the operation */
    SE05x_I2CM_status_t wrStatus;
    /** Buffer to be written */
    uint8_t *writebuf; /* Input */
} SE05x_I2CM_writeData_t;

/**  Read to I2CM from I2C Slave */
typedef struct
{
    /** How many bytes to read */
    uint16_t readLength;
    /** [Out] status of the operation */
    SE05x_I2CM_status_t rdStatus;
    /** Output. rdBuf will point to Host buffer.  */
    uint8_t *rdBuf;
} SE05x_I2CM_readData_t;

/** Used to report error response, not for outgoing command */
typedef struct
{
    /** [Out] In case there is any structural issue */
    SE05x_I2CM_status_t issueStatus;
} SE05x_I2CM_structuralIssue_t;

/** @brief Individual entry in array of TLV commands */
typedef union {
    /** @copydoc SE05x_I2CM_configData_t */
    SE05x_I2CM_configData_t cfg;
    /** @copydoc SE05x_I2CM_securityData_t */
    SE05x_I2CM_securityData_t sec;
    /** @copydoc SE05x_I2CM_writeData_t */
    SE05x_I2CM_writeData_t w;
    /** @copydoc SE05x_I2CM_readData_t */
    SE05x_I2CM_readData_t rd;
    /** @copydoc SE05x_I2CM_structuralIssue_t */
    SE05x_I2CM_structuralIssue_t issue;
} SE05x_I2CM_INS_type_t;

/** Individual entry in array of TLV commands, with type
 *
 * @ref Se05x_i2c_master_txn would expect an array of these.
 */
typedef struct _SE05x_I2CM_cmd
{
    /** @copybrief SE05x_I2CM_TLV_type_t */
    SE05x_I2CM_TLV_type_t type;
    /** @copybrief SE05x_I2CM_INS_type_t */
    SE05x_I2CM_INS_type_t cmd;
} SE05x_I2CM_cmd_t;

/*!
 *@}
 */ /* end of se050_i2cm */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/** MAC Validate
 *
 */
sss_status_t sss_se05x_mac_validate_one_go(
    sss_se05x_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t macLen);

/** Similar to @ref sss_se05x_asymmetric_sign_digest,
 *
 * but hashing/digest done by SE
 */
sss_status_t sss_se05x_asymmetric_sign(
    sss_se05x_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** Similar to @ref sss_se05x_asymmetric_verify_digest,
 * but hashing/digest done by SE
 *
 */
sss_status_t sss_se05x_asymmetric_verify(
    sss_se05x_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen);

/** Read with attestation
 *
 */
sss_status_t sss_se05x_key_store_get_key_attst(sss_se05x_key_store_t *keyStore,
    sss_se05x_object_t *keyObject,
    uint8_t *key,
    size_t *keylen,
    size_t *pKeyBitLen,
    sss_se05x_object_t *keyObject_attst,
    sss_algorithm_t algorithm_attst,
    uint8_t *random_attst,
    size_t randomLen_attst,
    sss_se05x_attst_data_t *attst_data);

uint32_t se05x_sssKeyTypeLenToCurveId(sss_cipher_type_t keyType, size_t keyBits);

/** @addtogroup se050_i2cm
 *
 * @{
*/

/** @brief Se05x_i2c_master_txn
*
* I2CM Transaction
*
* @param[in] sess session identifier
* @param[in,out] cmds Array of structure type capturing a sequence of i2c master cmd/rsp transactions.
* @param[in] cmdLen Amount of structures contained in cmds
*
* @pre p describes I2C master commands.
* @post p contains execution state of I2C master commands, the I2C master commands can be overwritten to report on execution failure.
*/
smStatus_t Se05x_i2c_master_txn(sss_session_t *sess, SE05x_I2CM_cmd_t *cmds, uint8_t cmdLen);

/** @brief Se05x_i2c_master_attst_txn
 *
 * I2CM Read With Attestation
 *
 * @param[in] sess session identifier
 * @param[in] keyObject Keyobject which contains  4 byte attestaion KeyId
 * @param[in,out] p Array of structure type capturing a sequence of i2c master cmd/rsp transactions.
 * @param[in] random_attst 16-byte freshness random
 * @param[in] random_attstLen length of freshness random
 * @param[in] attst_algo 1 byte attestationAlgo
 * @param[out] ptimeStamp  timestamp
 * @param[out] timeStampLen  Length for timestamp
 * @param[out] freshness  freshness (random)
 * @param[out] pfreshnessLen Length for freshness
 * @param[out] chipId  unique chip Id
 * @param[out] pchipIdLen Length for chipId
 * @param[out] signature  signature
 * @param[out] psignatureLen Length for signature
 * @param[in] noOftags Amount of structures contained in ``p``
 *
 * @pre p describes I2C master commands.
 * @post p contains execution state of I2C master commands, the I2C master commands can be overwritten to report on execution failure.
 */
smStatus_t Se05x_i2c_master_attst_txn(sss_session_t *sess,
    sss_object_t *keyObject,
    SE05x_I2CM_cmd_t *p,
    uint8_t *random_attst,
    size_t random_attstLen,
    SE05x_AttestationAlgo_t attst_algo,
    SE05x_TimeStamp_t *ptimeStamp,
    size_t *timeStampLen,
    uint8_t *freshness,
    size_t *pfreshnessLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen,
    uint8_t noOftags);

/*!
 *@}
 */ /* end of se050_i2cm */

#endif /* SSS_HAVE_APPLET_SE05X_IOT */

#endif /* SSS_APIS_INC_FSL_SSS_SE05X_TYPES_H_ */
