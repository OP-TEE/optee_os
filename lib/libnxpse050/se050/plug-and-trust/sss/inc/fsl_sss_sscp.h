/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FSL_SSS_SSCP_H_
#define _FSL_SSS_SSCP_H_

#include "fsl_sscp.h"
#include "fsl_sss_api.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if !defined(SSS_SSCP_CONFIG_FILE)
#include "fsl_sss_sscp_config.h"
#else
#include SSS_SSCP_CONFIG_FILE
#endif

#define SSS_SUBSYSTEM_TYPE_IS_SSCP(subsystem) ((subsystem == kType_SSS_SE_A71CH) || (subsystem == kType_SSS_SE_A71CL))

#define SSS_SESSION_TYPE_IS_SSCP(session) (session && SSS_SUBSYSTEM_TYPE_IS_SSCP(session->subsystem))

#define SSS_KEY_STORE_TYPE_IS_SSCP(keyStore) (keyStore && SSS_SESSION_TYPE_IS_SSCP(keyStore->session))

#define SSS_OBJECT_TYPE_IS_SSCP(pObject) (pObject && SSS_KEY_STORE_TYPE_IS_SSCP(pObject->keyStore))

#define SSS_DERIVE_KEY_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

#define SSS_ASYMMETRIC_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

#define SSS_SYMMETRIC_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

#define SSS_MAC_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

#define SSS_RNG_CONTEXT_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

#define SSS_DIGEST_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

#define SSS_AEAD_TYPE_IS_SSCP(context) (context && SSS_SESSION_TYPE_IS_SSCP(context->session))

typedef enum
{
    kSSS_SSCP_SessionProp_CertUID = kSSS_SessionProp_au8_Proprietary_Start + 1,
} sss_sscp_sesion_prop_au8_t;

typedef enum
{
    kSSS_SSCP_SessionProp_CertUIDLen = kSSS_SessionProp_u32_Optional_Start + 1,
} sss_sscp_sesion_prop_u32_t;

typedef void (*fn_sscp_close_t)(void);

typedef struct _sss_sscp_session
{
    /*! Indicates which security subsystem is selected to be used. */
    sss_type_t subsystem;

    /*! Implementation specific part
     * This will be NULL unitl and unless we are not ready to use the sscp_context.
     */
    sscp_context_t *sscp_context;
    /**
     * Allocated structure, not to be used directly...
     * Use only sscp_context */
    sscp_context_t mem_sscp_ctx;
    /** session identifier */
    uint32_t sessionId;
    /** Function pointer that can be used to close the last active session. */
    fn_sscp_close_t fp_closeConnection;
} sss_sscp_session_t;

typedef struct _sss_sscp_key_store
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_sscp_session_t *session;
    /*! Implementation specific part */
    uint32_t keyStoreId;
} sss_sscp_key_store_t;

typedef struct _sss_sscp_object
{
    /*! key store holding the data and other properties */
    sss_sscp_key_store_t *keyStore;

    uint32_t objectType; /*!< Object types */
    uint32_t cipherType; /*!< Cipher types */
    /*! Application specific key identifier. The keyId is kept in the key store along with the key data and other
     * properties. */
    uint32_t keyId;

    void *transientObject;
    size_t transientObjectLen;
    size_t transientObjectBitLen;
    uint8_t slotId;
} sss_sscp_object_t;

/*! @brief ::sss_symmetric_t with SSCP specific information */
typedef struct _sss_sscp_symmetric
{
    /*! Virtual connection between application (user context) and
                specific security subsystem  and function thereof. */
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;    /*!< What eventual operation algorithm be performed */
    sss_mode_t mode;              /*!< High level operation, encrypt/decrypt/etc. */
    uint32_t sessionId;           /*!< Session identifier in case of parallel contexts */
    /*! Implementation specific part */
    struct
    {
        uint8_t data[SSS_SSCP_SYMMETRIC_CONTEXT_SIZE];
    } context;
} sss_sscp_symmetric_t;

typedef struct _sss_sscp_aead
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;    /*!<  */
    sss_mode_t mode;              /*!<  */

    /*! Implementation specific part */
} sss_sscp_aead_t;

typedef struct _sss_sscp_digest
{
    /*! Virtual connection between application (user context) and specific security subsystem and function thereof. */
    sss_sscp_session_t *session;
    sss_algorithm_t algorithm; /*!<  */
    sss_mode_t mode;           /*!<  */
    /*! Full digest length per algorithm definition. This field is initialized along with algorithm. */
    size_t digestFullLen;

    /*! Implementation specific part */
    struct
    {
        uint8_t data[SSS_SSCP_DIGEST_CONTEXT_SIZE];
    } context;
} sss_sscp_digest_t;

typedef struct _sss_sscp_mac
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;    /*!<  */
    sss_mode_t mode;              /*!<  */

    /*! Implementation specific part */
    uint32_t macFullLen;
    struct
    {
        uint8_t data[SSS_SSCP_MAC_CONTEXT_SIZE];
    } context;
} sss_sscp_mac_t;

typedef struct _sss_sscp_asymmetric
{
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject;
    sss_algorithm_t algorithm; /*!<  */
    sss_mode_t mode;           /*!<  */
    size_t signatureFullLen;
    uint32_t sessionId; /*!<  */
    /*! Implementation specific part */
} sss_sscp_asymmetric_t;

typedef struct _sss_sscp_tunnel
{
    sss_sscp_session_t *session;
    uint32_t tunnelType;
    uint32_t sessionId; /*!<  */
    /*! Implementation specific part */
} sss_sscp_tunnel_t;

typedef struct _sss_sscp_derive_key
{
    sss_sscp_session_t *session;
    sss_sscp_object_t *keyObject;
    sss_algorithm_t algorithm; /*!<  */
    sss_mode_t mode;           /*!<  */
    uint32_t sessionId;        /*!<  */
    /*! Implementation specific part */
} sss_sscp_derive_key_t;

typedef struct
{
    /** Context holder of session */
    sss_sscp_session_t *session;
} sss_sscp_rng_context_t;

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */
/**
 * @addtogroup sss_sscp_session
 * @{
 */
/** @copydoc sss_session_open
 *
 */
sss_status_t sss_sscp_session_open(sss_sscp_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData);

/** @copydoc sss_session_prop_get_u32
 *
 */
sss_status_t sss_sscp_session_prop_get_u32(sss_sscp_session_t *session, uint32_t property, uint32_t *pValue);

/** @copydoc sss_session_prop_get_au8
 *
 */
sss_status_t sss_sscp_session_prop_get_au8(
    sss_sscp_session_t *session, uint32_t property, uint8_t *pValue, size_t *pValueLen);

/** @copydoc sss_session_close
 *
 */
void sss_sscp_session_close(sss_sscp_session_t *session);

/*! @} */ /* end of : sss_sscp_session */

/**
 * @addtogroup sss_sscp_keyobj
 * @{
 */
/** @copydoc sss_key_object_init
 *
 */
sss_status_t sss_sscp_key_object_init(sss_sscp_object_t *keyObject, sss_sscp_key_store_t *keyStore);

/** @copydoc sss_key_object_allocate_handle
 *
 */
sss_status_t sss_sscp_key_object_allocate_handle(sss_sscp_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

/** @copydoc sss_key_object_get_handle
 *
 */
sss_status_t sss_sscp_key_object_get_handle(sss_sscp_object_t *keyObject, uint32_t keyId);

/** @copydoc sss_key_object_set_user
 *
 */
sss_status_t sss_sscp_key_object_set_user(sss_sscp_object_t *keyObject, uint32_t user, uint32_t options);

/** @copydoc sss_key_object_set_purpose
 *
 */
sss_status_t sss_sscp_key_object_set_purpose(sss_sscp_object_t *keyObject, sss_mode_t purpose, uint32_t options);

/** @copydoc sss_key_object_set_access
 *
 */
sss_status_t sss_sscp_key_object_set_access(sss_sscp_object_t *keyObject, uint32_t access, uint32_t options);

/** @copydoc sss_key_object_set_eccgfp_group
 *
 */
sss_status_t sss_sscp_key_object_set_eccgfp_group(sss_sscp_object_t *keyObject, sss_eccgfp_group_t *group);

/** @copydoc sss_key_object_get_user
 *
 */
sss_status_t sss_sscp_key_object_get_user(sss_sscp_object_t *keyObject, uint32_t *user);

/** @copydoc sss_key_object_get_purpose
 *
 */
sss_status_t sss_sscp_key_object_get_purpose(sss_sscp_object_t *keyObject, sss_mode_t *purpose);

/** @copydoc sss_key_object_get_access
 *
 */
sss_status_t sss_sscp_key_object_get_access(sss_sscp_object_t *keyObject, uint32_t *access);

/** @copydoc sss_key_object_free
 *
 */
void sss_sscp_key_object_free(sss_sscp_object_t *keyObject);

/*! @} */ /* end of : sss_sscp_keyobj */

/**
 * @addtogroup sss_sscp_keyderive
 * @{
 */
/** @copydoc sss_derive_key_context_init
 *
 */
sss_status_t sss_sscp_derive_key_context_init(sss_sscp_derive_key_t *context,
    sss_sscp_session_t *session,
    sss_sscp_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_derive_key_one_go
*
*/
sss_status_t sss_sscp_derive_key_one_go(sss_sscp_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_sscp_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @copydoc sss_derive_key_sobj_one_go
*
*/
sss_status_t sss_sscp_derive_key_sobj_one_go(sss_sscp_derive_key_t *context,
    sss_sscp_object_t *saltKeyObject,
    const uint8_t *info,
    size_t infoLen,
    sss_sscp_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @copydoc sss_derive_key_go
 *
 */
sss_status_t sss_sscp_derive_key_go(sss_sscp_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_sscp_object_t *derivedKeyObject,
    uint16_t deriveDataLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen);

/** @copydoc sss_derive_key_dh
 *
 */
sss_status_t sss_sscp_derive_key_dh(
    sss_sscp_derive_key_t *context, sss_sscp_object_t *otherPartyKeyObject, sss_sscp_object_t *derivedKeyObject);

/** @copydoc sss_derive_key_context_free
 *
 */
void sss_sscp_derive_key_context_free(sss_sscp_derive_key_t *context);

/*! @} */ /* end of : sss_sscp_keyderive */

/**
 * @addtogroup sss_sscp_keystore
 * @{
 */
/** @copydoc sss_key_store_context_init
 *
 */
sss_status_t sss_sscp_key_store_context_init(sss_sscp_key_store_t *keyStore, sss_sscp_session_t *session);

/** @copydoc sss_key_store_allocate
 *
 */
sss_status_t sss_sscp_key_store_allocate(sss_sscp_key_store_t *keyStore, uint32_t keyStoreId);

/** @copydoc sss_key_store_save
 *
 */
sss_status_t sss_sscp_key_store_save(sss_sscp_key_store_t *keyStore);

/** @copydoc sss_key_store_load
 *
 */
sss_status_t sss_sscp_key_store_load(sss_sscp_key_store_t *keyStore);

/** @copydoc sss_key_store_set_key
 *
 */
sss_status_t sss_sscp_key_store_set_key(sss_sscp_key_store_t *keyStore,
    sss_sscp_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen);

/** @copydoc sss_key_store_generate_key
 *
 */
sss_status_t sss_sscp_key_store_generate_key(
    sss_sscp_key_store_t *keyStore, sss_sscp_object_t *keyObject, size_t keyBitLen, void *options);

/** @copydoc sss_key_store_get_key
 *
 */
sss_status_t sss_sscp_key_store_get_key(
    sss_sscp_key_store_t *keyStore, sss_sscp_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen);

#if 0
/* To be reviewed: Purnank */
/** @copydoc sss_sscp_key_store_get_key_fromoffset
 *
 */
sss_status_t sss_sscp_key_store_get_key_fromoffset(sss_sscp_key_store_t *keyStore,
    sss_sscp_object_t *keyObject,
    uint8_t *data,
    size_t *dataLen,
    size_t *pKeyBitLen,
    uint16_t offset);
#endif
/** @copydoc sss_key_store_open_key
 *
 */
sss_status_t sss_sscp_key_store_open_key(sss_sscp_key_store_t *keyStore, sss_sscp_object_t *keyObject);

/** @copydoc sss_key_store_freeze_key
 *
 */
sss_status_t sss_sscp_key_store_freeze_key(sss_sscp_key_store_t *keyStore, sss_sscp_object_t *keyObject);

/** @copydoc sss_key_store_erase_key
 *
 */
sss_status_t sss_sscp_key_store_erase_key(sss_sscp_key_store_t *keyStore, sss_sscp_object_t *keyObject);

/** @copydoc sss_key_store_context_free
 *
 */
void sss_sscp_key_store_context_free(sss_sscp_key_store_t *keyStore);

/*! @} */ /* end of : sss_sscp_keystore */

/**
 * @addtogroup sss_sscp_asym
 * @{
 */
/** @copydoc sss_asymmetric_context_init
 *
 */
sss_status_t sss_sscp_asymmetric_context_init(sss_sscp_asymmetric_t *context,
    sss_sscp_session_t *session,
    sss_sscp_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_asymmetric_encrypt
 *
 */
sss_status_t sss_sscp_asymmetric_encrypt(
    sss_sscp_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_asymmetric_decrypt
 *
 */
sss_status_t sss_sscp_asymmetric_decrypt(
    sss_sscp_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_asymmetric_sign_digest
 *
 */
sss_status_t sss_sscp_asymmetric_sign_digest(
    sss_sscp_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc sss_asymmetric_verify_digest
 *
 */
sss_status_t sss_sscp_asymmetric_verify_digest(
    sss_sscp_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen);

/** @copydoc sss_asymmetric_context_free
 *
 */
void sss_sscp_asymmetric_context_free(sss_sscp_asymmetric_t *context);

/*! @} */ /* end of : sss_sscp_asym */

/**
 * @addtogroup sss_sscp_symm
 * @{
 */
/** @copydoc sss_symmetric_context_init
 *
 */
sss_status_t sss_sscp_symmetric_context_init(sss_sscp_symmetric_t *context,
    sss_sscp_session_t *session,
    sss_sscp_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_cipher_one_go
 *
 */
sss_status_t sss_sscp_cipher_one_go(sss_sscp_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t dataLen);

/** @copydoc sss_cipher_init
 *
 */
sss_status_t sss_sscp_cipher_init(sss_sscp_symmetric_t *context, uint8_t *iv, size_t ivLen);

/** @copydoc sss_cipher_update
 *
 */
sss_status_t sss_sscp_cipher_update(
    sss_sscp_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_cipher_finish
 *
 */
sss_status_t sss_sscp_cipher_finish(
    sss_sscp_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_cipher_crypt_ctr
 *
 */
sss_status_t sss_sscp_cipher_crypt_ctr(sss_sscp_symmetric_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *initialCounter,
    uint8_t *lastEncryptedCounter,
    size_t *szLeft);

/** @copydoc sss_symmetric_context_free
 *
 */
void sss_sscp_symmetric_context_free(sss_sscp_symmetric_t *context);

/*! @} */ /* end of : sss_sscp_symm */

/**
 * @addtogroup sss_sscp_aead
 * @{
 */
/** @copydoc sss_aead_context_init
 *
 */
sss_status_t sss_sscp_aead_context_init(sss_sscp_aead_t *context,
    sss_sscp_session_t *session,
    sss_sscp_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_aead_one_go
 *
 */
sss_status_t sss_sscp_aead_one_go(sss_sscp_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc sss_aead_init
 *
 */
sss_status_t sss_sscp_aead_init(
    sss_sscp_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

/** @copydoc sss_aead_update_aad
 *
 */
sss_status_t sss_sscp_aead_update_aad(sss_sscp_aead_t *context, const uint8_t *aadData, size_t aadDataLen);

/** @copydoc sss_aead_update
 *
 */
sss_status_t sss_sscp_aead_update(
    sss_sscp_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_aead_finish
 *
 */
sss_status_t sss_sscp_aead_finish(sss_sscp_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc sss_aead_context_free
 *
 */
void sss_sscp_aead_context_free(sss_sscp_aead_t *context);

/*! @} */ /* end of : sss_sscp_aead */

/**
 * @addtogroup sss_sscp_mac
 * @{
 */
/** @copydoc sss_mac_context_init
 *
 */
sss_status_t sss_sscp_mac_context_init(sss_sscp_mac_t *context,
    sss_sscp_session_t *session,
    sss_sscp_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_mac_one_go
 *
 */
sss_status_t sss_sscp_mac_one_go(
    sss_sscp_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_init
 *
 */
sss_status_t sss_sscp_mac_init(sss_sscp_mac_t *context);

/** @copydoc sss_mac_update
 *
 */
sss_status_t sss_sscp_mac_update(sss_sscp_mac_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc sss_mac_finish
 *
 */
sss_status_t sss_sscp_mac_finish(sss_sscp_mac_t *context, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_context_free
 *
 */
void sss_sscp_mac_context_free(sss_sscp_mac_t *context);

/*! @} */ /* end of : sss_sscp_mac */

/**
 * @addtogroup sss_sscp_md
 * @{
 */
/** @copydoc sss_digest_context_init
 *
 */
sss_status_t sss_sscp_digest_context_init(
    sss_sscp_digest_t *context, sss_sscp_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode);

/** @copydoc sss_digest_one_go
 *
 */
sss_status_t sss_sscp_digest_one_go(
    sss_sscp_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

/** @copydoc sss_digest_init
 *
 */
sss_status_t sss_sscp_digest_init(sss_sscp_digest_t *context);

/** @copydoc sss_digest_update
 *
 */
sss_status_t sss_sscp_digest_update(sss_sscp_digest_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc sss_digest_finish
 *
 */
sss_status_t sss_sscp_digest_finish(sss_sscp_digest_t *context, uint8_t *digest, size_t *digestLen);

/** @copydoc sss_digest_context_free
 *
 */
void sss_sscp_digest_context_free(sss_sscp_digest_t *context);

/*! @} */ /* end of : sss_sscp_md */

/**
 * @addtogroup sss_sscp_rng
 * @{
 */
/** @copydoc sss_rng_context_init
 *
 */
sss_status_t sss_sscp_rng_context_init(sss_sscp_rng_context_t *context, sss_sscp_session_t *session);

/** @copydoc sss_rng_get_random
 *
 */
sss_status_t sss_sscp_rng_get_random(sss_sscp_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/** @copydoc sss_rng_context_free
 *
 */
sss_status_t sss_sscp_rng_context_free(sss_sscp_rng_context_t *context);

/*! @} */ /* end of : sss_sscp_rng */

#if defined(__cplusplus)
}
#endif

#endif /* _FSL_SSS_SSCP_H_ */
