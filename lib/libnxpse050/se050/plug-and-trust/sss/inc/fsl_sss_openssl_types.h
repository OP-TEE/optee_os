/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_APIS_INC_FSL_SSS_OPENSSL_TYPES_H_
#define SSS_APIS_INC_FSL_SSS_OPENSSL_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sss_api.h>
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_OPENSSL

#include <fsl_sss_keyid_map.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
/**
 * @addtogroup sss_sw_openssl
 * @{
 */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define SSS_SUBSYSTEM_TYPE_IS_OPENSSL(subsystem) (subsystem == kType_SSS_OpenSSL)

#define SSS_SESSION_TYPE_IS_OPENSSL(session) (session && SSS_SUBSYSTEM_TYPE_IS_OPENSSL(session->subsystem))

#define SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore) (keyStore && SSS_SESSION_TYPE_IS_OPENSSL(keyStore->session))

#define SSS_OBJECT_TYPE_IS_OPENSSL(pObject) (pObject && SSS_KEY_STORE_TYPE_IS_OPENSSL(pObject->keyStore))

#define SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context) (context && SSS_SESSION_TYPE_IS_OPENSSL(context->session))

#define SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context) (context && SSS_SESSION_TYPE_IS_OPENSSL(context->session))

#define SSS_SYMMETRIC_TYPE_IS_OPENSSL(context) (context && SSS_SESSION_TYPE_IS_OPENSSL(context->session))

#define SSS_MAC_TYPE_IS_OPENSSL(context) (context && SSS_SESSION_TYPE_IS_OPENSSL(context->session))

#define SSS_RNG_CONTEXT_TYPE_IS_OPENSSL(context) (context && SSS_SESSION_TYPE_IS_OPENSSL(context->session))

#define SSS_DIGEST_TYPE_IS_OPENSSL(context) (context && SSS_SESSION_TYPE_IS_OPENSSL(context->session))

#define SSS_AEAD_TYPE_IS_OPENSSL(context) (context && SSS_SESSION_TYPE_IS_OPENSSL(context->session))

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

struct _sss_openssl_session;

typedef struct _sss_openssl_session
{
    /*! Indicates which security subsystem is selected to be used. */
    sss_type_t subsystem;

    /* Root Path for persitant key store */
    const char *szRootPath;
} sss_openssl_session_t;

struct _sss_openssl_object;

typedef struct _sss_openssl_key_store
{
    sss_openssl_session_t *session;

    /*! Implementation specific part */
    struct _sss_openssl_object **objects;
    uint32_t max_object_count;

    keyStoreTable_t *keystore_shadow;

} sss_openssl_key_store_t;

typedef struct _sss_openssl_object
{
    /*! key store holding the data and other properties */
    sss_openssl_key_store_t *keyStore;
    /*! Object types */
    uint32_t objectType;
    uint32_t cipherType;
    /*! Application specific key identifier. The keyId is kept in the key  store
     * along with the key data and other properties. */
    uint32_t keyId;

    /*! Implementation specific part */
    /** Contents are malloced, so must be freed */
    uint32_t contents_must_free : 1;
    /** Type of key. Persistnet/trainsient @ref sss_key_object_mode_t */
    uint32_t keyMode : 3;
    /** Max size allocated */
    size_t contents_max_size;
    size_t contents_size;
    size_t keyBitLen;
    uint32_t user_id;
    sss_mode_t purpose;
    sss_access_permission_t accessRights;
    /* malloced / referenced contents */
    void *contents;
} sss_openssl_object_t;

typedef struct _sss_openssl_derive_key
{
    sss_openssl_session_t *session;
    sss_openssl_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */

} sss_openssl_derive_key_t;

typedef struct _sss_openssl_asymmetric
{
    sss_openssl_session_t *session;
    sss_openssl_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */

} sss_openssl_asymmetric_t;

typedef struct _sss_openssl_symmetric
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_openssl_session_t *session;
    sss_openssl_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;       /*!  */
    sss_mode_t mode;                 /*!  */
    EVP_CIPHER_CTX *cipher_ctx;
    uint8_t cache_data[16];
    size_t cache_data_len;
} sss_openssl_symmetric_t;

typedef struct
{
    sss_openssl_session_t *session;
    sss_openssl_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;       /*!  */
    sss_mode_t mode;                 /*!  */
    CMAC_CTX *cmac_ctx;
    HMAC_CTX *hmac_ctx;
} sss_openssl_mac_t;

typedef struct _sss_openssl_aead
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_openssl_session_t *session;
    sss_openssl_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;       /*!<  */
    sss_mode_t mode;                 /*!<  */

    /*! Implementation specific part */
    EVP_CIPHER_CTX *aead_ctx; /*!< Reference to aead context. */
    uint8_t cache_data[16];   /*!< Cache for GCM data  */
    size_t cache_data_len;    /*!< Store GCM Cache len*/
    uint8_t *pCcm_data;       /*!< Ref to CCM data dynamic allocated.. */
    size_t ccm_dataTotalLen;  /*!< Store CCM data total len. */
    size_t ccm_dataoffset;    /*!< Store CCM data offset. */
    uint8_t *pCcm_tag;        /*!< Reference to tag. */
    size_t ccm_tagLen;        /*!< Store tag len. */
    const uint8_t *pCcm_aad;  /*!< Reference to AAD */
    size_t ccm_aadLen;        /*!< Store AAD len. */
    const uint8_t *pCcm_iv;   /*!< Reference to IV. */
    size_t ccm_ivLen;         /*!< Store IV len. */
} sss_openssl_aead_t;

typedef struct _sss_openssl_digest
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_openssl_session_t *session;
    sss_algorithm_t algorithm; /*!<  */
    sss_mode_t mode;           /*!<  */
    /*! Full digest length per algorithm definition. This field is initialized along with algorithm. */
    size_t digestFullLen;
    /*! Implementation specific part */
    EVP_MD_CTX *mdctx;
} sss_openssl_digest_t;

typedef struct
{
    sss_openssl_session_t *session;
} sss_openssl_rng_context_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/** Similar to @ref sss_openssl_asymmetric_sign_digest,
*
* but hashing/digest done by openssl
*/
sss_status_t sss_openssl_asymmetric_sign(
    sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** Similar to @ref sss_openssl_asymmetric_verify_digest,
* but hashing/digest done by openssl
*
*/
sss_status_t sss_openssl_asymmetric_verify(
    sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen);

/** Store key inside persistant key store */
sss_status_t ks_openssl_store_key(const sss_openssl_object_t *sss_key);

sss_status_t ks_openssl_load_key(sss_openssl_object_t *sss_key, keyStoreTable_t *keystore_shadow, uint32_t extKeyId);

sss_status_t ks_openssl_fat_update(sss_openssl_key_store_t *keyStore);

sss_status_t ks_openssl_remove_key(const sss_openssl_object_t *sss_key);

sss_status_t sss_openssl_key_object_allocate(sss_openssl_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t keyMode);

/** @} */

#endif /* SSS_HAVE_OPENSSL */

#endif /* SSS_APIS_INC_FSL_SSS_OPENSSL_TYPES_H_ */
