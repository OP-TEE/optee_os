/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_APIS_INC_FSL_SSS_MBEDTLS_TYPES_H_
#define SSS_APIS_INC_FSL_SSS_MBEDTLS_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sss_api.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_MBEDTLS

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <fsl_sss_keyid_map.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ccm.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>

/**
 * @addtogroup sss_sw_mbedtls
 * @{
 */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define SSS_SUBSYSTEM_TYPE_IS_MBEDTLS(subsystem) (subsystem == kType_SSS_mbedTLS)

#define SSS_SESSION_TYPE_IS_MBEDTLS(session) (session && SSS_SUBSYSTEM_TYPE_IS_MBEDTLS(session->subsystem))

#define SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore) (keyStore && SSS_SESSION_TYPE_IS_MBEDTLS(keyStore->session))

#define SSS_OBJECT_TYPE_IS_MBEDTLS(pObject) (pObject && SSS_KEY_STORE_TYPE_IS_MBEDTLS(pObject->keyStore))

#define SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context) (context && SSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context) (context && SSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context) (context && SSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define SSS_MAC_TYPE_IS_MBEDTLS(context) (context && SSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define SSS_RNG_CONTEXT_TYPE_IS_MBEDTLS(context) (context && SSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define SSS_DIGEST_TYPE_IS_MBEDTLS(context) (context && SSS_SESSION_TYPE_IS_MBEDTLS(context->session))

#define SSS_AEAD_TYPE_IS_MBEDTLS(context) (context && SSS_SESSION_TYPE_IS_MBEDTLS(context->session))

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

struct _sss_mbedtls_session;

typedef struct _sss_mbedtls_session
{
    /*! Indicates which security subsystem is selected to be used. */
    sss_type_t subsystem;

    mbedtls_entropy_context *entropy;
    mbedtls_ctr_drbg_context *ctr_drbg;

#ifdef MBEDTLS_FS_IO
    /* Root Path for persitant key store */
    const char *szRootPath;
#endif
} sss_mbedtls_session_t;

struct _sss_mbedtls_object;

typedef struct _sss_mbedtls_key_store
{
    sss_mbedtls_session_t *session;

#ifdef MBEDTLS_FS_IO
    /*! Implementation specific part */
    struct _sss_mbedtls_object **objects;
    uint32_t max_object_count;

    keyStoreTable_t *keystore_shadow;
#endif
} sss_mbedtls_key_store_t;

typedef struct _sss_mbedtls_object
{
    /*! key store holding the data and other properties */
    sss_mbedtls_key_store_t *keyStore;
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
} sss_mbedtls_object_t;

typedef struct _sss_mbedtls_derive_key
{
    sss_mbedtls_session_t *session;
    sss_mbedtls_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */

} sss_mbedtls_derive_key_t;

typedef struct _sss_mbedtls_asymmetric
{
    sss_mbedtls_session_t *session;
    sss_mbedtls_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */

} sss_mbedtls_asymmetric_t;

typedef struct _sss_mbedtls_symmetric
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_mbedtls_session_t *session;
    sss_mbedtls_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;       /*!  */
    sss_mode_t mode;                 /*!  */
    mbedtls_cipher_context_t *cipher_ctx;
    uint8_t cache_data[16];
    size_t cache_data_len;

} sss_mbedtls_symmetric_t;

typedef struct _sss_mbedtls_mac
{
    sss_mbedtls_session_t *session;
    sss_mbedtls_object_t *keyObject; /*! Reference to key and it's properties. */
    sss_algorithm_t algorithm;       /*!  */
    sss_mode_t mode;                 /*!  */

    /*! Implementation specific part */
    mbedtls_cipher_context_t *cipher_ctx; /*For init- update -finish*/
    mbedtls_md_context_t *HmacCtx;
} sss_mbedtls_mac_t;

typedef struct _sss_mbedtls_aead
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_mbedtls_session_t *session;
    sss_mbedtls_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;       /*!<  */
    sss_mode_t mode;                 /*!<  */

    /*! Implementation specific part */
    mbedtls_gcm_context *gcm_ctx; /*!< Reference to gcm context. */
    mbedtls_ccm_context *ccm_ctx; /*!< Reference to ccm context. */
    uint8_t *pNonce;              /*!< Reference to IV. */
    size_t nonceLen;              /*!< Store IV len. */
    const uint8_t *pCcm_aad;      /*!< Reference to AAD */
    size_t ccm_aadLen;            /*!< Store AAD len. */
    uint8_t *pCcm_data;           /*!< Ref to CCM data dynamic allocated.. */
    size_t ccm_dataTotalLen;      /*!< Store CCM data total len. */
    size_t ccm_dataoffset;        /*!< Store CCM data offset. */
    uint8_t cache_data[16];       /*!< Cache for GCM data  */
    size_t cache_data_len;        /*!< Store GCM Cache len*/
} sss_mbedtls_aead_t;

typedef struct _sss_mbedtls_digest
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_mbedtls_session_t *session;
    sss_algorithm_t algorithm; /*!<  */
    sss_mode_t mode;           /*!<  */
    /*! Full digest length per algorithm definition. This field is initialized along with algorithm. */
    size_t digestFullLen;
    /*! Implementation specific part */
    mbedtls_md_context_t md_ctx;
} sss_mbedtls_digest_t;

typedef struct
{
    sss_mbedtls_session_t *session;

} sss_mbedtls_rng_context_t;

#define sss_mbedtls_tunnel_t sss_tunnel_t

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

#ifdef MBEDTLS_FS_IO

/** Store key inside persistant key store */
sss_status_t ks_mbedtls_store_key(const sss_mbedtls_object_t *sss_key);

sss_status_t ks_mbedtls_load_key(sss_mbedtls_object_t *sss_key, keyStoreTable_t *keystore_shadow, uint32_t extKeyId);

sss_status_t ks_mbedtls_remove_key(const sss_mbedtls_object_t *sss_key);

sss_status_t ks_mbedtls_fat_update(sss_mbedtls_key_store_t *keyStore);

#endif /* MBEDTLS_FS_IO */

/* Low Level API Key object create */
sss_status_t ks_mbedtls_key_object_create(sss_mbedtls_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t keyMode);

/** @}  */

#endif /* SSS_HAVE_MBEDTLS */

#endif /* SSS_APIS_INC_FSL_SSS_MBEDTLS_TYPES_H_ */
