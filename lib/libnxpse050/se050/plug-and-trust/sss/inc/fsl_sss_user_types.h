/*
 * Copyright 2018,2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_APIS_INC_fsl_sss_user_types_H_
#define SSS_APIS_INC_fsl_sss_user_types_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sss_api.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_USER

/**
 * @addtogroup sss_sw_host_impl
 * @{
 */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define SSS_SUBSYSTEM_TYPE_IS_HOST(subsystem) (subsystem == kType_SSS_mbedTLS)

#define SSS_SESSION_TYPE_IS_HOST(session) (session && SSS_SUBSYSTEM_TYPE_IS_HOST(session->subsystem))

#define SSS_KEY_STORE_TYPE_IS_HOST(keyStore) (keyStore && SSS_SESSION_TYPE_IS_HOST(keyStore->session))

#define SSS_OBJECT_TYPE_IS_HOST(pObject) (pObject && SSS_KEY_STORE_TYPE_IS_HOST(pObject->keyStore))

#define SSS_SYMMETRIC_TYPE_IS_HOST(context) (context && SSS_SESSION_TYPE_IS_HOST(context->session))

#define SSS_RNG_CONTEXT_TYPE_IS_HOST(context) (context && SSS_SESSION_TYPE_IS_HOST(context->session))

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

struct _sss_user_impl_session;

typedef struct _sss_user_impl_session
{
    /*! Indicates which security subsystem is selected to be used. */
    sss_type_t subsystem;

} sss_user_impl_session_t;

struct _sss_user_impl_object;

typedef struct _sss_user_impl_key_store
{
    sss_user_impl_session_t *session;

} sss_user_impl_key_store_t;

typedef struct _sss_user_impl_object
{
    /*! key store holding the data and other properties */
    sss_user_impl_key_store_t *keyStore;
    /*! Object types */
    uint32_t objectType;
    uint32_t cipherType;
    /*! Application specific key identifier. The keyId is kept in the key  store
     * along with the key data and other properties. */
    uint32_t keyId;

    /*! Implementation specific part */
    uint8_t key[16];
} sss_user_impl_object_t;

typedef struct _sss_user_impl_derive_key
{
    sss_user_impl_session_t *session;
    sss_user_impl_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */
} sss_user_impl_derive_key_t;

typedef struct _sss_user_impl_asymmetric
{
    sss_user_impl_session_t *session;
    sss_user_impl_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */
} sss_user_impl_asymmetric_t;

typedef struct _sss_user_impl_symmetric
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_user_impl_session_t *session;
    /*** Reference to key and it's properties. */
    sss_user_impl_object_t *keyObject;
    sss_algorithm_t algorithm;
    sss_mode_t mode;

    /*! Implementation specific part */
    void *cipher;
} sss_user_impl_symmetric_t;

typedef struct _sss_user_impl_mac
{
    sss_user_impl_session_t *session;
    /*! Reference to key and it's properties. */
    sss_user_impl_object_t *keyObject;
    sss_algorithm_t algorithm; /*!  */
    sss_mode_t mode;           /*!  */

    /*! Implementation specific part */
    void *mac;
} sss_user_impl_mac_t;

typedef struct _sss_user_impl_digest
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_user_impl_session_t *session;
    sss_algorithm_t algorithm; /*!<  */
    sss_mode_t mode;           /*!<  */
    /*! Full digest length per algorithm definition. This field is initialized along with algorithm. */
    size_t digestFullLen;
    /*! Implementation specific part */
} sss_user_impl_digest_t;

typedef struct
{
    sss_user_impl_session_t *session;

} sss_user_impl_rng_context_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/** @}  */

#endif /* SSS_HAVE_HOSTCRYPTO_USER */

#endif /* SSS_APIS_INC_fsl_sss_user_types_H_ */
