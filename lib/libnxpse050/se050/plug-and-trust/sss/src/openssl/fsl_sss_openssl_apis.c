/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fsl_sss_openssl_apis.h>

#if SSS_HAVE_OPENSSL

#include <inttypes.h>
#include <memory.h>
#include <nxEnsure.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
#include <openssl/modes.h>
#endif

#include "nxLog_sss.h"

#define MAX_KEY_OBJ_COUNT KS_N_ENTIRES
#define MAX_FILE_NAME_SIZE 255
#define MAX_SHARED_SECRET_DERIVED_DATA 255
#define BEGIN_PRIVATE "-----BEGIN PRIVATE KEY-----\n"
#define END_PRIVATE "\n-----END PRIVATE KEY-----"
#define BEGIN_EC_PRIVATE "-----BEGIN EC PRIVATE KEY-----\n"
#define END_EC_PRIVATE "\n-----END EC PRIVATE KEY-----"
#define BEGIN_PUBLIC "-----BEGIN PUBLIC KEY-----\n"
#define END_PUBLIC "\n-----END PUBLIC KEY-----"
#define BEGIN_RSA_PRIVATE "-----BEGIN RSA PRIVATE KEY-----\n"
#define END_RSA_PRIVATE "\n-----END RSA PRIVATE KEY-----"

#define CIPHER_BLOCK_SIZE 16

#ifndef RSA_PSS_SALTLEN_DIGEST
#define RSA_PSS_SALTLEN_DIGEST -1
#endif

/* ************************************************************************** */
/* Functions : Private sss openssl delceration                                */
/* ************************************************************************** */
static sss_status_t sss_openssl_generate_ecp_key(sss_openssl_object_t *keyObject, size_t keyBitLen);

static sss_status_t sss_openssl_generate_rsa_key(sss_openssl_object_t *keyObject, size_t keyBitLen);

static sss_status_t sss_openssl_set_key(
    sss_openssl_object_t *keyObject, const uint8_t *keyBuf, size_t keyBufLen, size_t keyBitLen);

static sss_status_t sss_openssl_hkdf_extract(const EVP_MD *md,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t *prk,
    unsigned int *prk_len);

static sss_status_t sss_openssl_hkdf_expand(const EVP_MD *md,
    const uint8_t *prk,
    size_t prk_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len);

static sss_status_t sss_openssl_aead_init_ctx(sss_openssl_aead_t *context);
static sss_status_t sss_openssl_aead_one_go_encrypt(sss_openssl_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

static sss_status_t sss_openssl_aead_one_go_decrypt(sss_openssl_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

static int aead_update(sss_openssl_aead_t *context,
    sss_mode_t mode,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen);
static sss_status_t sss_openssl_aead_ccm_init(
    sss_openssl_aead_t *context, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);
static sss_status_t sss_openssl_aead_ccm_final(
    sss_openssl_aead_t *context, uint8_t *destData, size_t *destLen, uint8_t *tag, size_t *tagLen);

static sss_status_t sss_openssl_aead_ccm_Decryptfinal(sss_openssl_aead_t *context, uint8_t *destData, size_t *destLen);

static sss_status_t sss_openssl_aead_ccm_Encryptfinal(sss_openssl_aead_t *context, uint8_t *destData, size_t *destLen);

static sss_status_t sss_openssl_aead_ccm_update(sss_openssl_aead_t *context, const uint8_t *srcData, size_t srcLen);
/* ************************************************************************** */
/* Functions : sss_openssl_session                                            */
/* ************************************************************************** */

sss_status_t sss_openssl_session_create(sss_openssl_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    sss_status_t retval = kStatus_SSS_Success;
    /* Nothing special to be handled */
    return retval;
}

sss_status_t sss_openssl_session_open(sss_openssl_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    sss_status_t retval = kStatus_SSS_InvalidArgument;
    memset(session, 0, sizeof(*session));

#if SSS_HAVE_OPENSSL
    memset(session, 0, sizeof(*session));

    OpenSSL_add_all_algorithms();

    if (connectionData == NULL) {
        retval             = kStatus_SSS_Success;
        session->subsystem = subsystem;
    }
    else {
        const char *szRootPath = (const char *)connectionData;
        session->szRootPath    = szRootPath;
        retval                 = kStatus_SSS_Success;
        session->subsystem     = subsystem;
    }
#else
    if (connectionData == NULL) {
        retval             = kStatus_SSS_Success;
        session->subsystem = subsystem;
    }
    else {
        /* Can't support connectionData  != NULL for openssl without
        * openssl_FS_IO */
        retval = kStatus_SSS_InvalidArgument;
    }
#endif

    return retval;
}

sss_status_t sss_openssl_session_prop_get_u32(sss_openssl_session_t *session, uint32_t property, uint32_t *pValue)
{
    sss_status_t retval = kStatus_SSS_Fail;
    /* TBU */
    return retval;
}

sss_status_t sss_openssl_session_prop_get_au8(
    sss_openssl_session_t *session, uint32_t property, uint8_t *pValue, size_t *pValueLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    /* TBU */
    return retval;
}

void sss_openssl_session_close(sss_openssl_session_t *session)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ERR_remove_thread_state(NULL);
#endif
#ifdef __linux__
    EVP_cleanup();
#endif
    memset(session, 0, sizeof(*session));
}

void sss_openssl_session_delete(sss_openssl_session_t *session)
{
    ;
}

/* End: openssl_session */

/* ************************************************************************** */
/* Functions : sss_openssl_keyobj                                             */
/* ************************************************************************** */

sss_status_t sss_openssl_key_object_init(sss_openssl_object_t *keyObject, sss_openssl_key_store_t *keyStore)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyStore);
    memset(keyObject, 0, sizeof(*keyObject));
    keyObject->keyStore = keyStore;
    retval              = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_object_allocate(sss_openssl_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t keyMode)
{
    size_t size         = 0;
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyObject);
    keyObject->keyId              = keyId;
    keyObject->objectType         = keyPart;
    keyObject->cipherType         = cipherType;
    keyObject->contents_max_size  = keyByteLenMax;
    keyObject->contents_must_free = 1;
    keyObject->keyMode            = keyMode;
    keyObject->accessRights       = 0x1F; /* Bitwise OR of all sss_access_permission. */
    switch (keyPart) {
    case kSSS_KeyPart_Default:
        size = keyByteLenMax;
        if (size != 0) {
            keyObject->contents = SSS_MALLOC(size);
            ENSURE_OR_GO_CLEANUP(keyObject->contents);
            memset(keyObject->contents, 0, size);
            retval = kStatus_SSS_Success;
        }
        break;
    case kSSS_KeyPart_Public:
    case kSSS_KeyPart_Pair:
    case kSSS_KeyPart_Private:
        /* Initialize the Generic key strucute if not done. */
        keyObject->contents = EVP_PKEY_new();
        retval              = kStatus_SSS_Success;
        break;
    default:
        break;
    }
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_object_allocate_handle(sss_openssl_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyObject);

    if (options != kKeyObject_Mode_Persistent && options != kKeyObject_Mode_Transient) {
        LOG_E("sss_openssl_key_object_allocate_handle option invalid 0x%X", options);
        goto cleanup;
    }
    ENSURE_OR_GO_CLEANUP((size_t)keyPart < UINT8_MAX);
    if (options == kKeyObject_Mode_Persistent) {
#ifdef SSS_HAVE_OPENSSL
        uint32_t i;
        sss_openssl_object_t **ks;
        ENSURE_OR_GO_CLEANUP(keyObject->keyStore);
        ENSURE_OR_GO_CLEANUP(keyObject->keyStore->max_object_count > 0);

        retval = ks_common_update_fat(
            keyObject->keyStore->keystore_shadow, keyId, keyPart, cipherType, 0, 0, (uint16_t)keyByteLenMax);
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);

        ks = keyObject->keyStore->objects;
        for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
            if (ks[i] == NULL) {
                ks[i]  = keyObject;
                retval = sss_openssl_key_object_allocate(keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
                break;
            }
        }
#endif
    }
    else {
        retval = sss_openssl_key_object_allocate(keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
    }
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_object_get_handle(sss_openssl_object_t *keyObject, uint32_t keyId)
{
    sss_status_t retval = kStatus_SSS_Fail;
#ifdef SSS_HAVE_OPENSSL
    uint32_t i;

    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyObject->keyStore);
    retval = kStatus_SSS_Success;
    /* If key store already has loaded this and shared this - fail */
    for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
        if (keyObject->keyStore->objects[i] != NULL && keyObject->keyStore->objects[i]->keyId == keyId) {
            /* Key Object already loaded and shared in another instance */
            LOG_W("KeyID 0x%X already loaded / shared", keyId);
            retval = kStatus_SSS_Fail;
            break;
        }
    }
    if (retval == kStatus_SSS_Success) {
        for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
            if (keyObject->keyStore->objects[i] == NULL) {
                retval = ks_openssl_load_key(keyObject, keyObject->keyStore->keystore_shadow, keyId);
                if (retval == kStatus_SSS_Success) {
                    keyObject->keyStore->objects[i] = keyObject;
                }
                break;
            }
        }
    }
#endif
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_object_set_user(sss_openssl_object_t *keyObject, uint32_t user, uint32_t options)
{
    sss_status_t retval = kStatus_SSS_Success;
    if (!(keyObject->accessRights & kAccessPermission_SSS_ChangeAttributes)) {
        LOG_E(" Don't have access rights to change the attributes");
        return kStatus_SSS_Fail;
    }
    keyObject->user_id = user;
    return retval;
}

sss_status_t sss_openssl_key_object_set_purpose(sss_openssl_object_t *keyObject, sss_mode_t purpose, uint32_t options)
{
    sss_status_t retval = kStatus_SSS_Success;
    if (!(keyObject->accessRights & kAccessPermission_SSS_ChangeAttributes)) {
        LOG_E(" Don't have access rights to change the attributes");
        return kStatus_SSS_Fail;
    }
    keyObject->purpose = purpose;
    return retval;
}

sss_status_t sss_openssl_key_object_set_access(sss_openssl_object_t *keyObject, uint32_t access, uint32_t options)
{
    sss_status_t retval = kStatus_SSS_Success;
    if (!(keyObject->accessRights & kAccessPermission_SSS_ChangeAttributes)) {
        LOG_E(" Don't have access rights to use the key");

        return kStatus_SSS_Fail;
    }
    keyObject->accessRights = access;
    return retval;
}

sss_status_t sss_openssl_key_object_set_eccgfp_group(sss_openssl_object_t *keyObject, sss_eccgfp_group_t *group)
{
    sss_status_t retval = kStatus_SSS_Success;
    /* TBU */
    return retval;
}

sss_status_t sss_openssl_key_object_get_user(sss_openssl_object_t *keyObject, uint32_t *user)
{
    sss_status_t retval = kStatus_SSS_Success;
    *user               = keyObject->user_id;
    return retval;
}

sss_status_t sss_openssl_key_object_get_purpose(sss_openssl_object_t *keyObject, sss_mode_t *purpose)
{
    sss_status_t retval = kStatus_SSS_Success;
    *purpose            = keyObject->purpose;
    return retval;
}

sss_status_t sss_openssl_key_object_get_access(sss_openssl_object_t *keyObject, uint32_t *access)
{
    sss_status_t retval = kStatus_SSS_Success;
    *access             = keyObject->accessRights;
    return retval;
}

void sss_openssl_key_object_free(sss_openssl_object_t *keyObject)
{
    EVP_PKEY *pKey = NULL;
    RSA *pRSA      = NULL;
    unsigned int i = 0;

    ENSURE_OR_GO_EXIT(keyObject)
    if (keyObject->keyStore != NULL && keyObject->objectType != 0) {
        for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
            if (keyObject->keyStore->objects[i] == keyObject) {
                keyObject->keyStore->objects[i] = NULL;
                break;
            }
        }
    }

    if (keyObject->contents != NULL && keyObject->contents_must_free) {
        switch (keyObject->cipherType) {
        case kSSS_CipherType_RSA:
            pKey = (EVP_PKEY *)keyObject->contents;
            pRSA = (RSA *)EVP_PKEY_get0(pKey);
            if (pRSA) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
                if (pRSA->references)
                    pRSA->references = 0;
#else
                /* not in 1.1 and above */
#endif
            }
            EVP_PKEY_free(pKey);
            break;
        case kSSS_CipherType_EC_NIST_P:
        case kSSS_CipherType_EC_NIST_K:
        case kSSS_CipherType_EC_BRAINPOOL:
        case kSSS_CipherType_EC_MONTGOMERY:
        case kSSS_CipherType_EC_TWISTED_ED:
            pKey = (EVP_PKEY *)keyObject->contents;
            EVP_PKEY_free(pKey);
            break;
        default:
            SSS_FREE(keyObject->contents);
        }
    }
    memset(keyObject, 0, sizeof(*keyObject));
exit:
    return;
}

/* End: openssl_keyobj */

/* ************************************************************************** */
/* Functions : sss_openssl_keyderive                                          */
/* ************************************************************************** */

sss_status_t sss_openssl_derive_key_context_init(sss_openssl_derive_key_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(context);
    ENSURE_OR_GO_CLEANUP(session);
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyObject->contents);

    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_openssl_derive_key_one_go(sss_openssl_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_openssl_object_t *derivedKeyObject,
    uint16_t deriveDataLen)
{
    size_t adjustedSaltLen = saltLen;

    if (context->mode == kMode_SSS_HKDF_ExpandOnly) {
        adjustedSaltLen = 0;
    }

    return sss_openssl_derive_key_go(
        context, saltData, adjustedSaltLen, info, infoLen, derivedKeyObject, deriveDataLen, NULL, NULL);
}

sss_status_t sss_openssl_derive_key_sobj_one_go(sss_openssl_derive_key_t *context,
    sss_openssl_object_t *saltKeyObject,
    const uint8_t *info,
    size_t infoLen,
    sss_openssl_object_t *derivedKeyObject,
    uint16_t deriveDataLen)
{
    uint8_t saltData[1024] = {0};
    size_t saltLen         = sizeof(saltData);
    size_t dummySize;
    sss_status_t status;

    if (context->mode != kMode_SSS_HKDF_ExpandOnly) {
        status = sss_openssl_key_store_get_key(saltKeyObject->keyStore, saltKeyObject, saltData, &saltLen, &dummySize);
        if (status != kStatus_SSS_Success) {
            return kStatus_SSS_Fail;
        }
    }
    else {
        saltLen = 0;
    }

    // Not yet fully implemented
    // TODO:
    // - deal with saltKeyObject
    return sss_openssl_derive_key_go(
        context, saltData, saltLen, info, infoLen, derivedKeyObject, deriveDataLen, NULL, NULL);
}

// In HKDF Expand only mode PRK is unbounded, we set a maximum of 256 byte
// RFC5869 Section 2.3
#define HKDF_PRK_MAX 256
sss_status_t sss_openssl_derive_key_go(sss_openssl_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_openssl_object_t *derivedKeyObject,
    uint16_t deriveDataLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen)
{
    sss_status_t retval = kStatus_SSS_Success;
    const EVP_MD *md    = NULL;
    uint8_t *secret     = NULL;
    size_t secretLen    = 0;
    secret              = context->keyObject->contents;
    secretLen           = context->keyObject->contents_size;
    uint8_t prk[HKDF_PRK_MAX];
    unsigned int prk_len = 0;

    /* Initialize the MD */
    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA1:
    case kAlgorithm_SSS_HMAC_SHA1:
        md = EVP_sha1();
        break;
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_HMAC_SHA256:
        md = EVP_sha256();
        break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_HMAC_SHA384:
        md = EVP_sha384();
        break;
    case kAlgorithm_SSS_SHA512:
    case kAlgorithm_SSS_HMAC_SHA512:
        md = EVP_sha512();
        break;
    default:
        return kStatus_SSS_Fail;
    }

    if (saltLen == 0) {
        /* Copy key as is */
        if (HKDF_PRK_MAX >= secretLen) {
            memcpy(prk, secret, secretLen);
            prk_len = secretLen;
        }
        else {
            LOG_E("HKDF Expand only (OpenSSL implementation): buffer too small");
            return kStatus_SSS_Fail;
        }
    }
    else {
        retval = sss_openssl_hkdf_extract(md, saltData, saltLen, secret, secretLen, prk, &prk_len);
        if (retval != kStatus_SSS_Success) {
            return kStatus_SSS_Fail;
        }
    }

    retval = sss_openssl_hkdf_expand(md, prk, prk_len, info, infoLen, derivedKeyObject->contents, deriveDataLen);
    derivedKeyObject->contents_size = deriveDataLen;

    return retval;
}

sss_status_t sss_openssl_derive_key_dh(sss_openssl_derive_key_t *context,
    sss_openssl_object_t *otherPartyKeyObject,
    sss_openssl_object_t *derivedKeyObject)
{
    sss_status_t retval = kStatus_SSS_Success;
    EVP_PKEY *pKeyPrv   = NULL;
    EC_KEY *pEcpPrv     = NULL;

    EVP_PKEY *pKeyExt = NULL;
    EC_KEY *pEcpExt   = NULL;

    size_t sharedSecretLen;
    int sharedSecretLen_Derived;
    EC_GROUP *pEC_Group = NULL;
    uint8_t *secret     = NULL;

    pKeyPrv = (EVP_PKEY *)context->keyObject->contents;
    pKeyExt = (EVP_PKEY *)otherPartyKeyObject->contents;

    if (context->keyObject->cipherType == kSSS_CipherType_EC_MONTGOMERY) {
        EVP_PKEY_CTX *ctx;
        ctx = EVP_PKEY_CTX_new(pKeyPrv, NULL);
        if (!ctx) {
            return kStatus_SSS_Fail;
        }

        if (EVP_PKEY_derive_init(ctx) <= 0) {
            return kStatus_SSS_Fail;
        }

        if (EVP_PKEY_derive_set_peer(ctx, pKeyExt) <= 0) {
            return kStatus_SSS_Fail;
        }

        /* Determine buffer length */
        if (EVP_PKEY_derive(ctx, NULL, &sharedSecretLen) <= 0) {
            return kStatus_SSS_Fail;
        }

        secret                  = (uint8_t *)SSS_MALLOC(sharedSecretLen);
        sharedSecretLen_Derived = sharedSecretLen;

        if (EVP_PKEY_derive(ctx, secret, &sharedSecretLen) <= 0) {
            return kStatus_SSS_Fail;
        }
        EVP_PKEY_CTX_free(ctx);
    }
    else {
        pEcpPrv         = EVP_PKEY_get1_EC_KEY(pKeyPrv);
        pEcpExt         = EVP_PKEY_get1_EC_KEY(pKeyExt);
        sharedSecretLen = (EC_GROUP_get_degree(EC_KEY_get0_group(pEcpExt)) + 7) / 8;
        secret          = (uint8_t *)SSS_MALLOC(sharedSecretLen);

        sharedSecretLen_Derived =
            ECDH_compute_key(secret, sharedSecretLen, EC_KEY_get0_public_key(pEcpExt), pEcpPrv, NULL);
    }

    memcpy(derivedKeyObject->contents, secret, sharedSecretLen_Derived);
    derivedKeyObject->contents_size = sharedSecretLen_Derived;

    EC_GROUP_free(pEC_Group);
    EC_KEY_free(pEcpPrv);
    EC_KEY_free(pEcpExt);
    SSS_FREE(secret);
    return retval;
}

void sss_openssl_derive_key_context_free(sss_openssl_derive_key_t *context)
{
    if (context->keyObject)
        sss_openssl_key_object_free(context->keyObject);
    memset(context, 0, sizeof(*context));
}

/* End: openssl_keyderive */

/* ************************************************************************** */
/* Functions : sss_openssl_keystore                                           */
/* ************************************************************************** */

sss_status_t sss_openssl_key_store_context_init(sss_openssl_key_store_t *keyStore, sss_openssl_session_t *session)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyStore);
    ENSURE_OR_GO_CLEANUP(session);
    memset(keyStore, 0, sizeof(*keyStore));
    keyStore->session = session;
    retval            = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_store_allocate(sss_openssl_key_store_t *keyStore, uint32_t keyStoreId)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyStore);
    retval = kStatus_SSS_Success;
#ifdef SSS_HAVE_OPENSSL
    if (keyStore->objects == NULL) {
        keyStore->max_object_count = MAX_KEY_OBJ_COUNT;
        keyStore->objects = (sss_openssl_object_t **)SSS_MALLOC(MAX_KEY_OBJ_COUNT * sizeof(sss_openssl_object_t *));
        memset(keyStore->objects, 0, (MAX_KEY_OBJ_COUNT * sizeof(sss_openssl_object_t *)));
        if (NULL == keyStore->objects) {
            LOG_E("Could not allocate key store");
            retval = kStatus_SSS_Fail;
        }
        else {
            ks_sw_fat_allocate(&keyStore->keystore_shadow);
            ks_sw_fat_load(keyStore->session->szRootPath, keyStore->keystore_shadow);
            retval = kStatus_SSS_Success;
        }
    }
    else {
        LOG_E("KeyStore already allocated");
        retval = kStatus_SSS_Fail;
    }
#endif
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_store_save(sss_openssl_key_store_t *keyStore)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyStore);
    ENSURE_OR_GO_CLEANUP(keyStore->session);
#ifdef SSS_HAVE_OPENSSL
    ENSURE_OR_GO_CLEANUP(keyStore->session->szRootPath);
    if (NULL != keyStore->objects) {
        uint32_t i;
        for (i = 0; i < keyStore->max_object_count; i++) {
            if (NULL != keyStore->objects[i]) {
                retval = ks_openssl_store_key(keyStore->objects[i]);
                /*Check added as part of security boundry checks*/
                ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);
            }
        }
    }
    retval = ks_openssl_fat_update(keyStore);
#endif
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_store_load(sss_openssl_key_store_t *keyStore)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyStore);
    ENSURE_OR_GO_CLEANUP(keyStore->session);
#ifdef SSS_HAVE_OPENSSL
    if (keyStore->objects == NULL) {
        retval = sss_openssl_key_store_allocate(keyStore, 0);
        /*Check added as part of security boundry checks*/
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);
    }
    if (keyStore->session->szRootPath) {
        if (NULL == keyStore->keystore_shadow) {
            ks_sw_fat_allocate(&keyStore->keystore_shadow);
        }
        retval                     = ks_sw_fat_load(keyStore->session->szRootPath, keyStore->keystore_shadow);
        keyStore->max_object_count = keyStore->keystore_shadow->maxEntries;
    }
#endif
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_store_set_key(sss_openssl_key_store_t *keyStore,
    sss_openssl_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
    sss_status_t retval      = kStatus_SSS_Fail;
    uint8_t opensslData[256] = {
        0,
    };
    size_t opensslDataLen = sizeof(opensslData);
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyObject->contents);
    if (!(keyObject->accessRights & kAccessPermission_SSS_Write)) {
        return retval;
    }

    if ((keyObject->objectType == kSSS_KeyPart_Pair) && (keyObject->cipherType == kSSS_CipherType_EC_MONTGOMERY)) {
        LOG_W("OpenSSL keystore cannot handle EC_MONT keypair with public key: Removing public key");
        ENSURE_OR_GO_CLEANUP(dataLen <= opensslDataLen);
        memcpy(opensslData, data, dataLen);
        if ((data[1] == 0x51) && (data[4] == 1)) {
            opensslData[1] -= 0x23;
            opensslData[4] = 0;
            opensslDataLen = dataLen - 0x23;
        }
        else if ((data[1] == 0x81) && (data[4] == 1)) {
            opensslData[1] -= 0x3b;
            opensslData[4] = 0;
            opensslDataLen = dataLen - 0x3b;
        }
        else {
            LOG_E("OpenSSL keystore cannot handle EC_MONT keypair with public key: Cannot remove public key");
            opensslDataLen = dataLen;
        }
        retval = sss_openssl_set_key(keyObject, opensslData, opensslDataLen, keyBitLen);
    }
    else {
        retval = sss_openssl_set_key(keyObject, data, dataLen, keyBitLen);
    }
cleanup:
    return retval;
}

sss_status_t sss_openssl_key_store_generate_key(
    sss_openssl_key_store_t *keyStore, sss_openssl_object_t *keyObject, size_t keyBitLen, void *options)
{
    sss_status_t retval = kStatus_SSS_Success;

    sss_cipher_type_t cipher_type = keyObject->cipherType;
    ENSURE_OR_GO_EXIT(keyStore);
    ENSURE_OR_GO_EXIT(keyObject);

    switch (cipher_type) {
    case kSSS_CipherType_EC_NIST_P:
    case kSSS_CipherType_EC_NIST_K:
    case kSSS_CipherType_EC_BRAINPOOL:
    case kSSS_CipherType_EC_MONTGOMERY:
    case kSSS_CipherType_EC_TWISTED_ED:
        retval = sss_openssl_generate_ecp_key(keyObject, keyBitLen);
        break;
    case kSSS_CipherType_RSA:
        retval = sss_openssl_generate_rsa_key(keyObject, keyBitLen);
        break;
    default:
        break;
    }
exit:
    return retval;
}

sss_status_t sss_openssl_key_store_get_key(sss_openssl_key_store_t *keyStore,
    sss_openssl_object_t *keyObject,
    uint8_t *data,
    size_t *dataLen,
    size_t *pKeyBitLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    EVP_PKEY *pk        = NULL;
    int len             = 0;
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyObject->contents);
    if (!(keyObject->accessRights & kAccessPermission_SSS_Read)) {
        return kStatus_SSS_Fail;
    }

    switch (keyObject->objectType) {
    case kSSS_KeyPart_Default:
        memcpy(data, keyObject->contents, keyObject->contents_size);
        *dataLen = keyObject->contents_size;
        break;
    case kSSS_KeyPart_Public:
    case kSSS_KeyPart_Pair: {
        pk  = (EVP_PKEY *)keyObject->contents;
        len = i2d_PUBKEY(pk, &data);
        if (len < 0 || (int)(*dataLen) < len) {
            goto cleanup;
        }

        *dataLen    = len;
        *pKeyBitLen = len * 8;
        break;
    }
    default:
        break;
    }

    retval = kStatus_SSS_Success;
cleanup:
    return retval;
}
#if 0
/* To be reviewed: Purnank */
sss_status_t sss_openssl_key_store_get_key_fromoffset(sss_openssl_key_store_t *keyStore,
    sss_openssl_object_t *keyObject,
    uint8_t *data,
    size_t *dataLen,
    size_t *pKeyBitLen,
    uint16_t offset)
{
    sss_status_t retval = kStatus_SSS_Success;
    return retval;
}
#endif
sss_status_t sss_openssl_key_store_open_key(sss_openssl_key_store_t *keyStore, sss_openssl_object_t *keyObject)
{
    sss_status_t retval = kStatus_SSS_Success;
    return retval;
}

sss_status_t sss_openssl_key_store_freeze_key(sss_openssl_key_store_t *keyStore, sss_openssl_object_t *keyObject)
{
    sss_status_t retval = kStatus_SSS_Success;
    return retval;
}

sss_status_t sss_openssl_key_store_erase_key(sss_openssl_key_store_t *keyStore, sss_openssl_object_t *keyObject)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(keyStore);
    ENSURE_OR_GO_EXIT(keyObject);
    ENSURE_OR_GO_EXIT(keyObject->keyStore);

    if (!(keyObject->accessRights & kAccessPermission_SSS_Delete)) {
        LOG_E("Don't have access right to delete the key");
        return retval;
    }

    if (keyObject->keyMode == kKeyObject_Mode_Persistent) {
#ifdef SSS_HAVE_OPENSSL
        unsigned int i = 0;
        /* first check if key exists delete key from shadow KS*/
        retval = ks_common_remove_fat(keyObject->keyStore->keystore_shadow, keyObject->keyId);
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);

        /* Update shadow keystore in file system*/
        retval = ks_openssl_fat_update(keyObject->keyStore);
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);

        /*Clear key object from file*/
        retval = ks_openssl_remove_key(keyObject);
        /*Check added as part of security boundary checks*/
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);

        for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
            if (keyObject->keyStore->objects[i] == keyObject) {
                keyObject->keyStore->objects[i] = NULL;
                break;
            }
        }
#endif
    }
    else {
        retval = kStatus_SSS_Success;
    }
#ifdef SSS_HAVE_OPENSSL
cleanup:
#endif
exit:
    return retval;
}

void sss_openssl_key_store_context_free(sss_openssl_key_store_t *keyStore)
{
    if (NULL != keyStore->objects) {
        uint32_t i;
        for (i = 0; i < keyStore->max_object_count; i++) {
            if (keyStore->objects[i] != NULL) {
                sss_openssl_key_object_free(keyStore->objects[i]);
                keyStore->objects[i] = NULL;
            }
        }
        SSS_FREE(keyStore->objects);
    }

    ks_sw_fat_free(keyStore->keystore_shadow);
    memset(keyStore, 0, sizeof(*keyStore));
}

int openssl_get_padding(sss_algorithm_t algorithm)
{
    int padding = 0;
    switch (algorithm) {
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH:
    case kAlgorithm_SSS_RSAES_PKCS1_V1_5:
        padding = RSA_PKCS1_PADDING;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512:
        padding = RSA_PKCS1_PSS_PADDING;
        break;
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA224:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA384:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512:
        padding = RSA_PKCS1_OAEP_PADDING;
        break;
    default:
        padding = RSA_PKCS1_PADDING;
    }
    return padding;
}

/* End: openssl_keystore */

/* ************************************************************************** */
/* Functions : sss_openssl_asym                                               */
/* ************************************************************************** */

sss_status_t sss_openssl_asymmetric_context_init(sss_openssl_asymmetric_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_CLEANUP(context);
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyObject->keyStore->session->subsystem == kType_SSS_OpenSSL);

    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_openssl_asymmetric_encrypt(
    sss_openssl_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval = kStatus_SSS_Success;
    int ret;
    sss_openssl_object_t *keyObj = context->keyObject;
    EVP_PKEY *pKey               = NULL;
    RSA *pRSA                    = NULL;
    char *pErr                   = NULL;
    int padding                  = 0;

    if (!(context->keyObject->accessRights & kAccessPermission_SSS_Use)) {
        return kStatus_SSS_Fail;
    }

    /* Get the RSA Key. */
    pKey = (EVP_PKEY *)keyObj->contents;
    pRSA = EVP_PKEY_get1_RSA(pKey);

    padding = openssl_get_padding(context->algorithm);

    /* Encrypt the mesasage. */
    ret = RSA_public_encrypt((int)srcLen, srcData, destData, pRSA, padding);
    if (ret == -1) {
        retval = kStatus_SSS_Fail;
        ERR_load_crypto_strings();
        pErr = SSS_MALLOC(150);
        ERR_error_string(ERR_get_error(), pErr);
        LOG_E("sss_openssl_asymmetric_encrypt");
        goto exit;
    }
    else {
        *destLen = ret;
    }

exit:
    return retval;
}

sss_status_t sss_openssl_asymmetric_decrypt(
    sss_openssl_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval = kStatus_SSS_Success;
    int ret;
    sss_openssl_object_t *keyObj = context->keyObject;
    EVP_PKEY *pKey               = NULL;
    RSA *pRSA                    = NULL;
    char *pErr                   = NULL;
    int padding                  = 0;

    if (!(context->keyObject->accessRights & kAccessPermission_SSS_Use)) {
        return kStatus_SSS_Fail;
    }

    /* Get the RSA Key. */
    pKey = (EVP_PKEY *)keyObj->contents;
    pRSA = EVP_PKEY_get1_RSA(pKey);

    padding = openssl_get_padding(context->algorithm);

    /* Decrypt the mesasage. */
    ret = RSA_private_decrypt((int)srcLen, srcData, destData, pRSA, padding);
    if (ret == -1) {
        retval = kStatus_SSS_Fail;
        ERR_load_crypto_strings();
        pErr = SSS_MALLOC(150);
        ERR_error_string(ERR_get_error(), pErr);
        LOG_E("sss_openssl_asymmetric_encrypt");
        goto exit;
    }
    else {
        *destLen = ret;
    }

exit:
    return retval;
}

void *openssl_get_hash_ptr_set_padding(sss_algorithm_t algorithm, uint32_t cipherType, EVP_PKEY_CTX *pKey_Ctx)
{
    void *hashfPtr = NULL;
    switch (algorithm) {
    case kAlgorithm_SSS_SHA1:
    case kAlgorithm_SSS_ECDSA_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1: {
        hashfPtr = (void *)EVP_sha1();
    } break;
    case kAlgorithm_SSS_SHA224:
    case kAlgorithm_SSS_ECDSA_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA224: {
        hashfPtr = (void *)EVP_sha224();
    } break;
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_ECDSA_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256:
    case kAlgorithm_SSS_RSAES_PKCS1_V1_5:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256:
    case kAlgorithm_SSS_ECDAA: {
        hashfPtr = (void *)EVP_sha256();
    } break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_ECDSA_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA384: {
        hashfPtr = (void *)EVP_sha384();
    } break;
    case kAlgorithm_SSS_SHA512:
    case kAlgorithm_SSS_ECDSA_SHA512:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512: {
        hashfPtr = (void *)EVP_sha512();
    } break;
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH:
    default:
        hashfPtr = NULL;
    }

    if (cipherType == kSSS_CipherType_RSA || cipherType == kSSS_CipherType_RSA_CRT) {
        EVP_PKEY_CTX_set_rsa_padding(pKey_Ctx, openssl_get_padding(algorithm));
    }
    else {
        //No padding for ECC Sign
        //EVP_CIPHER_CTX_set_padding(pKey_Ctx, 0);
    }

    return hashfPtr;
}

sss_status_t sss_openssl_asymmetric_sign_digest(
    sss_openssl_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    sss_status_t retval    = kStatus_SSS_Success;
    EVP_PKEY *pKey         = NULL;
    EVP_PKEY_CTX *pKey_Ctx = NULL;
    void *hashfPtr         = NULL;
    int ret                = 0;

    if (!(context->keyObject->accessRights & kAccessPermission_SSS_Use)) {
        return kStatus_SSS_Fail;
    }

    pKey = (EVP_PKEY *)context->keyObject->contents;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    if (context->keyObject->cipherType == kSSS_CipherType_EC_MONTGOMERY) {
        EVP_MD_CTX *pKey_md_Ctx = NULL;
        pKey_md_Ctx             = (EVP_MD_CTX *)EVP_MD_CTX_create();
        if (1 != EVP_DigestSignInit(pKey_md_Ctx, NULL, NULL, NULL, pKey)) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }
        if (1 != EVP_DigestSign(pKey_md_Ctx, signature, signatureLen, digest, digestLen)) {
            retval = kStatus_SSS_Fail;
        }
        goto exit;
    }
#endif
    /* Get the context from EVP_PKEY */
    pKey_Ctx = EVP_PKEY_CTX_new(pKey, NULL);

    /* Init the Signing context. */
    if (1 != EVP_PKEY_sign_init(pKey_Ctx)) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    /* Set the Signing MD. */
    hashfPtr = openssl_get_hash_ptr_set_padding(context->algorithm, context->keyObject->cipherType, pKey_Ctx);

    /*
    * For RSA, null hash pointer is valid, as sign with no hash is available.
    * Sign with no hash is invalid for ecc keys.
    */
    if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
        context->keyObject->cipherType == kSSS_CipherType_EC_NIST_K ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL ||
        context->keyObject->cipherType == kSSS_CipherType_EC_TWISTED_ED ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BARRETO_NAEHRIG) {
        ENSURE_OR_GO_EXIT(NULL != hashfPtr);
    }

    /* Explicitly set the salt length to match the digest size (-1)
     * #define RSA_PSS_SALTLEN_DIGEST -1, this is defined only in openssl 1.1
     * Define it explicitly in this file.
     */
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pKey_Ctx, RSA_PSS_SALTLEN_DIGEST);

    if (1 != EVP_PKEY_CTX_set_signature_md(pKey_Ctx, hashfPtr)) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    /* Set the Signature length to 0. */
    *signatureLen = 0;

    /* Determine buffer length */
    ret = EVP_PKEY_sign(pKey_Ctx, NULL, signatureLen, digest, digestLen);
    if (ret <= 0) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    /* Perfom Signing of the message. */
    ret = EVP_PKEY_sign(pKey_Ctx, signature, signatureLen, digest, digestLen);
    if (ret <= 0) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

exit:
    EVP_PKEY_CTX_free(pKey_Ctx);
    pKey_Ctx = NULL;
    return retval;
}

sss_status_t sss_openssl_asymmetric_verify_digest(
    sss_openssl_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t retval    = kStatus_SSS_Success;
    EVP_PKEY *pKey         = NULL;
    EVP_PKEY_CTX *pKey_Ctx = NULL;
    void *hashfPtr         = NULL;
    int ret                = 0;

    if (!(context->keyObject->accessRights & kAccessPermission_SSS_Use)) {
        return kStatus_SSS_Fail;
    }

    pKey = (EVP_PKEY *)context->keyObject->contents;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    if (context->keyObject->cipherType == kSSS_CipherType_EC_MONTGOMERY) {
        EVP_MD_CTX *pKey_md_Ctx = NULL;
        pKey_md_Ctx             = (EVP_MD_CTX *)EVP_MD_CTX_create();
        if (1 != EVP_DigestVerifyInit(pKey_md_Ctx, NULL, NULL, NULL, pKey)) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }

        if (1 != EVP_DigestVerify(pKey_md_Ctx, signature, signatureLen, digest, digestLen)) {
            retval = kStatus_SSS_Fail;
        }
        goto exit;
    }
#endif

    /* Get the context from EVP_PKEY */
    pKey_Ctx = EVP_PKEY_CTX_new(pKey, NULL);

    /* Init the Verfying context. */
    if (1 != EVP_PKEY_verify_init(pKey_Ctx)) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    /* Set the Signing MD. */
    hashfPtr = openssl_get_hash_ptr_set_padding(context->algorithm, context->keyObject->cipherType, pKey_Ctx);

    /*
    * For RSA, null hash pointer is valid, as sign with no hash is available.
    * Sign with no hash is invalid for ecc keys.
    */
    if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
        context->keyObject->cipherType == kSSS_CipherType_EC_NIST_K ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL ||
        context->keyObject->cipherType == kSSS_CipherType_EC_TWISTED_ED ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BARRETO_NAEHRIG) {
        ENSURE_OR_GO_EXIT(NULL != hashfPtr);
    }

    if (1 != EVP_PKEY_CTX_set_signature_md(pKey_Ctx, hashfPtr)) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    /* Perfom Verification of the message. */
    ret = EVP_PKEY_verify(pKey_Ctx, signature, signatureLen, digest, digestLen);
    if (1 != ret) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

exit:
    EVP_PKEY_CTX_free(pKey_Ctx);
    pKey_Ctx = NULL;
    return retval;
}

sss_status_t sss_openssl_asymmetric_sign(
    sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    EVP_MD_CTX *pKey_md_Ctx = NULL;
    EVP_PKEY *pKey          = NULL;

    pKey = (EVP_PKEY *)context->keyObject->contents;

    if (context->keyObject->cipherType == kSSS_CipherType_EC_TWISTED_ED) {
        pKey_md_Ctx = (EVP_MD_CTX *)EVP_MD_CTX_create();
        if (1 != EVP_DigestSignInit(pKey_md_Ctx, NULL, NULL, NULL, pKey)) {
            goto exit;
        }

        if (1 != EVP_DigestSign(pKey_md_Ctx, destData, destLen, srcData, srcLen)) {
            goto exit;
        }
    }
    else {
        goto exit;
    }

    retval                  = kStatus_SSS_Success;
#endif
exit:
    return retval;
}

sss_status_t sss_openssl_asymmetric_verify(
    sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    EVP_MD_CTX *pKey_md_Ctx = NULL;
    EVP_PKEY *pKey          = NULL;

    pKey = (EVP_PKEY *)context->keyObject->contents;

    if (context->keyObject->cipherType == kSSS_CipherType_EC_TWISTED_ED) {
        pKey_md_Ctx = (EVP_MD_CTX *)EVP_MD_CTX_create();
        if (1 != EVP_DigestVerifyInit(pKey_md_Ctx, NULL, NULL, NULL, pKey)) {
            goto exit;
        }

        if (1 != EVP_DigestVerify(pKey_md_Ctx, signature, signatureLen, srcData, srcLen)) {
            goto exit;
        }
    }
    else {
        goto exit;
    }

    retval = kStatus_SSS_Success;
#endif
exit:
    return retval;
}

void sss_openssl_asymmetric_context_free(sss_openssl_asymmetric_t *context)
{
    memset(context, 0, sizeof(*context));
}

/* End: openssl_asym */

/* ************************************************************************** */
/* Functions : sss_openssl_symm                                               */
/* ************************************************************************** */

sss_status_t sss_openssl_symmetric_context_init(sss_openssl_symmetric_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Success;

    context->session        = session;
    context->keyObject      = keyObject;
    context->algorithm      = algorithm;
    context->mode           = mode;
    context->cache_data_len = 0;
    context->cipher_ctx     = NULL;

    return retval;
}

sss_status_t sss_openssl_cipher_one_go(sss_openssl_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t dataLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    AES_KEY AESKey;
    DES_key_schedule schedule;
    DES_cblock DESKey;

    switch (context->algorithm) {
    case kAlgorithm_SSS_AES_ECB:
    case kAlgorithm_SSS_AES_CBC: {
        if (context->mode == kMode_SSS_Encrypt) {
            if (AES_set_encrypt_key((uint8_t *)context->keyObject->contents,
                    (int)(context->keyObject->contents_size * 8),
                    &AESKey) < 0) {
                retval = kStatus_SSS_Fail;
                LOG_E("Key initialization failed");
                goto exit;
            }
        }
        else if (context->mode == kMode_SSS_Decrypt) {
            if (AES_set_decrypt_key((uint8_t *)context->keyObject->contents,
                    (int)(context->keyObject->contents_size * 8),
                    &AESKey) < 0) {
                retval = kStatus_SSS_Fail;
                LOG_E("Key initialization failed");
                goto exit;
            }
        }
    } break;
    case kAlgorithm_SSS_AES_CTR: {
        if (AES_set_encrypt_key(
                (uint8_t *)context->keyObject->contents, (int)(context->keyObject->contents_size * 8), &AESKey) < 0) {
            retval = kStatus_SSS_Fail;
            LOG_E("Key initialization failed");
            goto exit;
        }
    } break;
    case kAlgorithm_SSS_DES_CBC:
    case kAlgorithm_SSS_DES_ECB:
    case kAlgorithm_SSS_DES3_CBC:
    case kAlgorithm_SSS_DES3_ECB: {
        memcpy(DESKey, (const char *)context->keyObject->contents, context->keyObject->contents_size);
        DES_set_key(&DESKey, &schedule);
        break;
    }
    default:
        return retval;
    }

    if (context->mode == kMode_SSS_Encrypt) {
        switch (context->algorithm) {
        case kAlgorithm_SSS_AES_ECB:
            AES_ecb_encrypt(srcData, destData, &AESKey, AES_ENCRYPT);
            break;
        case kAlgorithm_SSS_AES_CBC:
            AES_cbc_encrypt(srcData, destData, dataLen, &AESKey, iv, AES_ENCRYPT);
            break;
        case kAlgorithm_SSS_AES_CTR: {
            unsigned char ecount_buf[16] = {
                0,
            };
            unsigned int num = 0;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
            AES_ctr128_encrypt(srcData, destData, dataLen, &AESKey, iv, ecount_buf, &num);
#else
            CRYPTO_ctr128_encrypt(srcData, destData, dataLen, &AESKey, iv, ecount_buf, &num, (block128_f)AES_encrypt);
#endif
        } break;
        case kAlgorithm_SSS_DES_ECB: {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
            DES_ecb_encrypt((const_DES_cblock *)srcData, (DES_cblock *)destData, &schedule, DES_ENCRYPT);
#else
            size_t rem = dataLen;
            int offset = 0;
            if (dataLen % 8 != 0) {
                LOG_E("Input should be 8 byte aligned for DES ECB");
                return kStatus_SSS_Fail;
            }

            while ((rem > 0) && (rem % 8 == 0)) {
                DES_ecb_encrypt(
                    (const_DES_cblock *)(srcData + offset), (DES_cblock *)(destData + offset), &schedule, DES_ENCRYPT);
                offset = offset + 8;
                rem    = rem - 8;
            }
#endif
        } break;
        case kAlgorithm_SSS_DES_CBC:
            DES_cbc_encrypt(srcData, destData, (int)dataLen, &schedule, (DES_cblock *)iv, DES_ENCRYPT);
            break;
        default:
            break;
        }
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        switch (context->algorithm) {
        case kAlgorithm_SSS_AES_ECB:
            AES_ecb_encrypt(srcData, destData, &AESKey, AES_DECRYPT);
            break;
        case kAlgorithm_SSS_AES_CBC:
            AES_cbc_encrypt(srcData, destData, dataLen, &AESKey, iv, AES_DECRYPT);
            break;
        case kAlgorithm_SSS_AES_CTR: {
            unsigned char ecount_buf[16] = {
                0,
            };
            unsigned int num = 0;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
            AES_ctr128_encrypt(srcData, destData, dataLen, &AESKey, iv, ecount_buf, &num);
#else
            CRYPTO_ctr128_encrypt(srcData, destData, dataLen, &AESKey, iv, ecount_buf, &num, (block128_f)AES_encrypt);
#endif
        } break;
        case kAlgorithm_SSS_DES_ECB: {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
            DES_ecb_encrypt((const_DES_cblock *)srcData, (DES_cblock *)destData, &schedule, DES_DECRYPT);
#else
            size_t rem = dataLen;
            int offset = 0;
            if (dataLen % 8 != 0) {
                LOG_E("Input should be 8 byte aligned for DES ECB");
                return kStatus_SSS_Fail;
            }

            while ((rem > 0) && (rem % 8 == 0)) {
                DES_ecb_encrypt(
                    (const_DES_cblock *)(srcData + offset), (DES_cblock *)(destData + offset), &schedule, DES_DECRYPT);
                offset = offset + 8;
                rem    = rem - 8;
            }
#endif
        } break;
        case kAlgorithm_SSS_DES_CBC:
            DES_cbc_encrypt(srcData, destData, (long)dataLen, &schedule, (DES_cblock *)iv, DES_DECRYPT);
            break;
        default:
            break;
        }
    }
    else {
        return retval;
    }

exit:
    return kStatus_SSS_Success;
}

sss_status_t sss_openssl_cipher_init(sss_openssl_symmetric_t *context, uint8_t *iv, size_t ivLen)
{
    sss_status_t retval           = kStatus_SSS_Success;
    const EVP_CIPHER *cipher_info = NULL;

    if (context->algorithm == kAlgorithm_SSS_AES_ECB) {
        switch (context->keyObject->keyBitLen) {
        case 128:
            cipher_info = EVP_aes_128_ecb();
            break;
        case 192:
            cipher_info = EVP_aes_192_ecb();
            break;
        case 256:
            cipher_info = EVP_aes_256_ecb();
            break;
        default:
            goto exit;
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_CBC) {
        switch (context->keyObject->keyBitLen) {
        case 128:
            cipher_info = EVP_aes_128_cbc();
            break;
        case 192:
            cipher_info = EVP_aes_192_cbc();
            break;
        case 256:
            cipher_info = EVP_aes_256_cbc();
            break;
        default:
            goto exit;
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_CTR) {
        switch (context->keyObject->keyBitLen) {
        case 128:
            cipher_info = EVP_aes_128_ctr();
            break;
        case 192:
            cipher_info = EVP_aes_192_ctr();
            break;
        case 256:
            cipher_info = EVP_aes_256_ctr();
            break;
        default:
            goto exit;
        }
    }

    /* Create and initialise the context */
    context->cipher_ctx = EVP_CIPHER_CTX_new();
    if (!(context->cipher_ctx)) {
        retval = kStatus_SSS_InvalidArgument;
        LOG_E(" Cipher initialization failed ");
        goto exit;
    }

    if (context->mode == kMode_SSS_Encrypt) {
        /* Initialise the encryption operation. IMPORTANT - ensure you use a key
        * and IV size appropriate for your cipher
        */
        if (1 != EVP_CipherInit(context->cipher_ctx, cipher_info, context->keyObject->contents, iv, 1)) {
            retval = kStatus_SSS_InvalidArgument;
            LOG_E("EncryptionCipher initialization failed !!!");

            goto exit;
        }

        EVP_CIPHER_CTX_set_padding(context->cipher_ctx, 0);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        /* Initialise the encryption operation. IMPORTANT - ensure you use a key
        * and IV size appropriate for your cipher
        */
        if (1 != EVP_CipherInit(context->cipher_ctx, cipher_info, context->keyObject->contents, iv, 0)) {
            retval = kStatus_SSS_InvalidArgument;
            LOG_E(" DecryptionCipher initialization failed");
            goto exit;
        }

        EVP_CIPHER_CTX_set_padding(context->cipher_ctx, 0);
    }
    else {
        retval = kStatus_SSS_InvalidArgument;
    }

exit:
    return retval;
}

sss_status_t sss_openssl_cipher_update(
    sss_openssl_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval                  = kStatus_SSS_Fail;
    uint8_t inputData[CIPHER_BLOCK_SIZE] = {
        0,
    };
    size_t inputData_len = 0;
    size_t src_offset    = 0;
    size_t output_offset = 0;
    size_t outBuffSize   = *destLen;
    size_t blockoutLen   = 0;

    if ((context->cache_data_len + srcLen) < CIPHER_BLOCK_SIZE) {
        /* Insufficinet data to process . Cache the data */
        memcpy((context->cache_data + context->cache_data_len), srcData, srcLen);
        context->cache_data_len = context->cache_data_len + srcLen;
        *destLen                = 0;
        return kStatus_SSS_Success;
    }
    else {
        /* Concatenate the unprocessed and current input data*/
        memcpy(inputData, context->cache_data, context->cache_data_len);
        inputData_len = context->cache_data_len;
        memcpy((inputData + inputData_len), srcData, (CIPHER_BLOCK_SIZE - context->cache_data_len));
        inputData_len += (CIPHER_BLOCK_SIZE - context->cache_data_len);
        src_offset += (CIPHER_BLOCK_SIZE - context->cache_data_len);
        context->cache_data_len = 0;

        blockoutLen = outBuffSize;
        ENSURE_OR_GO_EXIT(blockoutLen >= inputData_len);
        if (1 !=
            EVP_CipherUpdate(
                context->cipher_ctx, (destData + output_offset), (int *)&blockoutLen, inputData, (int)inputData_len)) {
            goto exit;
        }
        outBuffSize -= blockoutLen;
        output_offset += blockoutLen;

        while (srcLen - src_offset >= CIPHER_BLOCK_SIZE) {
            memcpy(inputData, (srcData + src_offset), 16);
            src_offset += CIPHER_BLOCK_SIZE;

            blockoutLen   = outBuffSize;
            inputData_len = CIPHER_BLOCK_SIZE;
            ENSURE_OR_GO_EXIT(blockoutLen >= inputData_len);
            if (1 != EVP_CipherUpdate(context->cipher_ctx,
                         (destData + output_offset),
                         (int *)&blockoutLen,
                         inputData,
                         (int)inputData_len)) {
                goto exit;
            }
            outBuffSize -= blockoutLen;
            output_offset += blockoutLen;
        }

        *destLen = output_offset;

        /* Copy unprocessed data to cache */
        if ((srcLen - src_offset) > 0) {
            memcpy(context->cache_data, (srcData + src_offset), (srcLen - src_offset));
            context->cache_data_len = (srcLen - src_offset);
        }
    }

    retval = kStatus_SSS_Success;
exit:
    if (retval == kStatus_SSS_Fail) {
        *destLen = 0;
    }
    return retval;
}

sss_status_t sss_openssl_cipher_finish(
    sss_openssl_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval                            = kStatus_SSS_Fail;
    uint8_t srcdata_updated[2 * CIPHER_BLOCK_SIZE] = {
        0,
    };
    size_t srcdata_updated_len          = 0;
    size_t outBuffSize                  = *destLen;
    size_t blockoutLen                  = 0;
    uint8_t dummyBuf[CIPHER_BLOCK_SIZE] = {
        0,
    };
    int dummyBufLen = sizeof(dummyBuf);

    if (srcLen > CIPHER_BLOCK_SIZE) {
        LOG_E("srcLen cannot be grater than 16 bytes. Call update function ");
        *destLen = 0;
        goto exit;
    }

    if (context->cache_data_len != 0) {
        memcpy(srcdata_updated, context->cache_data, context->cache_data_len);
        srcdata_updated_len     = context->cache_data_len;
        context->cache_data_len = 0;
    }
    if (srcLen != 0) {
        memcpy((srcdata_updated + srcdata_updated_len), srcData, srcLen);
        srcdata_updated_len += srcLen;
    }

    srcdata_updated_len = srcdata_updated_len + (CIPHER_BLOCK_SIZE - (srcdata_updated_len % 16));

    if (*destLen < srcdata_updated_len) {
        LOG_E("Output buffer not sufficient");
        goto exit;
    }

    if (srcdata_updated_len > 0) {
        blockoutLen = outBuffSize;
        ENSURE_OR_GO_EXIT(blockoutLen >= CIPHER_BLOCK_SIZE);
        if (1 !=
            EVP_CipherUpdate(context->cipher_ctx, destData, (int *)&blockoutLen, srcdata_updated, CIPHER_BLOCK_SIZE)) {
            goto exit;
        }
        *destLen = blockoutLen;
        outBuffSize -= blockoutLen;
    }

    if (srcdata_updated_len > CIPHER_BLOCK_SIZE) {
        blockoutLen = outBuffSize;
        ENSURE_OR_GO_EXIT(blockoutLen >= CIPHER_BLOCK_SIZE);
        if (1 != EVP_CipherUpdate(context->cipher_ctx,
                     destData + CIPHER_BLOCK_SIZE,
                     (int *)&blockoutLen,
                     srcdata_updated + CIPHER_BLOCK_SIZE,
                     CIPHER_BLOCK_SIZE)) {
            goto exit;
        }
        *destLen += blockoutLen;
        outBuffSize -= blockoutLen;
    }

    /* All data processed using EVP_CipherUpdate call. EVP_CipherFinal call will be dummy call.
       No encrypted/decrypted output will be generated */
    if (1 != EVP_CipherFinal(context->cipher_ctx, dummyBuf, &dummyBufLen)) {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_openssl_cipher_crypt_ctr(sss_openssl_symmetric_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *initialCounter,
    uint8_t *lastEncryptedCounter,
    size_t *szLeft)
{
    sss_status_t retval = kStatus_SSS_Fail;
    AES_KEY key;

    if (AES_set_encrypt_key(
            (uint8_t *)context->keyObject->contents, (int)(context->keyObject->contents_size * 8), &key) < 0) {
        goto exit;
    }

    switch (context->keyObject->keyBitLen) {
    case 128:
    case 192:
    case 256: {
        unsigned int iLeft = (unsigned int)*szLeft;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        AES_ctr128_encrypt(srcData, destData, size, &key, initialCounter, lastEncryptedCounter, &iLeft);
#else
        CRYPTO_ctr128_encrypt(
            srcData, destData, size, &key, initialCounter, lastEncryptedCounter, &iLeft, (block128_f)AES_encrypt);
#endif
        *szLeft = iLeft;
        break;
    }
    default:
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_openssl_symmetric_context_free(sss_openssl_symmetric_t *context)
{
    if (context->cipher_ctx != NULL) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)context->cipher_ctx);
        context->cipher_ctx = NULL;
    }
    memset(context, 0, sizeof(*context));
}

/* End: openssl_symm */

/* ************************************************************************** */
/* Functions : sss_openssl_aead                                               */
/* ************************************************************************** */

sss_status_t sss_openssl_aead_context_init(sss_openssl_aead_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    context->session    = session;
    context->keyObject  = keyObject;
    context->mode       = mode;
    if (algorithm == kAlgorithm_SSS_AES_GCM || algorithm == kAlgorithm_SSS_AES_CCM) {
        context->algorithm = algorithm;
    }
    else {
        LOG_E("AEAD improper algorithm passed!!!");
        goto exit;
    }
    /* Create and initialise the context */
    context->aead_ctx = EVP_CIPHER_CTX_new();
    ENSURE_OR_GO_EXIT(context->aead_ctx != NULL);
    context->pCcm_aad  = NULL;
    context->pCcm_data = NULL;
    context->pCcm_iv   = NULL;
    context->pCcm_tag  = NULL;
    retval             = sss_openssl_aead_init_ctx(context);

exit:
    return retval;
}

static sss_status_t sss_openssl_aead_init_ctx(sss_openssl_aead_t *context)
{
    sss_status_t retval         = kStatus_SSS_Fail;
    const EVP_CIPHER *aead_info = NULL;
    int ret                     = 0;
    if (context->algorithm == kAlgorithm_SSS_AES_GCM) {
        switch (context->keyObject->keyBitLen) {
        case 128:
            aead_info = EVP_aes_128_gcm();
            break;
        case 192:
            aead_info = EVP_aes_192_gcm();
            break;
        case 256:
            aead_info = EVP_aes_256_gcm();
            break;
        default:
            LOG_E("Improper key size!");
            goto exit;
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
        switch (context->keyObject->keyBitLen) {
        case 128:
            aead_info = EVP_aes_128_ccm();
            break;
        case 192:
            aead_info = EVP_aes_192_ccm();
            break;
        case 256:
            aead_info = EVP_aes_256_ccm();
            break;
        default:
            LOG_E("Improper key size!");
            goto exit;
        }
    }
    if (context->mode == kMode_SSS_Encrypt) {
        /* Initialise the encryption operation. */
        ret = EVP_EncryptInit_ex(context->aead_ctx, aead_info, NULL, NULL, NULL);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        /* Initialise the decryption operation. */
        ret = EVP_DecryptInit_ex(context->aead_ctx, aead_info, NULL, NULL, NULL);
    }
    ENSURE_OR_GO_EXIT(ret == 1);
    retval = kStatus_SSS_Success;

exit:
    return retval;
}

sss_status_t sss_openssl_aead_one_go(sss_openssl_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 0;

    /* Set IV length if default 96 bits is not appropriate */
    ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_GCM_SET_IVLEN, nonceLen, NULL);
    ENSURE_OR_GO_EXIT(ret == 1);
    context->pCcm_data = NULL;

    /* Check mode do the operation requested */
    if (context->mode == kMode_SSS_Encrypt) {
        retval = sss_openssl_aead_one_go_encrypt(
            context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        retval = sss_openssl_aead_one_go_decrypt(
            context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }

exit:
    return retval;
}

sss_status_t sss_openssl_aead_init(
    sss_openssl_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 0;

    if (context->algorithm == kAlgorithm_SSS_AES_GCM) {
        ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_GCM_SET_IVLEN, nonceLen, NULL);
        ENSURE_OR_GO_EXIT(ret == 1);
        context->cache_data_len = 0;
        memset(context->cache_data, 0x00, sizeof(context->cache_data));
        /* Initialise key and IV */
        {
            if (context->mode == kMode_SSS_Encrypt) {
                ret = EVP_EncryptInit_ex(context->aead_ctx, NULL, NULL, context->keyObject->contents, nonce);
            }
            else {
                ret = EVP_DecryptInit_ex(context->aead_ctx, NULL, NULL, context->keyObject->contents, nonce);
            }
            ENSURE_OR_GO_EXIT(ret == 1);
        }
    }
    if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
        context->pCcm_iv          = nonce;
        context->ccm_ivLen        = nonceLen;
        context->ccm_tagLen       = tagLen;
        context->ccm_aadLen       = aadLen;
        context->ccm_dataTotalLen = payloadLen;
        if (context->ccm_dataTotalLen) {
            context->pCcm_data = SSS_MALLOC(payloadLen);
            if (context->pCcm_data) {
                memset(context->pCcm_data, 0, payloadLen);
                context->ccm_dataoffset = 0;
            }
            else {
                LOG_E("malloc failed");
                goto exit;
            }
        }
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_openssl_aead_update_aad(sss_openssl_aead_t *context, const uint8_t *aadData, size_t aadDataLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 0;
    int len             = 0;

    /* Provide AAD data */
    if (context->algorithm == kAlgorithm_SSS_AES_GCM) {
        if (context->mode == kMode_SSS_Decrypt) {
            ret = EVP_DecryptUpdate(context->aead_ctx, NULL, &len, aadData, aadDataLen);
        }
        else {
            ret = EVP_EncryptUpdate(context->aead_ctx, NULL, &len, aadData, aadDataLen);
        }
        ENSURE_OR_GO_EXIT(ret == 1);
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
        context->pCcm_aad   = aadData;
        context->ccm_aadLen = aadDataLen;
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_openssl_aead_update(
    sss_openssl_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
#if SSS_HAVE_TESTCOUNTERPART
    uint8_t inputData[CIPHER_BLOCK_SIZE] = {
        0,
    };
    size_t inputData_len = 0;
    size_t src_offset    = 0;
    size_t output_offset = 0;
    size_t outBuffSize   = *destLen;
    size_t blockoutLen   = 0;
    int ret              = 0;

    /*Note for OpenSSL AES_CCM Update data is called only once*/
    if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
        if ((srcData != NULL) && (srcLen > 0)) {
            retval = sss_openssl_aead_ccm_update(context, srcData, srcLen);
        }
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);
        *destLen = 0;
    }
    else {
        if ((context->cache_data_len + srcLen) < CIPHER_BLOCK_SIZE) {
            /* Insufficinet data to process . Cache the data */
            memcpy((context->cache_data + context->cache_data_len), srcData, srcLen);
            context->cache_data_len = context->cache_data_len + srcLen;
            *destLen                = 0;
            return kStatus_SSS_Success;
        }
        else {
            /* Concatenate the unprocessed and current input data*/
            memcpy(inputData, context->cache_data, context->cache_data_len);
            inputData_len = context->cache_data_len;
            memcpy((inputData + inputData_len), srcData, (CIPHER_BLOCK_SIZE - context->cache_data_len));
            inputData_len += (CIPHER_BLOCK_SIZE - context->cache_data_len);
            src_offset += (CIPHER_BLOCK_SIZE - context->cache_data_len);
            blockoutLen = outBuffSize;

            /* Add Source Data */
            ret =
                aead_update(context, context->mode, inputData, inputData_len, (destData + output_offset), &blockoutLen);
            ENSURE_OR_GO_CLEANUP(ret == 1);
            outBuffSize -= blockoutLen;
            output_offset += blockoutLen;

            while (srcLen - src_offset >= CIPHER_BLOCK_SIZE) {
                memcpy(inputData, (srcData + src_offset), 16);
                src_offset += CIPHER_BLOCK_SIZE;
                blockoutLen = outBuffSize;

                /* Add Source Data */
                ret = aead_update(
                    context, context->mode, inputData, inputData_len, (destData + output_offset), &blockoutLen);
                ENSURE_OR_GO_CLEANUP(ret == 1);

                outBuffSize -= blockoutLen;
                output_offset += blockoutLen;
            }
            *destLen = output_offset;
            /* Copy unprocessed data to cache */
            memcpy(context->cache_data, (srcData + src_offset), (srcLen - src_offset));
            context->cache_data_len = (srcLen - src_offset);
        }
    }
    retval = kStatus_SSS_Success;

cleanup:
    if (retval == kStatus_SSS_Fail) {
        *destLen = 0;
    }
#endif /*End of SSS_HAVE_TESTCOUNTERPART*/
    return retval;
}
static sss_status_t sss_openssl_aead_ccm_update(sss_openssl_aead_t *context, const uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    if ((context->ccm_dataoffset + srcLen) <= (context->ccm_dataTotalLen)) {
        memcpy(context->pCcm_data + context->ccm_dataoffset, srcData, srcLen);
        context->ccm_dataoffset = context->ccm_dataoffset + srcLen;
        retval                  = kStatus_SSS_Success;
    }
    else {
        /*Free the allocated memory in init*/
        if (context->pCcm_data != NULL) {
            SSS_FREE(context->pCcm_data);
            context->pCcm_data = NULL;
        }
    }
    return retval;
}

static int aead_update(sss_openssl_aead_t *context,
    sss_mode_t mode,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen)
{
#if SSS_HAVE_TESTCOUNTERPART
    int ret = 0;
    int len = 0;
    if (context->mode == kMode_SSS_Encrypt) {
        ret = EVP_EncryptUpdate(context->aead_ctx, destData, &len, srcData, srcLen);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        ret = EVP_DecryptUpdate(context->aead_ctx, destData, &len, srcData, srcLen);
    }
    *destLen = len;
#endif /*SSS_HAVE_TESTCOUNTERPART*/
    return ret;
}

sss_status_t sss_openssl_aead_finish(sss_openssl_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
#if SSS_HAVE_TESTCOUNTERPART
    int ret = 0;

    uint8_t srcdata_updated[2 * CIPHER_BLOCK_SIZE] = {
        0,
    };
    size_t srcdata_updated_len = 0;
    int len                    = 0;
    if (context->algorithm == kAlgorithm_SSS_AES_CCM) { /* Check if finish has got source data */
        if ((srcData != NULL) && (srcLen > 0)) {
            retval = sss_openssl_aead_ccm_update(context, srcData, srcLen);
            ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);
        }
        retval = sss_openssl_aead_ccm_final(context, destData, destLen, tag, tagLen);
    }
    else {
        if (srcLen > CIPHER_BLOCK_SIZE) {
            LOG_E("srcLen cannot be grater than 16 bytes. Call update function ");
            *destLen = 0;
            goto exit;
        }

        if (context->cache_data_len != 0) {
            memcpy(srcdata_updated, context->cache_data, context->cache_data_len);
            srcdata_updated_len = context->cache_data_len;
        }

        if (srcLen != 0) {
            memcpy((srcdata_updated + srcdata_updated_len), srcData, srcLen);
            srcdata_updated_len += srcLen;
        }

        if (srcdata_updated_len % CIPHER_BLOCK_SIZE != 0) {
            srcdata_updated_len = srcdata_updated_len + (CIPHER_BLOCK_SIZE - (srcdata_updated_len % 16));
        }

        /* Add Source Data */
        ret = aead_update(context, context->mode, srcdata_updated, srcdata_updated_len, destData, destLen);
        ENSURE_OR_GO_EXIT(ret == 1);

        if (context->mode == kMode_SSS_Encrypt) {
            ret = EVP_EncryptFinal_ex(context->aead_ctx, destData, &len);
            ENSURE_OR_GO_EXIT(ret == 1);
            *destLen = len;
            ret      = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
            *tagLen  = EVP_CTRL_GCM_GET_TAG;
        }
        else if (context->mode == kMode_SSS_Decrypt) {
            ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_CCM_SET_TAG, *tagLen, tag);
            ENSURE_OR_GO_EXIT(ret == 1);
            /* Finalise decrypt */
            //ret = EVP_DecryptFinal_ex(context->aead_ctx, destData, &context->len);
        }
        //ENSURE_OR_GO_EXIT(ret == 1);
        retval = kStatus_SSS_Success;
    }
exit:
#endif /*SSS_HAVE_TESTCOUNTERPART*/
    return retval;
}

static sss_status_t sss_openssl_aead_ccm_final(
    sss_openssl_aead_t *context, uint8_t *destData, size_t *destLen, uint8_t *tag, size_t *tagLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
#if SSS_HAVE_TESTCOUNTERPART
    context->pCcm_tag = tag;
    if (context->mode == kMode_SSS_Decrypt) {
        retval = sss_openssl_aead_ccm_Decryptfinal(context, destData, destLen);
    }
    else {
        retval = sss_openssl_aead_ccm_Encryptfinal(context, destData, destLen);
        if (retval == kStatus_SSS_Success) {
            tag     = context->pCcm_tag;
            *tagLen = context->ccm_tagLen;
        }
    }
    ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);
    *destLen = context->ccm_dataTotalLen;
    retval   = kStatus_SSS_Success;
exit:
#endif /*SSS_HAVE_TESTCOUNTERPART*/
    return retval;
}

static sss_status_t sss_openssl_aead_ccm_Encryptfinal(sss_openssl_aead_t *context, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
#if SSS_HAVE_TESTCOUNTERPART
    int ret = 0;
    int len = 0;
    /*Set IV len */
    ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_CCM_SET_IVLEN, context->ccm_ivLen, NULL);
    ENSURE_OR_GO_EXIT(ret == 1)

    /* Set tag length */
    ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_CCM_SET_TAG, context->ccm_tagLen, NULL);
    ENSURE_OR_GO_EXIT(ret == 1)

    /* Initialise key and IV */
    ret = EVP_EncryptInit_ex(context->aead_ctx, NULL, NULL, context->keyObject->contents, context->pCcm_iv);
    ENSURE_OR_GO_EXIT(ret == 1);
    /* Provide the total plain length */
    ret = EVP_EncryptUpdate(context->aead_ctx, NULL, &len, NULL, context->ccm_dataTotalLen);
    ENSURE_OR_GO_EXIT(ret == 1);

    /* Provide any AAD data*/
    ret = EVP_EncryptUpdate(context->aead_ctx, NULL, &len, context->pCcm_aad, context->ccm_aadLen);
    ENSURE_OR_GO_EXIT(ret == 1);

    /* Provide the message to be decrypted*/
    ret = EVP_EncryptUpdate(context->aead_ctx, destData, &len, context->pCcm_data, context->ccm_dataTotalLen);
    ENSURE_OR_GO_EXIT(ret == 1);
    *destLen = len;
    len      = 0;
    ret      = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_CCM_GET_TAG, context->ccm_tagLen, context->pCcm_tag);

    ENSURE_OR_GO_EXIT(ret == 1);
    //context->ccm_tagLen = len;
    retval = kStatus_SSS_Success;
exit:
#endif /*SSS_HAVE_TESTCOUNTERPART*/
    return retval;
}

static sss_status_t sss_openssl_aead_ccm_Decryptfinal(sss_openssl_aead_t *context, uint8_t *destData, size_t *destLen)

{
    sss_status_t retval = kStatus_SSS_Fail;
#if SSS_HAVE_TESTCOUNTERPART
    int ret        = 0;
    int len        = 0;
    int payloadlen = context->ccm_dataTotalLen;

    /*Set IV len */
    ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_CCM_SET_IVLEN, context->ccm_ivLen, NULL);
    ENSURE_OR_GO_EXIT(ret == 1)
    /* Set expected tag value. */
    ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_CCM_SET_TAG, context->ccm_tagLen, context->pCcm_tag);
    ENSURE_OR_GO_EXIT(ret == 1);
    /* Initialise key and IV */
    ret = EVP_DecryptInit_ex(context->aead_ctx, NULL, NULL, context->keyObject->contents, context->pCcm_iv);
    ENSURE_OR_GO_EXIT(ret == 1);
    /* Provide the total ciphertext length */
    ret = EVP_DecryptUpdate(context->aead_ctx, NULL, &len, NULL, payloadlen);
    ENSURE_OR_GO_EXIT(ret == 1);

    /* Provide any AAD data*/
    ret = EVP_DecryptUpdate(context->aead_ctx, NULL, &len, context->pCcm_aad, context->ccm_aadLen);
    ENSURE_OR_GO_EXIT(ret == 1);
    /* Provide the message to be decrypted*/
    ret = EVP_DecryptUpdate(context->aead_ctx, destData, &len, context->pCcm_data, context->ccm_dataTotalLen);
    ENSURE_OR_GO_EXIT(ret == 1);
    *destLen = len;
    retval   = kStatus_SSS_Success;
exit:
#endif /*SSS_HAVE_TESTCOUNTERPART*/
    return retval;
}

void sss_openssl_aead_context_free(sss_openssl_aead_t *context)
{
    if (context->aead_ctx != NULL) {
        if ((context->algorithm == kAlgorithm_SSS_AES_CCM) && (context->pCcm_data != NULL)) {
            SSS_FREE(context->pCcm_data);
            context->pCcm_data = NULL;
        }
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)context->aead_ctx);
        context->aead_ctx = NULL;
    }
    memset(context, 0, sizeof(*context));
}

/* End: openssl_aead */

/* ************************************************************************** */
/* Functions : sss_openssl_mac                                                */
/* ************************************************************************** */

sss_status_t sss_openssl_mac_context_init(sss_openssl_mac_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    if (context != NULL) {
        if (algorithm == kAlgorithm_SSS_CMAC_AES) {
            context->cmac_ctx = CMAC_CTX_new();
        }
        if (algorithm == kAlgorithm_SSS_HMAC_SHA1 || algorithm == kAlgorithm_SSS_HMAC_SHA224 ||
            algorithm == kAlgorithm_SSS_HMAC_SHA256 || algorithm == kAlgorithm_SSS_HMAC_SHA384 ||
            algorithm == kAlgorithm_SSS_HMAC_SHA512) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
            context->hmac_ctx = SSS_MALLOC(sizeof(HMAC_CTX));
#else
            context->hmac_ctx = HMAC_CTX_new();
#endif
            if (context->hmac_ctx != NULL) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
                HMAC_CTX_init(context->hmac_ctx);
#endif
            }
        }
        context->session   = session;
        context->keyObject = keyObject;
        context->mode      = mode;
        context->algorithm = algorithm;
        retval             = kStatus_SSS_Success;
    }

    return retval;
}

sss_status_t sss_openssl_mac_one_go(
    sss_openssl_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 0;
    unsigned int iMacLen;
    const EVP_CIPHER *cipher_info = NULL;
    uint8_t *key;
    size_t keylen;

    if ((context == NULL) || (message == NULL) || (mac == NULL) || (macLen == NULL)) {
        goto cleanup;
    }

    if (context->keyObject->contents) {
        key    = context->keyObject->contents;
        keylen = context->keyObject->contents_size;
    }
    else {
        LOG_E("KeyObject key not created");
        goto cleanup;
    }

    iMacLen = (unsigned int)*macLen;
    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        if (context->cmac_ctx == NULL) {
            retval = kStatus_SSS_InvalidArgument;
        }
        else {
            if (!(keylen == 16 || keylen == 24 || keylen == 32)) {
                LOG_E("key bit not supported");
                goto cleanup;
            }

            switch (keylen * 8) {
            case 128:
                cipher_info = EVP_aes_128_cbc();
                break;
            case 192:
                cipher_info = EVP_aes_192_cbc();
                break;
            case 256:
                cipher_info = EVP_aes_256_cbc();
                break;
            }

            ret = CMAC_Init(
                context->cmac_ctx, context->keyObject->contents, context->keyObject->contents_size, cipher_info, NULL);
            if (ret == 1) {
                ret = CMAC_Update(context->cmac_ctx, message, messageLen);
                if (ret == 1) {
                    ret = CMAC_Final(context->cmac_ctx, mac, macLen);
                    if (ret == 1) {
                        retval = kStatus_SSS_Success;
                    }
                }
            }
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_HMAC_SHA1 || context->algorithm == kAlgorithm_SSS_HMAC_SHA224 ||
             context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384 ||
             context->algorithm == kAlgorithm_SSS_HMAC_SHA512) {
        iMacLen              = (unsigned int)*macLen;
        const EVP_MD *evp_md = NULL;
        switch (context->algorithm) {
        case kAlgorithm_SSS_HMAC_SHA1:
            evp_md = EVP_sha1();
            break;
        case kAlgorithm_SSS_HMAC_SHA224:
            evp_md = EVP_sha224();
            break;
        case kAlgorithm_SSS_HMAC_SHA256:
            evp_md = EVP_sha256();
            break;
        case kAlgorithm_SSS_HMAC_SHA384:
            evp_md = EVP_sha384();
            break;
        case kAlgorithm_SSS_HMAC_SHA512:
            evp_md = EVP_sha512();
            break;
        default:
            LOG_E("Invalid HMAC algorithm");
            retval = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (NULL != HMAC(evp_md,
                        context->keyObject->contents,
                        (int)context->keyObject->contents_size,
                        message,
                        messageLen,
                        mac,
                        &iMacLen)) {
            retval = kStatus_SSS_Success;
        }
        *macLen = iMacLen;
    }

cleanup:
    return retval;
}

sss_status_t sss_openssl_mac_init(sss_openssl_mac_t *context)
{
    sss_status_t retval           = kStatus_SSS_Fail;
    const EVP_CIPHER *cipher_info = NULL;
    int ret;
    uint8_t *key;
    size_t keylen;

    if (context->keyObject->contents) {
        key    = context->keyObject->contents;
        keylen = context->keyObject->contents_size;
    }
    else {
        LOG_E("KeyObject key not created");
        goto cleanup;
    }

    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        if (!(keylen == 16 || keylen == 24 || keylen == 32)) {
            LOG_E("key bit not supported");
            goto cleanup;
        }

        switch (keylen * 8) {
        case 128:
            cipher_info = EVP_aes_128_cbc();
            break;
        case 192:
            cipher_info = EVP_aes_192_cbc();
            break;
        case 256:
            cipher_info = EVP_aes_256_cbc();
            break;
        }

        if (context->cmac_ctx) {
            ret = CMAC_Init(
                context->cmac_ctx, context->keyObject->contents, context->keyObject->contents_size, cipher_info, NULL);
            if (ret == 1) {
                retval = kStatus_SSS_Success;
            }
        }
        else {
            LOG_W(
                "cipher context not allocated call "
                "sss_openssl_mac_context_init");
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_HMAC_SHA1 || context->algorithm == kAlgorithm_SSS_HMAC_SHA224 ||
             context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384 ||
             context->algorithm == kAlgorithm_SSS_HMAC_SHA512) {
        const EVP_MD *evp_md = NULL;
        switch (context->algorithm) {
        case kAlgorithm_SSS_HMAC_SHA1:
            evp_md = EVP_sha1();
            break;
        case kAlgorithm_SSS_HMAC_SHA224:
            evp_md = EVP_sha224();
            break;
        case kAlgorithm_SSS_HMAC_SHA256:
            evp_md = EVP_sha256();
            break;
        case kAlgorithm_SSS_HMAC_SHA384:
            evp_md = EVP_sha384();
            break;
        case kAlgorithm_SSS_HMAC_SHA512:
            evp_md = EVP_sha512();
            break;
        default:
            LOG_E("Invalid HMAC algorithm");
            retval = kStatus_SSS_Fail;
            goto cleanup;
        }

        ret = HMAC_Init_ex(
            context->hmac_ctx, context->keyObject->contents, (int)context->keyObject->contents_size, evp_md, NULL);
        if (ret == 1) {
            retval = kStatus_SSS_Success;
        }
        else {
            LOG_E(
                "cipher context not allocated, call "
                "sss_openssl_mac_context_init");
        }
    }

cleanup:
    return retval;
}

sss_status_t sss_openssl_mac_update(sss_openssl_mac_t *context, const uint8_t *message, size_t messageLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret;
    if (message == NULL) {
        return kStatus_SSS_InvalidArgument;
    }
    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        CMAC_CTX *ctx;
        ctx = context->cmac_ctx;

        ret = CMAC_Update(ctx, message, messageLen);
        if (ret == 1) {
            retval = kStatus_SSS_Success;
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_HMAC_SHA1 || context->algorithm == kAlgorithm_SSS_HMAC_SHA224 ||
             context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384 ||
             context->algorithm == kAlgorithm_SSS_HMAC_SHA512) {
        ret = HMAC_Update(context->hmac_ctx, message, messageLen);
        if (ret == 1) {
            retval = kStatus_SSS_Success;
        }
    }
    else {
        //invalid alogortihm
    }
    return retval;
}

sss_status_t sss_openssl_mac_finish(sss_openssl_mac_t *context, uint8_t *mac, size_t *macLen)
{
    int ret;
    sss_status_t retval = kStatus_SSS_Fail;
    if (mac == NULL || macLen == NULL) {
        return kStatus_SSS_InvalidArgument;
    }
    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        CMAC_CTX *ctx;
        ctx = context->cmac_ctx;

        ret = CMAC_Final(ctx, mac, macLen);
        if (ret == 1) {
            retval = kStatus_SSS_Success;
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_HMAC_SHA1 || context->algorithm == kAlgorithm_SSS_HMAC_SHA224 ||
             context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384 ||
             context->algorithm == kAlgorithm_SSS_HMAC_SHA512) {
        unsigned int iMacLen = (unsigned int)*macLen;
        ret                  = HMAC_Final(context->hmac_ctx, mac, &iMacLen);
        if (ret == 1) {
            retval = kStatus_SSS_Success;
        }
        *macLen = iMacLen;
    }
    else {
        //invalid alogortihm
    }
    return retval;
}

void sss_openssl_mac_context_free(sss_openssl_mac_t *context)
{
    if (context != NULL) {
        //sss_openssl_key_object_free(context->keyObject);
        if (context->algorithm == kAlgorithm_SSS_HMAC_SHA1 || context->algorithm == kAlgorithm_SSS_HMAC_SHA224 ||
            context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384 ||
            context->algorithm == kAlgorithm_SSS_HMAC_SHA512) {
            if (context->hmac_ctx != NULL) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
                HMAC_CTX_cleanup((HMAC_CTX *)context->hmac_ctx);

#else
                HMAC_CTX_free((HMAC_CTX *)context->hmac_ctx);
#endif
            }
        }
        else if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
            if (context->cmac_ctx != NULL) {
                CMAC_CTX_free((CMAC_CTX *)context->cmac_ctx);
            }
        }
        memset(context, 0, sizeof(*context));
    }
}

/* End: openssl_mac */

/* ************************************************************************** */
/* Functions : sss_openssl_md                                                 */
/* ************************************************************************** */

sss_status_t sss_openssl_digest_context_init(
    sss_openssl_digest_t *context, sss_openssl_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_CLEANUP(context);
    context->session   = session;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_openssl_digest_one_go(
    sss_openssl_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    sss_status_t retval     = kStatus_SSS_Fail;
    int ret                 = 0;
    unsigned int iDigestLen = (unsigned int)*digestLen;

    const EVP_MD *md;

    context->mdctx = EVP_MD_CTX_create();
    if (context->mdctx == NULL) {
        LOG_E("EVP_MD_CTX_create failed");
        goto exit;
    }

    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA1:
        md         = EVP_get_digestbyname("SHA1");
        *digestLen = 20;
        break;
    case kAlgorithm_SSS_SHA224:
        md         = EVP_get_digestbyname("SHA224");
        *digestLen = 28;
        break;
    case kAlgorithm_SSS_SHA256:
        md         = EVP_get_digestbyname("SHA256");
        *digestLen = 32;
        break;
    case kAlgorithm_SSS_SHA384:
        md         = EVP_get_digestbyname("SHA384");
        *digestLen = 48;
        break;
    case kAlgorithm_SSS_SHA512:
        md         = EVP_get_digestbyname("SHA512");
        *digestLen = 64;
        break;
    default:
        LOG_E(" Algorithm mode not suported ");
        goto exit;
    }

    if (md == NULL) {
        goto exit;
    }

    ret = EVP_DigestInit_ex(context->mdctx, md, NULL);
    if (ret != 1) {
        LOG_E(" EVP_DigestInit_ex failed ");
        goto exit;
    }

    ret = EVP_DigestUpdate(context->mdctx, message, messageLen);
    if (ret != 1) {
        LOG_E(" EVP_DigestUpdate failed ");
        goto exit;
    }

    ret = EVP_DigestFinal_ex(context->mdctx, digest, &iDigestLen);
    if (ret != 1) {
        LOG_E(" EVP_DigestFinal_ex failed ");
        goto exit;
    }
    *digestLen = iDigestLen;

    EVP_MD_CTX_destroy(context->mdctx);
    context->mdctx = NULL;

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_openssl_digest_init(sss_openssl_digest_t *context)
{
    sss_status_t retval = kStatus_SSS_Fail;
    const EVP_MD *md;
    int ret = 0;

    OpenSSL_add_all_algorithms();

    context->mdctx = EVP_MD_CTX_create();
    if (context->mdctx == NULL) {
        LOG_E(" EVP_MD_CTX_create failed ");
        goto exit;
    }

    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA1:
        md = EVP_get_digestbyname("SHA1");
        break;
    case kAlgorithm_SSS_SHA224:
        md = EVP_get_digestbyname("SHA224");
        break;
    case kAlgorithm_SSS_SHA256:
        md = EVP_get_digestbyname("SHA256");
        break;
    case kAlgorithm_SSS_SHA384:
        md = EVP_get_digestbyname("SHA384");
        break;
    case kAlgorithm_SSS_SHA512:
        md = EVP_get_digestbyname("SHA512");
        break;
    default:
        LOG_E(" Algorithm mode not suported ");
        goto exit;
    }

    ret = EVP_DigestInit_ex(context->mdctx, md, NULL);
    if (ret != 1) {
        LOG_E("EVP_DigestInit_ex failed ");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_openssl_digest_update(sss_openssl_digest_t *context, const uint8_t *message, size_t messageLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 0;

    ret = EVP_DigestUpdate(context->mdctx, message, messageLen);
    if (ret != 1) {
        LOG_E("EVP_DigestUpdate failed ");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_openssl_digest_finish(sss_openssl_digest_t *context, uint8_t *digest, size_t *digestLen)
{
    sss_status_t retval     = kStatus_SSS_Fail;
    int ret                 = 0;
    unsigned int iDigestLen = (unsigned int)*digestLen;

    ret = EVP_DigestFinal_ex(context->mdctx, digest, &iDigestLen);
    if (ret != 1) {
        LOG_E("EVP_DigestFinal_ex failed ");
        goto exit;
    }
    *digestLen = iDigestLen;

    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA1:
        *digestLen = 20;
        break;
    case kAlgorithm_SSS_SHA224:
        *digestLen = 28;
        break;
    case kAlgorithm_SSS_SHA256:
        *digestLen = 32;
        break;
    case kAlgorithm_SSS_SHA384:
        *digestLen = 48;
        break;
    case kAlgorithm_SSS_SHA512:
        *digestLen = 64;
        break;
    default:
        *digestLen = 0;
        LOG_E("Algorithm mode not suported ");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_openssl_digest_context_free(sss_openssl_digest_t *context)
{
    if (NULL != context->mdctx) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        EVP_MD_CTX_cleanup(context->mdctx);
#else
        EVP_MD_CTX_destroy(context->mdctx);
#endif
    }
    memset(context, 0, sizeof(*context));
}

/* End: openssl_md */

/* ************************************************************************** */
/* Functions : sss_openssl_rng                                                */
/* ************************************************************************** */

sss_status_t sss_openssl_rng_context_init(sss_openssl_rng_context_t *context, sss_openssl_session_t *session)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_CLEANUP(context);
    context->session = session;
    retval           = kStatus_SSS_Success;

cleanup:
    return retval;
}

sss_status_t sss_openssl_rng_get_random(sss_openssl_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
    sss_status_t retval = kStatus_SSS_Fail;

    if (random_data == NULL) {
        goto exit;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (0 == RAND_pseudo_bytes((unsigned char *)random_data, (int)dataLen)) {
        LOG_E("Error in RAND_pseudo_bytes ");
        goto exit;
    }
#else
    if (0 == RAND_bytes((unsigned char *)random_data, (int)dataLen)) {
        LOG_E("Error in RAND_pseudo_bytes ");
        goto exit;
    }
#endif

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_openssl_rng_context_free(sss_openssl_rng_context_t *context)
{
    sss_status_t retval = kStatus_SSS_Success;
    memset(context, 0, sizeof(*context));
    return retval;
}

/* End: openssl_rng */

/* ************************************************************************** */
/* Functions : Private sss openssl functions                                  */
/* ************************************************************************** */
static sss_status_t sss_openssl_generate_ecp_key(sss_openssl_object_t *keyObject, size_t keyBitLen)
{
    sss_status_t retval = kStatus_SSS_Success;
    EVP_PKEY *pKey      = NULL;
    EC_KEY *pEC_Key     = NULL;
    EC_GROUP *pEC_Group = NULL;
    int nid             = 0;
    int ret             = 0;

    /* Initilaize the EC Key. */
    pEC_Key = EC_KEY_new();
    if (pEC_Key == NULL) {
        retval = kStatus_SSS_Fail;
        LOG_E("Unable to initialize EC_Key");
        goto exit;
    }

    if (keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
        switch (keyBitLen) {
        case 192:
            nid = NID_X9_62_prime192v1;
            break;
        case 224:
            nid = NID_secp224r1;
            break;
        case 256:
            nid = NID_X9_62_prime256v1;
            break;
        case 384:
            nid = NID_secp384r1;
            break;
        case 521:
            nid = NID_secp521r1;
            break;
        default:
            LOG_E("Key type EC_NIST_P not supported with key length 0x%X", keyBitLen);
            retval = kStatus_SSS_Fail;
            goto exit;
        }
    }
    else if (keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        switch (keyBitLen) {
        case 192:
            nid = NID_brainpoolP192r1;
            break;
        case 224:
            nid = NID_brainpoolP224r1;
            break;
        case 320:
            nid = NID_brainpoolP320r1;
            break;
        case 384:
            nid = NID_brainpoolP384r1;
            break;
        case 160:
            nid = NID_brainpoolP160r1;
            break;
        case 256:
            nid = NID_brainpoolP256r1;
            break;
        case 512:
            nid = NID_brainpoolP512r1;
            break;
        default:
            LOG_E("Key type EC_BRAINPOOL not supported with key length 0x%X", keyBitLen);
            retval = kStatus_SSS_Fail;
            goto exit;
        }
    }
    else if (keyObject->cipherType == kSSS_CipherType_EC_NIST_K) {
        switch (keyBitLen) {
        case 160:
            nid = NID_secp160k1;
            break;
        case 192:
            nid = NID_secp192k1;
            break;
        case 224:
            nid = NID_secp224k1;
            break;
        case 256:
            nid = NID_secp256k1;
            break;
        default:
            LOG_E("Key type EC_NIST_K not supported with key length 0x%X", keyBitLen);
            retval = kStatus_SSS_Fail;
            goto exit;
        }
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    else if (keyObject->cipherType == kSSS_CipherType_EC_MONTGOMERY) {
        switch (keyBitLen) {
        case 256:
            nid = NID_X25519;
            break;
        case 448:
            nid = NID_X448;
            break;
        default:
            LOG_E("Key type EC_MONTGOMERY not supported with key length 0x%X", keyBitLen);
            retval = kStatus_SSS_Fail;
            goto exit;
        }
    }
    else if (keyObject->cipherType == kSSS_CipherType_EC_TWISTED_ED) {
        switch (keyBitLen) {
        case 256:
            nid = NID_ED25519;
            break;
        default:
            LOG_E("Key type EC_TWISTED_ED not supported with key length 0x%X", keyBitLen);
            retval = kStatus_SSS_Fail;
            goto exit;
        }
    }
#endif
    else {
        LOG_E("sss_openssl_generate_ecp_key: Invalid key type ");
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    if (nid == NID_X448 || nid == NID_X25519 || nid == NID_ED25519) {
        EVP_PKEY_CTX *pCtx = EVP_PKEY_CTX_new_id(nid, NULL);
        if (1 != EVP_PKEY_keygen_init(pCtx)) {
            retval = kStatus_SSS_Fail;
            LOG_E("Unable to generate keys.");
        }
        /* Assign the EC Key to generic Key context. */
        pKey = (EVP_PKEY *)keyObject->contents;
        if (1 != EVP_PKEY_keygen(pCtx, &pKey)) {
            retval = kStatus_SSS_Fail;
            LOG_E("Unable to generate keys.");
        }
        EVP_PKEY_CTX_free(pCtx);
        goto exit;
    }
#endif

    if (nid != 0) {
        /* Get the Group by curve name. */
        pEC_Group = EC_GROUP_new_by_curve_name(nid);
        if (pEC_Group == NULL) {
            retval = kStatus_SSS_Fail;
            LOG_E("sss_openssl_generate_ecp_key: unable to get the group.");
            goto exit;
        }
        EC_GROUP_set_asn1_flag(pEC_Group, OPENSSL_EC_NAMED_CURVE);

        /* Set the group to ECKey context. */
        if (EC_KEY_set_group(pEC_Key, pEC_Group) == 0) {
            retval = kStatus_SSS_Fail;
            LOG_E("sss_openssl_generate_ecp_key: unable set the group.");
            EC_KEY_free(pEC_Key);
            pEC_Key = NULL;
            goto exit;
        }

        /* Generate the EC keys. */
        ret = EC_KEY_generate_key(pEC_Key);
        if (!ret) {
            retval = kStatus_SSS_Fail;
            LOG_E("Unable to generate keys.");
            EC_KEY_free(pEC_Key);
            pEC_Key = NULL;
            goto exit;
        }

        /* Assign the EC Key to generic Key context. */
        pKey = (EVP_PKEY *)keyObject->contents;
        if (!EVP_PKEY_set1_EC_KEY(pKey, pEC_Key)) {
            retval = kStatus_SSS_Fail;
            LOG_E("Unable to assigning ECC key to EVP_PKEY context.");
            EC_GROUP_free(pEC_Group);
            EC_KEY_free(pEC_Key);
            pEC_Key   = NULL;
            pEC_Group = NULL;
            goto exit;
        }
    }
    else {
        LOG_E("No support for keyBitLen 0x%X", keyBitLen);
    }

exit:
    if (pEC_Group)
        EC_GROUP_free(pEC_Group);
    if (pEC_Key)
        EC_KEY_free(pEC_Key);
    return retval;
}

#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif

static sss_status_t sss_openssl_generate_rsa_key(sss_openssl_object_t *keyObject, size_t keyBitLen)
{
    sss_status_t retval   = kStatus_SSS_Success;
    EVP_PKEY *pKey        = NULL;
    RSA *pRSA             = NULL;
    BIGNUM *pBigNum       = NULL;
    char *pBuffer         = NULL;
    unsigned long ulError = 0;

    if (keyBitLen == 512 || keyBitLen == 1024 || keyBitLen == 1152 || keyBitLen == 2048 || keyBitLen == 3072 ||
        keyBitLen == 4096) {
        /* Load the error strings. */
        ERR_load_CRYPTO_strings();

        pRSA    = RSA_new();
        pBigNum = BN_new();

        if (1 != BN_set_word(pBigNum, RSA_F4)) {
            retval = kStatus_SSS_Fail;
            LOG_E("sss_openssl_generate_rsa_key: BigNum creation Failed.");
            goto exit;
        }

        /* Generate the Keys. */
        if (1 != RSA_generate_key_ex(pRSA, (int)keyBitLen, pBigNum, NULL)) {
            retval  = kStatus_SSS_Fail;
            ulError = ERR_get_error();
            pBuffer = (char *)ERR_error_string(ulError, (char *)pBuffer);
            LOG_E(" sss_openssl_generate_rsa_key");
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
            ERR_free_strings();
#endif
            BN_free(pBigNum);
            goto exit;
        }
        BN_clear_free(pBigNum);

        /* Assign the EC Key to generic Key context. */
        pKey = (EVP_PKEY *)keyObject->contents;
        if (!EVP_PKEY_set1_RSA(pKey, pRSA)) {
            retval = kStatus_SSS_Fail;
            LOG_E("Unable to assigning RSA key to EVP_PKEY context.");
            BN_free(pBigNum);
            RSA_free(pRSA);
            goto exit;
        }
    }
    else {
        LOG_E("No support for keyBitLen", keyBitLen);
        retval = kStatus_SSS_Fail;
    }

exit:
    RSA_free(pRSA);
    return retval;
}

sss_status_t openssl_convert_to_bio(sss_openssl_object_t *keyObject, char *base64_format, int base64_format_len)
{
    BIO *pBio_Pem       = NULL;
    EVP_PKEY *pKey      = NULL;
    char *pem_format    = NULL;
    char *start         = NULL;
    char *end           = NULL;
    sss_status_t ret    = kStatus_SSS_Fail;
    uint32_t objectType = keyObject->objectType;

    switch (objectType) {
    case kSSS_KeyPart_Public:
        start = BEGIN_PUBLIC;
        end   = END_PUBLIC;
        break;
    case kSSS_KeyPart_Private:
    case kSSS_KeyPart_Pair: {
        if (keyObject->cipherType == kSSS_CipherType_RSA || keyObject->cipherType == kSSS_CipherType_RSA_CRT) {
            start = BEGIN_RSA_PRIVATE;
            end   = END_RSA_PRIVATE;
            break;
        }
        else if (keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
                 keyObject->cipherType == kSSS_CipherType_EC_NIST_K ||
                 keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL ||
                 keyObject->cipherType == kSSS_CipherType_EC_MONTGOMERY ||
                 keyObject->cipherType == kSSS_CipherType_EC_TWISTED_ED) {
            start = BEGIN_EC_PRIVATE;
            end   = END_EC_PRIVATE;
            break;
        }
        else {
            goto exit;
        }
    }
    default:
        goto exit;
    }

    pem_format = (char *)SSS_CALLOC(1, base64_format_len + strlen(start) + strlen(end) + 1);
    /* Convert Base64 to PEM format. */
    snprintf(pem_format,
        (strlen(base64_format) + strlen(start) + strlen(end) + 1),
        "%s"
        "%s"
        "%s",
        start,
        base64_format,
        end);

    /* Assign the PEM_Format to BIO. */
    pBio_Pem = BIO_new_mem_buf(pem_format, (int)strlen(pem_format));
    if (pBio_Pem == NULL) {
        LOG_E("Unable to assign the PEM to BIO buffer.");
        goto exit;
    }

    if (objectType == kSSS_KeyPart_Public) {
        /* Convert the BIO to PKEY format. */
        pKey = PEM_read_bio_PUBKEY(pBio_Pem, NULL, NULL, NULL);
    }
    else {
        pKey = PEM_read_bio_PrivateKey(pBio_Pem, NULL, NULL, NULL);
    }

    if (pKey == NULL) {
        LOG_E("Unable to read the key from PEM.");
        goto exit;
    }

    EVP_PKEY_free((EVP_PKEY *)keyObject->contents);
    keyObject->contents = pKey;

    ret = kStatus_SSS_Success;
exit:

    BIO_free(pBio_Pem);
    pBio_Pem = NULL;

    if (pem_format)
        SSS_FREE(pem_format);

    return ret;
}

static sss_status_t sss_openssl_set_key(
    sss_openssl_object_t *keyObject, const uint8_t *keyBuf, size_t keyBufLen, size_t keyBitLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    char *base64_format = NULL;
    BIO *pBio_Mem = NULL, *pBio_64 = NULL;
    BUF_MEM *pBufMem = NULL;
    //EVP_PKEY *pKey = NULL;
    sss_status_t ret = kStatus_SSS_Fail;

    if (keyObject->objectType == kSSS_KeyPart_Default) {
        if (keyBufLen > keyObject->contents_max_size) {
            LOG_E("Not enough memory for key_size ", keyObject->contents_max_size);
            goto exit;
        }
        else {
            if (keyBuf != NULL) /* For Empty Certificate */
                memcpy(keyObject->contents, keyBuf, keyBufLen);
            keyObject->contents_size = keyBufLen;
        }
    }
    else if ((keyObject->objectType == kSSS_KeyPart_Private) || (keyObject->objectType == kSSS_KeyPart_Public) ||
             (keyObject->objectType == kSSS_KeyPart_Pair)) {
        pBio_64 = BIO_new(BIO_f_base64());
        if (pBio_64 == NULL) {
            LOG_E("Unable to initialize Base64 format.");
            goto exit;
        }
        BIO_set_flags(pBio_64, BIO_FLAGS_BASE64_NO_NL);
        //BIO_set_close(pBio_64, BIO_NOCLOSE);

        pBio_Mem = BIO_new(BIO_s_mem());
        if (pBio_Mem == NULL) {
            LOG_E("Unable to initialize Base64 mem format.");
            goto exit;
        }
        //BIO_set_close(pBio_Mem, BIO_NOCLOSE);

        pBio_64 = BIO_push(pBio_64, pBio_Mem);

        BIO_write(pBio_64, keyBuf, (int)keyBufLen);
        if (pBio_64 == NULL) {
            LOG_E(" sss_openssl_set_key: key write failure.");
            goto exit;
        }

        if (BIO_flush(pBio_64) < 1) {
            LOG_E("sss_openssl_set_key: flushing failed.");
            goto exit;
        }

        BIO_get_mem_ptr(pBio_64, &pBufMem);
        base64_format = SSS_CALLOC(1, (pBufMem->length) + 1);
        memcpy(base64_format, pBufMem->data, pBufMem->length);
        base64_format[pBufMem->length] = '\0';

        ret = openssl_convert_to_bio(keyObject, base64_format, (int)pBufMem->length);
        if (ret != kStatus_SSS_Success) {
            LOG_E(" sss_openssl_set_key: flushing failed.");
            goto exit;
        }
    }
    else {
        goto exit;
    }

    keyObject->keyBitLen = keyBitLen;

    retval = kStatus_SSS_Success;
exit:
    BIO_free(pBio_Mem);
    pBio_Mem = NULL;

    BIO_free(pBio_64);
    pBio_64 = NULL;

    if (base64_format)
        SSS_FREE(base64_format);

    return retval;
}

static sss_status_t sss_openssl_hkdf_extract(const EVP_MD *md,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t *prk,
    unsigned int *prk_len)
{
    int hash_len;
    unsigned char null_salt[EVP_MAX_MD_SIZE] = {'\0'};
    sss_status_t retval                      = kStatus_SSS_Success;

    hash_len = EVP_MD_size(md);

    if (salt == NULL) {
        salt     = null_salt;
        salt_len = hash_len;
    }

    unsigned int iPrkLen = *prk_len;
    if (HMAC(md, salt, (int)salt_len, ikm, (int)ikm_len, prk, &iPrkLen) == NULL) {
        retval = kStatus_SSS_Fail;
    }
    *prk_len = iPrkLen;

    return retval;
}

static sss_status_t sss_openssl_hkdf_expand(const EVP_MD *md,
    const uint8_t *prk,
    size_t prk_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len)
{
    size_t hash_len;
    size_t N;
    size_t T_len = 0, where = 0, i;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX hmac;
#else
    HMAC_CTX *hmac = NULL;
#endif
    unsigned char T[EVP_MAX_MD_SIZE];
    sss_status_t retval = kStatus_SSS_Success;

    if (info_len == 0 || okm_len == 0 || okm == NULL) {
        retval = kStatus_SSS_InvalidArgument;
        goto exit;
    }

    hash_len = EVP_MD_size(md);

    if (info == NULL) {
        info = (const unsigned char *)"";
    }

    N = okm_len / hash_len;

    if ((okm_len % hash_len) != 0) {
        N++;
    }

    if (N > 255) {
        retval = kStatus_SSS_InvalidArgument;
        goto exit;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_init(&hmac);
#else
    hmac           = HMAC_CTX_new();
    if (hmac == NULL) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (!HMAC_Init_ex(&hmac, prk, (int)prk_len, md, NULL)) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    /* Section 2.3. */
    for (i = 1; i <= N; i++) {
        unsigned char c = (unsigned char)i;

        if (i > 1) {
            if (!HMAC_Init_ex(&hmac, NULL, 0, NULL, NULL)) {
                retval = kStatus_SSS_Fail;
                goto exit;
            }

            if (!HMAC_Update(&hmac, T, T_len)) {
                retval = kStatus_SSS_Fail;
                goto exit;
            }
        }

        if (!HMAC_Update(&hmac, info, info_len)) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }

        if (!HMAC_Update(&hmac, &c, 1)) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }

        if (!HMAC_Final(&hmac, T, NULL)) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }

        memcpy(okm + where, T, (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        T_len = hash_len;
    }
#else
    if (!HMAC_Init_ex(hmac, prk, (int)prk_len, md, NULL)) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    /* Section 2.3. */
    for (i = 1; i <= N; i++) {
        unsigned char c = (unsigned char)i;

        if (i > 1) {
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL)) {
                retval = kStatus_SSS_Fail;
                goto exit;
            }

            if (!HMAC_Update(hmac, T, T_len)) {
                retval = kStatus_SSS_Fail;
                goto exit;
            }
        }

        if (!HMAC_Update(hmac, info, info_len)) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }

        if (!HMAC_Update(hmac, &c, 1)) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }

        if (!HMAC_Final(hmac, T, NULL)) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }

        memcpy(okm + where, T, (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        T_len = hash_len;
    }
#endif

exit:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_cleanup(&hmac);
#else
    HMAC_CTX_free(hmac);
#endif
    return retval;
}
static sss_status_t sss_openssl_aead_one_go_encrypt(sss_openssl_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 0;
    int len             = 0;
    size_t dest_len     = 0;
    /* Initialise key and IV */
    ret = EVP_EncryptInit_ex(context->aead_ctx, NULL, NULL, context->keyObject->contents, nonce);
    ENSURE_OR_GO_EXIT(ret == 1);
    if (aad != NULL) {
        /* Add AAD data.*/
        ret = EVP_EncryptUpdate(context->aead_ctx, NULL, &len, aad, aadLen);
        ENSURE_OR_GO_EXIT(ret == 1);
    }
    if (srcData != NULL) {
        /* Encrypt plaintext */
        ret = EVP_EncryptUpdate(context->aead_ctx, destData, &len, srcData, size);
        ENSURE_OR_GO_EXIT(ret == 1);
        dest_len = len;
    }

    /* Finalise the encryption */
    ret = EVP_EncryptFinal_ex(context->aead_ctx, tag, &len);
    ENSURE_OR_GO_EXIT(ret == 1);

    /* Get the tag */
    ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_GCM_GET_TAG, EVP_CTRL_GCM_GET_TAG, tag);
    ENSURE_OR_GO_EXIT(ret == 1);
    *tagLen = EVP_CTRL_GCM_GET_TAG;
    retval  = kStatus_SSS_Success;

exit:
    return retval;
}

static sss_status_t sss_openssl_aead_one_go_decrypt(sss_openssl_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 0;
    int len             = 0;

    /* Initialise key and IV */
    ret = EVP_DecryptInit_ex(context->aead_ctx, NULL, NULL, context->keyObject->contents, nonce);
    ENSURE_OR_GO_EXIT(ret == 1);

    /* Specify any AAD */
    if (aad != NULL) {
        ret = EVP_DecryptUpdate(context->aead_ctx, NULL, &len, aad, aadLen);
        ENSURE_OR_GO_EXIT(ret == 1);
    }

    /* Decrypt ciphertext */
    if (srcData != NULL) {
        ret = EVP_DecryptUpdate(context->aead_ctx, destData, &len, srcData, size);
        ENSURE_OR_GO_EXIT(ret == 1);
    }

    /* Set tag value. */
    ret = EVP_CIPHER_CTX_ctrl(context->aead_ctx, EVP_CTRL_CCM_SET_TAG, 16, tag);
    ENSURE_OR_GO_EXIT(ret == 1);

    /* Finalise decrypt */
    ret = EVP_DecryptFinal_ex(context->aead_ctx, destData, &len);
    ENSURE_OR_GO_EXIT(ret == 1);
    retval = kStatus_SSS_Success;

exit:
    return retval;
}

#endif /* SSS_HAVE_OPENSSL */
