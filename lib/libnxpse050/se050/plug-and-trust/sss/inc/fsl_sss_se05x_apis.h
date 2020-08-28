/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file */

#ifndef FSL_SSS_SE05X_APIS_H
#define FSL_SSS_SE05X_APIS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_se05x_types.h>

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */
/**
 * @addtogroup sss_se05x_session
 * @{
 */
/** @copydoc sss_session_create
 *
 */
sss_status_t sss_se05x_session_create(sss_se05x_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData);

/** @copydoc sss_session_open
 *
 */
sss_status_t sss_se05x_session_open(sss_se05x_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData);

/** @copydoc sss_session_prop_get_u32
 *
 */
sss_status_t sss_se05x_session_prop_get_u32(sss_se05x_session_t *session, uint32_t property, uint32_t *pValue);

/** @copydoc sss_session_prop_get_au8
 *
 */
sss_status_t sss_se05x_session_prop_get_au8(
    sss_se05x_session_t *session, uint32_t property, uint8_t *pValue, size_t *pValueLen);

/** @copydoc sss_session_close
 *
 */
void sss_se05x_session_close(sss_se05x_session_t *session);

/** @copydoc sss_session_delete
 *
 */
void sss_se05x_session_delete(sss_se05x_session_t *session);

/*! @} */ /* end of : sss_se05x_session */

/**
 * @addtogroup sss_se05x_keyobj
 * @{
 */
/** @copydoc sss_key_object_init
 *
 */
sss_status_t sss_se05x_key_object_init(sss_se05x_object_t *keyObject, sss_se05x_key_store_t *keyStore);

/** @copydoc sss_key_object_allocate_handle
 *
 * On SE050, the memory get reserved only when the actual object is created and
 * hence there is no memory reservation happening in this API call.  but
 * internally it checks if the object already exists or not . if the object is
 * already existing it returns a failure.
 *
 */
sss_status_t sss_se05x_key_object_allocate_handle(sss_se05x_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

/** @copydoc sss_key_object_get_handle
 *
 * On SE05X, this API uses @ref Se05x_API_ReadType and fetches
 * parameters of the API.
 *
 */
sss_status_t sss_se05x_key_object_get_handle(sss_se05x_object_t *keyObject, uint32_t keyId);

/** Not Available for SE05X
 *
 */
sss_status_t sss_se05x_key_object_set_user(sss_se05x_object_t *keyObject, uint32_t user, uint32_t options);

/** @copydoc sss_key_object_set_purpose
 *
 */
sss_status_t sss_se05x_key_object_set_purpose(sss_se05x_object_t *keyObject, sss_mode_t purpose, uint32_t options);

/** Not Available for SE05X
 *
 */
sss_status_t sss_se05x_key_object_set_access(sss_se05x_object_t *keyObject, uint32_t access, uint32_t options);

/** Not Available for SE05X
 *
 */
sss_status_t sss_se05x_key_object_set_eccgfp_group(sss_se05x_object_t *keyObject, sss_eccgfp_group_t *group);

/** Not Available for SE05X
 *
 */
sss_status_t sss_se05x_key_object_get_user(sss_se05x_object_t *keyObject, uint32_t *user);

/** Not Available for SE05X
 *
 */
sss_status_t sss_se05x_key_object_get_purpose(sss_se05x_object_t *keyObject, sss_mode_t *purpose);

/** Not Available for SE05X
 *
 */
sss_status_t sss_se05x_key_object_get_access(sss_se05x_object_t *keyObject, uint32_t *access);

/** @copydoc sss_key_object_free
 *
 * On SE050, this has no impact on physical Key Object.
 */
void sss_se05x_key_object_free(sss_se05x_object_t *keyObject);

/*! @} */ /* end of : sss_se05x_keyobj */

/**
 * @addtogroup sss_se05x_keyderive
 * @{
 */
/** @copydoc sss_derive_key_context_init
 *
 */
sss_status_t sss_se05x_derive_key_context_init(sss_se05x_derive_key_t *context,
    sss_se05x_session_t *session,
    sss_se05x_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_derive_key_go
 *
 */
sss_status_t sss_se05x_derive_key_go(sss_se05x_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_se05x_object_t *derivedKeyObject,
    uint16_t deriveDataLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen);

/** @copydoc sss_derive_key_one_go
 *
 */
sss_status_t sss_se05x_derive_key_one_go(sss_se05x_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_se05x_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @copydoc sss_derive_key_sobj_one_go
*
*/
sss_status_t sss_se05x_derive_key_sobj_one_go(sss_se05x_derive_key_t *context,
    sss_se05x_object_t *saltKeyObject,
    const uint8_t *info,
    size_t infoLen,
    sss_se05x_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @copydoc sss_derive_key_dh
 *
 */
sss_status_t sss_se05x_derive_key_dh(
    sss_se05x_derive_key_t *context, sss_se05x_object_t *otherPartyKeyObject, sss_se05x_object_t *derivedKeyObject);

/** @copydoc sss_derive_key_context_free
 *
 */
void sss_se05x_derive_key_context_free(sss_se05x_derive_key_t *context);

/*! @} */ /* end of : sss_se05x_keyderive */

/**
 * @addtogroup sss_se05x_keystore
 * @{
 */
/** @copydoc sss_key_store_context_init
 *
 */
sss_status_t sss_se05x_key_store_context_init(sss_se05x_key_store_t *keyStore, sss_se05x_session_t *session);

/** @copydoc sss_key_store_allocate
 *
 * This API does not do anything special on SE05X.
 */
sss_status_t sss_se05x_key_store_allocate(sss_se05x_key_store_t *keyStore, uint32_t keyStoreId);

/** @copydoc sss_key_store_save
 *
 * This API does not do anything special on SE05X.
 */
sss_status_t sss_se05x_key_store_save(sss_se05x_key_store_t *keyStore);

/** @copydoc sss_key_store_load
 *
 * This API does not do anything special on SE05X.
 */
sss_status_t sss_se05x_key_store_load(sss_se05x_key_store_t *keyStore);

/** @copydoc sss_key_store_set_key
 *
 */
sss_status_t sss_se05x_key_store_set_key(sss_se05x_key_store_t *keyStore,
    sss_se05x_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen);

/** @copydoc sss_key_store_generate_key
 *
 */
sss_status_t sss_se05x_key_store_generate_key(
    sss_se05x_key_store_t *keyStore, sss_se05x_object_t *keyObject, size_t keyBitLen, void *options);

/** @copydoc sss_key_store_get_key
 *
 */
sss_status_t sss_se05x_key_store_get_key(
    sss_se05x_key_store_t *keyStore, sss_se05x_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen);

/** @copydoc sss_key_store_open_key
 *
 * In SE05X, these keys can be used as KEK encryption key
 *
 * If ``keyObject`` == NULL, then subsequent key injection does not use any KEK.
 *
 * @return     The sss status.
 */
sss_status_t sss_se05x_key_store_open_key(sss_se05x_key_store_t *keyStore, sss_se05x_object_t *keyObject);

/** Not available for SE05X
 *
 */
sss_status_t sss_se05x_key_store_freeze_key(sss_se05x_key_store_t *keyStore, sss_se05x_object_t *keyObject);

/** @copydoc sss_key_store_erase_key
 *
 */
sss_status_t sss_se05x_key_store_erase_key(sss_se05x_key_store_t *keyStore, sss_se05x_object_t *keyObject);

/** @copydoc sss_key_store_context_free
 *
 */
void sss_se05x_key_store_context_free(sss_se05x_key_store_t *keyStore);

/** Export Key from SE050 to host
 *
 * Only Transient keys can be exported.
 */
sss_status_t sss_se05x_key_store_export_key(
    sss_se05x_key_store_t *keyStore, sss_se05x_object_t *keyObject, uint8_t *key, size_t *keylen);

/** Re Import previously exported SE05X key from host to the SE05X
 *
 * Only Transient keys can be imported.
 */
sss_status_t sss_se05x_key_store_import_key(
    sss_se05x_key_store_t *keyStore, sss_se05x_object_t *keyObject, uint8_t *key, size_t keylen);

/*! @} */ /* end of : sss_se05x_keystore */

/**
 * @addtogroup sss_se05x_asym
 * @{
 */
/** @copydoc sss_asymmetric_context_init
 *
 */
sss_status_t sss_se05x_asymmetric_context_init(sss_se05x_asymmetric_t *context,
    sss_se05x_session_t *session,
    sss_se05x_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_asymmetric_encrypt
 *
 */
sss_status_t sss_se05x_asymmetric_encrypt(
    sss_se05x_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_asymmetric_decrypt
 *
 */
sss_status_t sss_se05x_asymmetric_decrypt(
    sss_se05x_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_asymmetric_sign_digest
 *
 */
sss_status_t sss_se05x_asymmetric_sign_digest(
    sss_se05x_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc sss_asymmetric_verify_digest
 *
 */
sss_status_t sss_se05x_asymmetric_verify_digest(
    sss_se05x_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen);

/** @copydoc sss_asymmetric_context_free
 *
 */
void sss_se05x_asymmetric_context_free(sss_se05x_asymmetric_t *context);

/*! @} */ /* end of : sss_se05x_asym */

/**
 * @addtogroup sss_se05x_symm
 * @{
 */
/** @copydoc sss_symmetric_context_init
 *
 */
sss_status_t sss_se05x_symmetric_context_init(sss_se05x_symmetric_t *context,
    sss_se05x_session_t *session,
    sss_se05x_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_cipher_one_go
 *
 */
sss_status_t sss_se05x_cipher_one_go(sss_se05x_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t dataLen);

/** @copydoc sss_cipher_init
 *
 */
sss_status_t sss_se05x_cipher_init(sss_se05x_symmetric_t *context, uint8_t *iv, size_t ivLen);

/** @copydoc sss_cipher_update
 *
 */
sss_status_t sss_se05x_cipher_update(
    sss_se05x_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_cipher_finish
 *
 */
sss_status_t sss_se05x_cipher_finish(
    sss_se05x_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_cipher_crypt_ctr
 *
 */
sss_status_t sss_se05x_cipher_crypt_ctr(sss_se05x_symmetric_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *initialCounter,
    uint8_t *lastEncryptedCounter,
    size_t *szLeft);

/** @copydoc sss_symmetric_context_free
 *
 */
void sss_se05x_symmetric_context_free(sss_se05x_symmetric_t *context);

/*! @} */ /* end of : sss_se05x_symm */

/**
 * @addtogroup sss_se05x_aead
 * @{
 */
/** @copydoc sss_aead_context_init
 *
 */
sss_status_t sss_se05x_aead_context_init(sss_se05x_aead_t *context,
    sss_se05x_session_t *session,
    sss_se05x_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_aead_one_go
 *
 */
sss_status_t sss_se05x_aead_one_go(sss_se05x_aead_t *context,
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
sss_status_t sss_se05x_aead_init(
    sss_se05x_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

/** @copydoc sss_aead_update_aad
 *
 */
sss_status_t sss_se05x_aead_update_aad(sss_se05x_aead_t *context, const uint8_t *aadData, size_t aadDataLen);

/** @copydoc sss_aead_update
 *
 */
sss_status_t sss_se05x_aead_update(
    sss_se05x_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_aead_finish
 *
 */
sss_status_t sss_se05x_aead_finish(sss_se05x_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc sss_aead_context_free
 *
 */
void sss_se05x_aead_context_free(sss_se05x_aead_t *context);

/*! @} */ /* end of : sss_se05x_aead */

/**
 * @addtogroup sss_se05x_mac
 * @{
 */
/** @copydoc sss_mac_context_init
 *
 */
sss_status_t sss_se05x_mac_context_init(sss_se05x_mac_t *context,
    sss_se05x_session_t *session,
    sss_se05x_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_mac_one_go
 *
 */
sss_status_t sss_se05x_mac_one_go(
    sss_se05x_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_init
 *
 */
sss_status_t sss_se05x_mac_init(sss_se05x_mac_t *context);

/** @copydoc sss_mac_update
 *
 */
sss_status_t sss_se05x_mac_update(sss_se05x_mac_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc sss_mac_finish
 *
 */
sss_status_t sss_se05x_mac_finish(sss_se05x_mac_t *context, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_context_free
 *
 */
void sss_se05x_mac_context_free(sss_se05x_mac_t *context);

/*! @} */ /* end of : sss_se05x_mac */

/**
 * @addtogroup sss_se05x_md
 * @{
 */
/** @copydoc sss_digest_context_init
 *
 */
sss_status_t sss_se05x_digest_context_init(
    sss_se05x_digest_t *context, sss_se05x_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode);

/** @copydoc sss_digest_one_go
 *
 */
sss_status_t sss_se05x_digest_one_go(
    sss_se05x_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

/** @copydoc sss_digest_init
 *
 */
sss_status_t sss_se05x_digest_init(sss_se05x_digest_t *context);

/** @copydoc sss_digest_update
 *
 */
sss_status_t sss_se05x_digest_update(sss_se05x_digest_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc sss_digest_finish
 *
 */
sss_status_t sss_se05x_digest_finish(sss_se05x_digest_t *context, uint8_t *digest, size_t *digestLen);

/** @copydoc sss_digest_context_free
 *
 */
void sss_se05x_digest_context_free(sss_se05x_digest_t *context);

/*! @} */ /* end of : sss_se05x_md */

/**
 * @addtogroup sss_se05x_rng
 * @{
 */
/** @copydoc sss_rng_context_init
 *
 */
sss_status_t sss_se05x_rng_context_init(sss_se05x_rng_context_t *context, sss_se05x_session_t *session);

/** @copydoc sss_rng_get_random
 *
 */
sss_status_t sss_se05x_rng_get_random(sss_se05x_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/** @copydoc sss_rng_context_free
 *
 */
sss_status_t sss_se05x_rng_context_free(sss_se05x_rng_context_t *context);

/*! @} */ /* end of : sss_se05x_rng */

/**
* @addtogroup sss_se05x_tunnel
* @{
*/
/** @copydoc sss_tunnel_context_init
 *
 */
sss_status_t sss_se05x_tunnel_context_init(sss_se05x_tunnel_context_t *context, sss_se05x_session_t *session);

/** @copydoc sss_tunnel_context_free
*
*/
void sss_se05x_tunnel_context_free(sss_se05x_tunnel_context_t *context);

/*! @} */ /* end of : sss_se05x_tunnel */

sss_status_t sss_se05x_refresh_session(sss_se05x_session_t *session, void *connectionData);

/**
 * @addtogroup sss_se05x_tunnel
 * @{
 */

/** @copydoc sss_tunnel_context_init
 *
 */
sss_status_t sss_se05x_tunnel_context_init(sss_se05x_tunnel_context_t *context, sss_se05x_session_t *session);

/** @copydoc sss_tunnel_t
 *
 */
sss_status_t sss_se05x_tunnel(sss_se05x_tunnel_context_t *context,
    uint8_t *data,
    size_t dataLen,
    sss_se05x_object_t *keyObjects,
    uint32_t keyObjectCount,
    uint32_t tunnelType);

/** @copydoc sss_tunnel_context_free
 *
 */
void sss_se05x_tunnel_context_free(sss_se05x_tunnel_context_t *context);

/*! @} */ /* end of : sss_se05x_tunnel */

/** Set features of the Applet.
 *
 * See @ref Se05x_API_SetAppletFeatures
 */
sss_status_t sss_se05x_set_feature(
    sss_se05x_session_t *session, SE05x_Applet_Feature_t feature, SE05x_Applet_Feature_Disable_t disable_features);

SE05x_DigestMode_t se05x_get_sha_algo(sss_algorithm_t algorithm);

#if SSSFTR_SE05X_ECC
sss_status_t sss_se05x_key_store_create_curve(Se05xSession_t *pSession, uint32_t curve_id);
#endif

/* clang-format off */
#   if (SSS_HAVE_SSS == 1)
        /* Direct Call : session */
#       define sss_session_create(session,subsystem,application_id,connection_type,connectionData) \
            sss_se05x_session_create(((sss_se05x_session_t * ) session),(subsystem),(application_id),(connection_type),(connectionData))
#       define sss_session_open(session,subsystem,application_id,connection_type,connectionData) \
            sss_se05x_session_open(((sss_se05x_session_t * ) session),(subsystem),(application_id),(connection_type),(connectionData))
#       define sss_session_prop_get_u32(session,property,pValue) \
            sss_se05x_session_prop_get_u32(((sss_se05x_session_t * ) session),(property),(pValue))
#       define sss_session_prop_get_au8(session,property,pValue,pValueLen) \
            sss_se05x_session_prop_get_au8(((sss_se05x_session_t * ) session),(property),(pValue),(pValueLen))
#       define sss_session_close(session) \
            sss_se05x_session_close(((sss_se05x_session_t * ) session))
#       define sss_session_delete(session) \
            sss_se05x_session_delete(((sss_se05x_session_t * ) session))
        /* Direct Call : keyobj */
#       define sss_key_object_init(keyObject,keyStore) \
            sss_se05x_key_object_init(((sss_se05x_object_t * ) keyObject),((sss_se05x_key_store_t * ) keyStore))
#       define sss_key_object_allocate_handle(keyObject,keyId,keyPart,cipherType,keyByteLenMax,options) \
            sss_se05x_key_object_allocate_handle(((sss_se05x_object_t * ) keyObject),(keyId),(keyPart),(cipherType),(keyByteLenMax),(options))
#       define sss_key_object_get_handle(keyObject,keyId) \
            sss_se05x_key_object_get_handle(((sss_se05x_object_t * ) keyObject),(keyId))
#       define sss_key_object_set_user(keyObject,user,options) \
            sss_se05x_key_object_set_user(((sss_se05x_object_t * ) keyObject),(user),(options))
#       define sss_key_object_set_purpose(keyObject,purpose,options) \
            sss_se05x_key_object_set_purpose(((sss_se05x_object_t * ) keyObject),(purpose),(options))
#       define sss_key_object_set_access(keyObject,access,options) \
            sss_se05x_key_object_set_access(((sss_se05x_object_t * ) keyObject),(access),(options))
#       define sss_key_object_set_eccgfp_group(keyObject,group) \
            sss_se05x_key_object_set_eccgfp_group(((sss_se05x_object_t * ) keyObject),(group))
#       define sss_key_object_get_user(keyObject,user) \
            sss_se05x_key_object_get_user(((sss_se05x_object_t * ) keyObject),(user))
#       define sss_key_object_get_purpose(keyObject,purpose) \
            sss_se05x_key_object_get_purpose(((sss_se05x_object_t * ) keyObject),(purpose))
#       define sss_key_object_get_access(keyObject,access) \
            sss_se05x_key_object_get_access(((sss_se05x_object_t * ) keyObject),(access))
#       define sss_key_object_free(keyObject) \
            sss_se05x_key_object_free(((sss_se05x_object_t * ) keyObject))
        /* Direct Call : keyderive */
#       define sss_derive_key_context_init(context,session,keyObject,algorithm,mode) \
            sss_se05x_derive_key_context_init(((sss_se05x_derive_key_t * ) context),((sss_se05x_session_t * ) session),((sss_se05x_object_t * ) keyObject),(algorithm),(mode))
#       define sss_derive_key_go(context,saltData,saltLen,info,infoLen,derivedKeyObject,deriveDataLen,hkdfOutput,hkdfOutputLen) \
            sss_se05x_derive_key_go(((sss_se05x_derive_key_t * ) context),(saltData),(saltLen),(info),(infoLen),((sss_se05x_object_t * ) derivedKeyObject),(deriveDataLen),(hkdfOutput),(hkdfOutputLen))
#       define sss_derive_key_dh(context,otherPartyKeyObject,derivedKeyObject) \
            sss_se05x_derive_key_dh(((sss_se05x_derive_key_t * ) context),((sss_se05x_object_t * ) otherPartyKeyObject),((sss_se05x_object_t * ) derivedKeyObject))
#       define sss_derive_key_context_free(context) \
            sss_se05x_derive_key_context_free(((sss_se05x_derive_key_t * ) context))
        /* Direct Call : keystore */
#       define sss_key_store_context_init(keyStore,session) \
            sss_se05x_key_store_context_init(((sss_se05x_key_store_t * ) keyStore),((sss_se05x_session_t * ) session))
#       define sss_key_store_allocate(keyStore,keyStoreId) \
            sss_se05x_key_store_allocate(((sss_se05x_key_store_t * ) keyStore),(keyStoreId))
#       define sss_key_store_save(keyStore) \
            sss_se05x_key_store_save(((sss_se05x_key_store_t * ) keyStore))
#       define sss_key_store_load(keyStore) \
            sss_se05x_key_store_load(((sss_se05x_key_store_t * ) keyStore))
#       define sss_key_store_set_key(keyStore,keyObject,data,dataLen,keyBitLen,options,optionsLen) \
            sss_se05x_key_store_set_key(((sss_se05x_key_store_t * ) keyStore),((sss_se05x_object_t * ) keyObject),(data),(dataLen),(keyBitLen),(options),(optionsLen))
#       define sss_key_store_generate_key(keyStore,keyObject,keyBitLen,options) \
            sss_se05x_key_store_generate_key(((sss_se05x_key_store_t * ) keyStore),((sss_se05x_object_t * ) keyObject),(keyBitLen),(options))
#       define sss_key_store_get_key(keyStore,keyObject,data,dataLen,pKeyBitLen) \
            sss_se05x_key_store_get_key(((sss_se05x_key_store_t * ) keyStore),((sss_se05x_object_t * ) keyObject),(data),(dataLen),(pKeyBitLen))
#       define sss_key_store_open_key(keyStore,keyObject) \
            sss_se05x_key_store_open_key(((sss_se05x_key_store_t * ) keyStore),((sss_se05x_object_t * ) keyObject))
#       define sss_key_store_freeze_key(keyStore,keyObject) \
            sss_se05x_key_store_freeze_key(((sss_se05x_key_store_t * ) keyStore),((sss_se05x_object_t * ) keyObject))
#       define sss_key_store_erase_key(keyStore,keyObject) \
            sss_se05x_key_store_erase_key(((sss_se05x_key_store_t * ) keyStore),((sss_se05x_object_t * ) keyObject))
#       define sss_key_store_context_free(keyStore) \
            sss_se05x_key_store_context_free(((sss_se05x_key_store_t * ) keyStore))
        /* Direct Call : asym */
#       define sss_asymmetric_context_init(context,session,keyObject,algorithm,mode) \
            sss_se05x_asymmetric_context_init(((sss_se05x_asymmetric_t * ) context),((sss_se05x_session_t * ) session),((sss_se05x_object_t * ) keyObject),(algorithm),(mode))
#       define sss_asymmetric_encrypt(context,srcData,srcLen,destData,destLen) \
            sss_se05x_asymmetric_encrypt(((sss_se05x_asymmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_asymmetric_decrypt(context,srcData,srcLen,destData,destLen) \
            sss_se05x_asymmetric_decrypt(((sss_se05x_asymmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_asymmetric_sign_digest(context,digest,digestLen,signature,signatureLen) \
            sss_se05x_asymmetric_sign_digest(((sss_se05x_asymmetric_t * ) context),(digest),(digestLen),(signature),(signatureLen))
#       define sss_asymmetric_verify_digest(context,digest,digestLen,signature,signatureLen) \
            sss_se05x_asymmetric_verify_digest(((sss_se05x_asymmetric_t * ) context),(digest),(digestLen),(signature),(signatureLen))
#       define sss_asymmetric_context_free(context) \
            sss_se05x_asymmetric_context_free(((sss_se05x_asymmetric_t * ) context))
        /* Direct Call : symm */
#       define sss_symmetric_context_init(context,session,keyObject,algorithm,mode) \
            sss_se05x_symmetric_context_init(((sss_se05x_symmetric_t * ) context),((sss_se05x_session_t * ) session),((sss_se05x_object_t * ) keyObject),(algorithm),(mode))
#       define sss_cipher_one_go(context,iv,ivLen,srcData,destData,dataLen) \
            sss_se05x_cipher_one_go(((sss_se05x_symmetric_t * ) context),(iv),(ivLen),(srcData),(destData),(dataLen))
#       define sss_cipher_init(context,iv,ivLen) \
            sss_se05x_cipher_init(((sss_se05x_symmetric_t * ) context),(iv),(ivLen))
#       define sss_cipher_update(context,srcData,srcLen,destData,destLen) \
            sss_se05x_cipher_update(((sss_se05x_symmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_cipher_finish(context,srcData,srcLen,destData,destLen) \
            sss_se05x_cipher_finish(((sss_se05x_symmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_cipher_crypt_ctr(context,srcData,destData,size,initialCounter,lastEncryptedCounter,szLeft) \
            sss_se05x_cipher_crypt_ctr(((sss_se05x_symmetric_t * ) context),(srcData),(destData),(size),(initialCounter),(lastEncryptedCounter),(szLeft))
#       define sss_symmetric_context_free(context) \
            sss_se05x_symmetric_context_free(((sss_se05x_symmetric_t * ) context))
        /* Direct Call : aead */
#       define sss_aead_context_init(context,session,keyObject,algorithm,mode) \
            sss_se05x_aead_context_init(((sss_se05x_aead_t * ) context),((sss_se05x_session_t * ) session),((sss_se05x_object_t * ) keyObject),(algorithm),(mode))
#       define sss_aead_one_go(context,srcData,destData,size,nonce,nonceLen,aad,aadLen,tag,tagLen) \
            sss_se05x_aead_one_go(((sss_se05x_aead_t * ) context),(srcData),(destData),(size),(nonce),(nonceLen),(aad),(aadLen),(tag),(tagLen))
#       define sss_aead_init(context,nonce,nonceLen,tagLen,aadLen,payloadLen) \
            sss_se05x_aead_init(((sss_se05x_aead_t * ) context),(nonce),(nonceLen),(tagLen),(aadLen),(payloadLen))
#       define sss_aead_update_aad(context,aadData,aadDataLen) \
            sss_se05x_aead_update_aad(((sss_se05x_aead_t * ) context),(aadData),(aadDataLen))
#       define sss_aead_update(context,srcData,srcLen,destData,destLen) \
            sss_se05x_aead_update(((sss_se05x_aead_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_aead_finish(context,srcData,srcLen,destData,destLen,tag,tagLen) \
            sss_se05x_aead_finish(((sss_se05x_aead_t * ) context),(srcData),(srcLen),(destData),(destLen),(tag),(tagLen))
#       define sss_aead_context_free(context) \
            sss_se05x_aead_context_free(((sss_se05x_aead_t * ) context))
        /* Direct Call : mac */
#       define sss_mac_context_init(context,session,keyObject,algorithm,mode) \
            sss_se05x_mac_context_init(((sss_se05x_mac_t * ) context),((sss_se05x_session_t * ) session),((sss_se05x_object_t * ) keyObject),(algorithm),(mode))
#       define sss_mac_one_go(context,message,messageLen,mac,macLen) \
            sss_se05x_mac_one_go(((sss_se05x_mac_t * ) context),(message),(messageLen),(mac),(macLen))
#       define sss_mac_init(context) \
            sss_se05x_mac_init(((sss_se05x_mac_t * ) context))
#       define sss_mac_update(context,message,messageLen) \
            sss_se05x_mac_update(((sss_se05x_mac_t * ) context),(message),(messageLen))
#       define sss_mac_finish(context,mac,macLen) \
            sss_se05x_mac_finish(((sss_se05x_mac_t * ) context),(mac),(macLen))
#       define sss_mac_context_free(context) \
            sss_se05x_mac_context_free(((sss_se05x_mac_t * ) context))
        /* Direct Call : md */
#       define sss_digest_context_init(context,session,algorithm,mode) \
            sss_se05x_digest_context_init(((sss_se05x_digest_t * ) context),((sss_se05x_session_t * ) session),(algorithm),(mode))
#       define sss_digest_one_go(context,message,messageLen,digest,digestLen) \
            sss_se05x_digest_one_go(((sss_se05x_digest_t * ) context),(message),(messageLen),(digest),(digestLen))
#       define sss_digest_init(context) \
            sss_se05x_digest_init(((sss_se05x_digest_t * ) context))
#       define sss_digest_update(context,message,messageLen) \
            sss_se05x_digest_update(((sss_se05x_digest_t * ) context),(message),(messageLen))
#       define sss_digest_finish(context,digest,digestLen) \
            sss_se05x_digest_finish(((sss_se05x_digest_t * ) context),(digest),(digestLen))
#       define sss_digest_context_free(context) \
            sss_se05x_digest_context_free(((sss_se05x_digest_t * ) context))
        /* Direct Call : rng */
#       define sss_rng_context_init(context,session) \
            sss_se05x_rng_context_init(((sss_se05x_rng_context_t * ) context),((sss_se05x_session_t * ) session))
#       define sss_rng_get_random(context,random_data,dataLen) \
            sss_se05x_rng_get_random(((sss_se05x_rng_context_t * ) context),(random_data),(dataLen))
#       define sss_rng_context_free(context) \
            sss_se05x_rng_context_free(((sss_se05x_rng_context_t * ) context))
        /* Direct Call : tunnel */
#       define sss_tunnel_context_init(context,session) \
            sss_se05x_tunnel_context_init(((sss_se05x_tunnel_context_t * ) context),((sss_se05x_session_t * ) session))
#       define sss_tunnel(context,data,dataLen,keyObjects,keyObjectCount,tunnelType) \
            sss_se05x_tunnel(((sss_se05x_tunnel_context_t * ) context),(data),(dataLen),((sss_se05x_object_t * ) keyObjects),(keyObjectCount),(tunnelType))
#       define sss_tunnel_context_free(context) \
            sss_se05x_tunnel_context_free(((sss_se05x_tunnel_context_t * ) context))
#   endif /* (SSS_HAVE_SSS == 1) */
/* clang-format on */
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#ifdef __cplusplus
} // extern "C"
#endif /* __cplusplus */

#endif /* FSL_SSS_SE05X_APIS_H */
