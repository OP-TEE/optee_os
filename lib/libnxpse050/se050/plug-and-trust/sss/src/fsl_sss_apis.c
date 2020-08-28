/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <fsl_sss_api.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_SSCP
#include <fsl_sss_sscp.h>
#endif /* SSS_HAVE_SSCP */

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_se05x_apis.h>
#endif /* SSS_HAVE_APPLET_SE05X_IOT */

#if SSS_HAVE_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#endif /* SSS_HAVE_MBEDTLS */

#if SSS_HAVE_OPENSSL
#include <fsl_sss_openssl_apis.h>
#endif /* SSS_HAVE_OPENSSL */

#if defined(FLOW_VERBOSE)
#define NX_LOG_ENABLE_SSS_DEBUG 1
#endif
#include "nxLog_sss.h"

#if (SSS_HAVE_SSS > 1)

sss_status_t sss_session_create(sss_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    if (kType_SSS_Software == subsystem) {
#if SSS_HAVE_OPENSSL
        /* if I have openSSL */
        subsystem = kType_SSS_OpenSSL;
#endif
#if SSS_HAVE_MBEDTLS
        /* if I have mbed TLS */
        subsystem = kType_SSS_mbedTLS;
#endif
    }
    else if (kType_SSS_SecureElement == subsystem) {
#if SSS_HAVE_APPLET_SE05X_IOT
        subsystem = kType_SSS_SE_SE05x;
#endif
#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
        subsystem = kType_SSS_SE_A71CH;
#endif
    }

#if SSS_HAVE_SSCP
    if (SSS_SUBSYSTEM_TYPE_IS_SSCP(subsystem)) {
        return kStatus_SSS_Success; /* Nothing special to be handled yet */
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SUBSYSTEM_TYPE_IS_SE05X(subsystem)) {
        return kStatus_SSS_Success; /* Nothing special to be handled yet */
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SUBSYSTEM_TYPE_IS_MBEDTLS(subsystem)) {
        return kStatus_SSS_Success; /* Nothing special to be handled yet */
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SUBSYSTEM_TYPE_IS_OPENSSL(subsystem)) {
        return kStatus_SSS_Success; /* Nothing special to be handled yet */
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_session_open(sss_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    if (kType_SSS_Software == subsystem) {
#if SSS_HAVE_OPENSSL
        /* if I have openSSL */
        subsystem = kType_SSS_OpenSSL;
#endif
#if SSS_HAVE_MBEDTLS
        /* if I have mbed TLS */
        subsystem = kType_SSS_mbedTLS;
#endif
    }
    else if (kType_SSS_SecureElement == subsystem) {
#if SSS_HAVE_SE

        subsystem = kType_SSS_SE_SE05x;
#endif
#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
        subsystem = kType_SSS_SE_A71CH;
#endif
    }

#if SSS_HAVE_SSCP
    if (SSS_SUBSYSTEM_TYPE_IS_SSCP(subsystem)) {
        sss_sscp_session_t *sscp_session = (sss_sscp_session_t *)session;
        return sss_sscp_session_open(sscp_session, subsystem, application_id, connection_type, connectionData);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SUBSYSTEM_TYPE_IS_SE05X(subsystem)) {
        sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)session;
        return sss_se05x_session_open(se05x_session, subsystem, application_id, connection_type, connectionData);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SUBSYSTEM_TYPE_IS_MBEDTLS(subsystem)) {
        sss_mbedtls_session_t *mbedtls_session = (sss_mbedtls_session_t *)session;
        return sss_mbedtls_session_open(mbedtls_session, subsystem, application_id, connection_type, connectionData);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SUBSYSTEM_TYPE_IS_OPENSSL(subsystem)) {
        sss_openssl_session_t *openssl_session = (sss_openssl_session_t *)session;
        return sss_openssl_session_open(openssl_session, subsystem, application_id, connection_type, connectionData);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_session_prop_get_u32(sss_session_t *session, uint32_t property, uint32_t *pValue)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_session_t *sscp_session = (sss_sscp_session_t *)session;
        return sss_sscp_session_prop_get_u32(sscp_session, property, pValue);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)session;
        return sss_se05x_session_prop_get_u32(se05x_session, property, pValue);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_session_t *mbedtls_session = (sss_mbedtls_session_t *)session;
        return sss_mbedtls_session_prop_get_u32(mbedtls_session, property, pValue);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_session_t *openssl_session = (sss_openssl_session_t *)session;
        return sss_openssl_session_prop_get_u32(openssl_session, property, pValue);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_session_prop_get_au8(sss_session_t *session, uint32_t property, uint8_t *pValue, size_t *pValueLen)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_session_t *sscp_session = (sss_sscp_session_t *)session;
        return sss_sscp_session_prop_get_au8(sscp_session, property, pValue, pValueLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)session;
        return sss_se05x_session_prop_get_au8(se05x_session, property, pValue, pValueLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_session_t *mbedtls_session = (sss_mbedtls_session_t *)session;
        return sss_mbedtls_session_prop_get_au8(mbedtls_session, property, pValue, pValueLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_session_t *openssl_session = (sss_openssl_session_t *)session;
        return sss_openssl_session_prop_get_au8(openssl_session, property, pValue, pValueLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_session_close(sss_session_t *session)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_session_t *sscp_session = (sss_sscp_session_t *)session;
        sss_sscp_session_close(sscp_session);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)session;
        sss_se05x_session_close(se05x_session);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_session_t *mbedtls_session = (sss_mbedtls_session_t *)session;
        sss_mbedtls_session_close(mbedtls_session);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_session_t *openssl_session = (sss_openssl_session_t *)session;
        sss_openssl_session_close(openssl_session);
    }
#endif /* SSS_HAVE_OPENSSL */
}

void sss_session_delete(sss_session_t *session)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        /* Nothing special to be handled */
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        /* Nothing special to be handled */
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        /* Nothing special to be handled */
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        /* Nothing special to be handled */
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_key_object_init(sss_object_t *keyObject, sss_key_store_t *keyStore)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*sscp_keyObject) <= sizeof(*keyObject));
        SSS_ASSERT(sizeof(*sscp_keyStore) <= sizeof(*keyStore));
        return sss_sscp_key_object_init(sscp_keyObject, sscp_keyStore);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*se05x_keyObject) <= sizeof(*keyObject));
        SSS_ASSERT(sizeof(*se05x_keyStore) <= sizeof(*keyStore));
        return sss_se05x_key_object_init(se05x_keyObject, se05x_keyStore);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        return sss_mbedtls_key_object_init(mbedtls_keyObject, mbedtls_keyStore);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        return sss_openssl_key_object_init(openssl_keyObject, openssl_keyStore);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_allocate_handle(sss_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_allocate_handle(sscp_keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT && SSSFTR_SE05X_KEY_SET
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_allocate_handle(
            se05x_keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_allocate_handle(
            mbedtls_keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_allocate_handle(
            openssl_keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_get_handle(sss_object_t *keyObject, uint32_t keyId)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_get_handle(sscp_keyObject, keyId);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT && SSSFTR_SE05X_KEY_GET
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_get_handle(se05x_keyObject, keyId);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_get_handle(mbedtls_keyObject, keyId);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_get_handle(openssl_keyObject, keyId);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_set_user(sss_object_t *keyObject, uint32_t user, uint32_t options)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_set_user(sscp_keyObject, user, options);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_set_user(se05x_keyObject, user, options);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_set_user(mbedtls_keyObject, user, options);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_set_user(openssl_keyObject, user, options);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_set_purpose(sss_object_t *keyObject, sss_mode_t purpose, uint32_t options)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_set_purpose(sscp_keyObject, purpose, options);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_set_purpose(se05x_keyObject, purpose, options);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_set_purpose(mbedtls_keyObject, purpose, options);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_set_purpose(openssl_keyObject, purpose, options);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_set_access(sss_object_t *keyObject, uint32_t access, uint32_t options)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_set_access(sscp_keyObject, access, options);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_set_access(se05x_keyObject, access, options);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_set_access(mbedtls_keyObject, access, options);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_set_access(openssl_keyObject, access, options);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_set_eccgfp_group(sss_object_t *keyObject, sss_eccgfp_group_t *group)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_set_eccgfp_group(sscp_keyObject, group);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_set_eccgfp_group(se05x_keyObject, group);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_set_eccgfp_group(mbedtls_keyObject, group);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_set_eccgfp_group(openssl_keyObject, group);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_get_user(sss_object_t *keyObject, uint32_t *user)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_get_user(sscp_keyObject, user);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_get_user(se05x_keyObject, user);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_get_user(mbedtls_keyObject, user);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_get_user(openssl_keyObject, user);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_get_purpose(sss_object_t *keyObject, sss_mode_t *purpose)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_get_purpose(sscp_keyObject, purpose);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_get_purpose(se05x_keyObject, purpose);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_get_purpose(mbedtls_keyObject, purpose);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_get_purpose(openssl_keyObject, purpose);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_get_access(sss_object_t *keyObject, uint32_t *access)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_object_get_access(sscp_keyObject, access);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_object_get_access(se05x_keyObject, access);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_object_get_access(mbedtls_keyObject, access);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_object_get_access(openssl_keyObject, access);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_key_object_free(sss_object_t *keyObject)
{
#if SSS_HAVE_SSCP
    if (SSS_OBJECT_TYPE_IS_SSCP(keyObject)) {
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        sss_sscp_key_object_free(sscp_keyObject);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_OBJECT_TYPE_IS_SE05X(keyObject)) {
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        sss_se05x_key_object_free(se05x_keyObject);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        sss_mbedtls_key_object_free(mbedtls_keyObject);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        sss_openssl_key_object_free(openssl_keyObject);
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_derive_key_context_init(sss_derive_key_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_derive_key_t *sscp_context = (sss_sscp_derive_key_t *)context;
        sss_sscp_session_t *sscp_session    = (sss_sscp_session_t *)session;
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*sscp_keyObject) <= sizeof(*keyObject));
        return sss_sscp_derive_key_context_init(sscp_context, sscp_session, sscp_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_derive_key_t *se05x_context = (sss_se05x_derive_key_t *)context;
        sss_se05x_session_t *se05x_session    = (sss_se05x_session_t *)session;
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*se05x_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*se05x_keyObject) <= sizeof(*keyObject));
        return sss_se05x_derive_key_context_init(se05x_context, se05x_session, se05x_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_derive_key_t *mbedtls_context = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_session_t *mbedtls_session    = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_derive_key_context_init(
            mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_derive_key_t *openssl_context = (sss_openssl_derive_key_t *)context;
        sss_openssl_session_t *openssl_session    = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_derive_key_context_init(
            openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_derive_key_go(sss_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen)
{
#if SSS_HAVE_SSCP
    if (SSS_DERIVE_KEY_TYPE_IS_SSCP(context)) {
        sss_sscp_derive_key_t *sscp_context      = (sss_sscp_derive_key_t *)context;
        sss_sscp_object_t *sscp_derivedKeyObject = (sss_sscp_object_t *)derivedKeyObject;
        return sss_sscp_derive_key_go(sscp_context,
            saltData,
            saltLen,
            info,
            infoLen,
            sscp_derivedKeyObject,
            deriveDataLen,
            hkdfOutput,
            hkdfOutputLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DERIVE_KEY_TYPE_IS_SE05X(context)) {
        sss_se05x_derive_key_t *se05x_context      = (sss_se05x_derive_key_t *)context;
        sss_se05x_object_t *se05x_derivedKeyObject = (sss_se05x_object_t *)derivedKeyObject;
        return sss_se05x_derive_key_go(se05x_context,
            saltData,
            saltLen,
            info,
            infoLen,
            se05x_derivedKeyObject,
            deriveDataLen,
            hkdfOutput,
            hkdfOutputLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context      = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_object_t *mbedtls_derivedKeyObject = (sss_mbedtls_object_t *)derivedKeyObject;
        return sss_mbedtls_derive_key_go(mbedtls_context,
            saltData,
            saltLen,
            info,
            infoLen,
            mbedtls_derivedKeyObject,
            deriveDataLen,
            hkdfOutput,
            hkdfOutputLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context      = (sss_openssl_derive_key_t *)context;
        sss_openssl_object_t *openssl_derivedKeyObject = (sss_openssl_object_t *)derivedKeyObject;
        return sss_openssl_derive_key_go(openssl_context,
            saltData,
            saltLen,
            info,
            infoLen,
            openssl_derivedKeyObject,
            deriveDataLen,
            hkdfOutput,
            hkdfOutputLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

/*
  Salt is public information and is passed as an array.
*/
sss_status_t sss_derive_key_one_go(sss_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen)
{
#if SSS_HAVE_SSCP
    if (SSS_DERIVE_KEY_TYPE_IS_SSCP(context)) {
        sss_sscp_derive_key_t *sscp_context      = (sss_sscp_derive_key_t *)context;
        sss_sscp_object_t *sscp_derivedKeyObject = (sss_sscp_object_t *)derivedKeyObject;
        return sss_sscp_derive_key_one_go(
            sscp_context, saltData, saltLen, info, infoLen, sscp_derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DERIVE_KEY_TYPE_IS_SE05X(context)) {
        sss_se05x_derive_key_t *se05x_context      = (sss_se05x_derive_key_t *)context;
        sss_se05x_object_t *se05x_derivedKeyObject = (sss_se05x_object_t *)derivedKeyObject;
        return sss_se05x_derive_key_one_go(
            se05x_context, saltData, saltLen, info, infoLen, se05x_derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context      = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_object_t *mbedtls_derivedKeyObject = (sss_mbedtls_object_t *)derivedKeyObject;
        return sss_mbedtls_derive_key_one_go(
            mbedtls_context, saltData, saltLen, info, infoLen, mbedtls_derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context      = (sss_openssl_derive_key_t *)context;
        sss_openssl_object_t *openssl_derivedKeyObject = (sss_openssl_object_t *)derivedKeyObject;
        return sss_openssl_derive_key_one_go(
            openssl_context, saltData, saltLen, info, infoLen, openssl_derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_derive_key_sobj_one_go(sss_derive_key_t *context,
    sss_object_t *saltKeyObject,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen)
{
#if SSS_HAVE_SSCP
    if (SSS_DERIVE_KEY_TYPE_IS_SSCP(context)) {
        sss_sscp_derive_key_t *sscp_context      = (sss_sscp_derive_key_t *)context;
        sss_sscp_object_t *sscp_derivedKeyObject = (sss_sscp_object_t *)derivedKeyObject;
        sss_sscp_object_t *sscp_saltKeyObject    = (sss_sscp_object_t *)saltKeyObject;
        return sss_sscp_derive_key_sobj_one_go(
            sscp_context, sscp_saltKeyObject, info, infoLen, sscp_derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DERIVE_KEY_TYPE_IS_SE05X(context)) {
        sss_se05x_derive_key_t *se05x_context      = (sss_se05x_derive_key_t *)context;
        sss_se05x_object_t *se05x_derivedKeyObject = (sss_se05x_object_t *)derivedKeyObject;
        sss_se05x_object_t *se05x_saltKeyObject    = (sss_se05x_object_t *)saltKeyObject;
        return sss_se05x_derive_key_sobj_one_go(
            se05x_context, se05x_saltKeyObject, info, infoLen, se05x_derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context      = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_object_t *mbedtls_derivedKeyObject = (sss_mbedtls_object_t *)derivedKeyObject;
        sss_mbedtls_object_t *mbedtls_saltKeyObject    = (sss_mbedtls_object_t *)saltKeyObject;
        return sss_mbedtls_derive_key_sobj_one_go(
            mbedtls_context, mbedtls_saltKeyObject, info, infoLen, mbedtls_derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context      = (sss_openssl_derive_key_t *)context;
        sss_openssl_object_t *openssl_derivedKeyObject = (sss_openssl_object_t *)derivedKeyObject;
        sss_openssl_object_t *openssl_saltKeyObject    = (sss_openssl_object_t *)saltKeyObject;
        return sss_openssl_derive_key_sobj_one_go(
            openssl_context, openssl_saltKeyObject, info, infoLen, openssl_derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_derive_key_dh(
    sss_derive_key_t *context, sss_object_t *otherPartyKeyObject, sss_object_t *derivedKeyObject)
{
#if SSS_HAVE_SSCP
    if (SSS_DERIVE_KEY_TYPE_IS_SSCP(context)) {
        sss_sscp_derive_key_t *sscp_context         = (sss_sscp_derive_key_t *)context;
        sss_sscp_object_t *sscp_otherPartyKeyObject = (sss_sscp_object_t *)otherPartyKeyObject;
        sss_sscp_object_t *sscp_derivedKeyObject    = (sss_sscp_object_t *)derivedKeyObject;
        return sss_sscp_derive_key_dh(sscp_context, sscp_otherPartyKeyObject, sscp_derivedKeyObject);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DERIVE_KEY_TYPE_IS_SE05X(context)) {
        sss_se05x_derive_key_t *se05x_context         = (sss_se05x_derive_key_t *)context;
        sss_se05x_object_t *se05x_otherPartyKeyObject = (sss_se05x_object_t *)otherPartyKeyObject;
        sss_se05x_object_t *se05x_derivedKeyObject    = (sss_se05x_object_t *)derivedKeyObject;
        return sss_se05x_derive_key_dh(se05x_context, se05x_otherPartyKeyObject, se05x_derivedKeyObject);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context         = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_object_t *mbedtls_otherPartyKeyObject = (sss_mbedtls_object_t *)otherPartyKeyObject;
        sss_mbedtls_object_t *mbedtls_derivedKeyObject    = (sss_mbedtls_object_t *)derivedKeyObject;
        return sss_mbedtls_derive_key_dh(mbedtls_context, mbedtls_otherPartyKeyObject, mbedtls_derivedKeyObject);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context         = (sss_openssl_derive_key_t *)context;
        sss_openssl_object_t *openssl_otherPartyKeyObject = (sss_openssl_object_t *)otherPartyKeyObject;
        sss_openssl_object_t *openssl_derivedKeyObject    = (sss_openssl_object_t *)derivedKeyObject;
        return sss_openssl_derive_key_dh(openssl_context, openssl_otherPartyKeyObject, openssl_derivedKeyObject);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_derive_key_context_free(sss_derive_key_t *context)
{
#if SSS_HAVE_SSCP
    if (SSS_DERIVE_KEY_TYPE_IS_SSCP(context)) {
        sss_sscp_derive_key_t *sscp_context = (sss_sscp_derive_key_t *)context;
        sss_sscp_derive_key_context_free(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DERIVE_KEY_TYPE_IS_SE05X(context)) {
        sss_se05x_derive_key_t *se05x_context = (sss_se05x_derive_key_t *)context;
        sss_se05x_derive_key_context_free(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_derive_key_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context = (sss_openssl_derive_key_t *)context;
        sss_openssl_derive_key_context_free(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_key_store_context_init(sss_key_store_t *keyStore, sss_session_t *session)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        sss_sscp_session_t *sscp_session    = (sss_sscp_session_t *)session;
        SSS_ASSERT(sizeof(*sscp_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        return sss_sscp_key_store_context_init(sscp_keyStore, sscp_session);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        sss_se05x_session_t *se05x_session    = (sss_se05x_session_t *)session;
        SSS_ASSERT(sizeof(*se05x_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*se05x_session) <= sizeof(*session));
        return sss_se05x_key_store_context_init(se05x_keyStore, se05x_session);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_session_t *mbedtls_session    = (sss_mbedtls_session_t *)session;
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        return sss_mbedtls_key_store_context_init(mbedtls_keyStore, mbedtls_session);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_session_t *openssl_session    = (sss_openssl_session_t *)session;
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        return sss_openssl_key_store_context_init(openssl_keyStore, openssl_session);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_allocate(sss_key_store_t *keyStore, uint32_t keyStoreId)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        return sss_sscp_key_store_allocate(sscp_keyStore, keyStoreId);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        return sss_se05x_key_store_allocate(se05x_keyStore, keyStoreId);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        return sss_mbedtls_key_store_allocate(mbedtls_keyStore, keyStoreId);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        return sss_openssl_key_store_allocate(openssl_keyStore, keyStoreId);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_save(sss_key_store_t *keyStore)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        return sss_sscp_key_store_save(sscp_keyStore);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        return sss_se05x_key_store_save(se05x_keyStore);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        return sss_mbedtls_key_store_save(mbedtls_keyStore);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        return sss_openssl_key_store_save(openssl_keyStore);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_load(sss_key_store_t *keyStore)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        return sss_sscp_key_store_load(sscp_keyStore);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        return sss_se05x_key_store_load(se05x_keyStore);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        return sss_mbedtls_key_store_load(mbedtls_keyStore);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        return sss_openssl_key_store_load(openssl_keyStore);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_set_key(sss_key_store_t *keyStore,
    sss_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
    LOG_D("sss_key_store_set_key(@%08X, cipherType=%s, keyBitLen=%d)",
        keyObject->keyId,
        sss_cipher_type_sz(keyObject->cipherType),
        keyBitLen);
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_store_set_key(sscp_keyStore, sscp_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT && SSSFTR_SE05X_KEY_SET
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_store_set_key(
            se05x_keyStore, se05x_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_store_set_key(
            mbedtls_keyStore, mbedtls_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_store_set_key(
            openssl_keyStore, openssl_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_generate_key(
    sss_key_store_t *keyStore, sss_object_t *keyObject, size_t keyBitLen, void *options)
{
    LOG_D("sss_key_store_generate_key(@%08X, cipherType=%s, keyBitLen=%d)",
        keyObject->keyId,
        sss_cipher_type_sz(keyObject->cipherType),
        keyBitLen);
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_store_generate_key(sscp_keyStore, sscp_keyObject, keyBitLen, options);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_store_generate_key(se05x_keyStore, se05x_keyObject, keyBitLen, options);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_store_generate_key(mbedtls_keyStore, mbedtls_keyObject, keyBitLen, options);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_store_generate_key(openssl_keyStore, openssl_keyObject, keyBitLen, options);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_get_key(
    sss_key_store_t *keyStore, sss_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_store_get_key(sscp_keyStore, sscp_keyObject, data, dataLen, pKeyBitLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT && SSSFTR_SE05X_KEY_GET
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_store_get_key(se05x_keyStore, se05x_keyObject, data, dataLen, pKeyBitLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_store_get_key(mbedtls_keyStore, mbedtls_keyObject, data, dataLen, pKeyBitLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_store_get_key(openssl_keyStore, openssl_keyObject, data, dataLen, pKeyBitLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_open_key(sss_key_store_t *keyStore, sss_object_t *keyObject)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_store_open_key(sscp_keyStore, sscp_keyObject);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_store_open_key(se05x_keyStore, se05x_keyObject);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_store_open_key(mbedtls_keyStore, mbedtls_keyObject);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_store_open_key(openssl_keyStore, openssl_keyObject);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_freeze_key(sss_key_store_t *keyStore, sss_object_t *keyObject)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_store_freeze_key(sscp_keyStore, sscp_keyObject);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_store_freeze_key(se05x_keyStore, se05x_keyObject);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_store_freeze_key(mbedtls_keyStore, mbedtls_keyObject);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_store_freeze_key(openssl_keyStore, openssl_keyObject);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_erase_key(sss_key_store_t *keyStore, sss_object_t *keyObject)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        return sss_sscp_key_store_erase_key(sscp_keyStore, sscp_keyObject);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        return sss_se05x_key_store_erase_key(se05x_keyStore, se05x_keyObject);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        return sss_mbedtls_key_store_erase_key(mbedtls_keyStore, mbedtls_keyObject);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        return sss_openssl_key_store_erase_key(openssl_keyStore, openssl_keyObject);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_key_store_context_free(sss_key_store_t *keyStore)
{
#if SSS_HAVE_SSCP
    if (SSS_KEY_STORE_TYPE_IS_SSCP(keyStore)) {
        sss_sscp_key_store_t *sscp_keyStore = (sss_sscp_key_store_t *)keyStore;
        sss_sscp_key_store_context_free(sscp_keyStore);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_KEY_STORE_TYPE_IS_SE05X(keyStore)) {
        sss_se05x_key_store_t *se05x_keyStore = (sss_se05x_key_store_t *)keyStore;
        sss_se05x_key_store_context_free(se05x_keyStore);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_key_store_context_free(mbedtls_keyStore);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_key_store_context_free(openssl_keyStore);
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_asymmetric_context_init(sss_asymmetric_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_asymmetric_t *sscp_context = (sss_sscp_asymmetric_t *)context;
        sss_sscp_session_t *sscp_session    = (sss_sscp_session_t *)session;
        sss_sscp_object_t *sscp_keyObject   = (sss_sscp_object_t *)keyObject;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*sscp_keyObject) <= sizeof(*keyObject));
        return sss_sscp_asymmetric_context_init(sscp_context, sscp_session, sscp_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_asymmetric_t *se05x_context = (sss_se05x_asymmetric_t *)context;
        sss_se05x_session_t *se05x_session    = (sss_se05x_session_t *)session;
        sss_se05x_object_t *se05x_keyObject   = (sss_se05x_object_t *)keyObject;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*se05x_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*se05x_keyObject) <= sizeof(*keyObject));
        return sss_se05x_asymmetric_context_init(se05x_context, se05x_session, se05x_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        sss_mbedtls_session_t *mbedtls_session    = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_asymmetric_context_init(
            mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        sss_openssl_session_t *openssl_session    = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_asymmetric_context_init(
            openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_encrypt(
    sss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if SSS_HAVE_SSCP
    if (SSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_asymmetric_t *sscp_context = (sss_sscp_asymmetric_t *)context;
        return sss_sscp_asymmetric_encrypt(sscp_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_ASYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_asymmetric_t *se05x_context = (sss_se05x_asymmetric_t *)context;
        return sss_se05x_asymmetric_encrypt(se05x_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        return sss_mbedtls_asymmetric_encrypt(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        return sss_openssl_asymmetric_encrypt(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_decrypt(
    sss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if SSS_HAVE_SSCP
    if (SSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_asymmetric_t *sscp_context = (sss_sscp_asymmetric_t *)context;
        return sss_sscp_asymmetric_decrypt(sscp_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_ASYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_asymmetric_t *se05x_context = (sss_se05x_asymmetric_t *)context;
        return sss_se05x_asymmetric_decrypt(se05x_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        return sss_mbedtls_asymmetric_decrypt(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        return sss_openssl_asymmetric_decrypt(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_sign_digest(
    sss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
#if SSS_HAVE_SSCP
    if (SSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_asymmetric_t *sscp_context = (sss_sscp_asymmetric_t *)context;
        return sss_sscp_asymmetric_sign_digest(sscp_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_ASYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_asymmetric_t *se05x_context = (sss_se05x_asymmetric_t *)context;
        return sss_se05x_asymmetric_sign_digest(se05x_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        return sss_mbedtls_asymmetric_sign_digest(mbedtls_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        return sss_openssl_asymmetric_sign_digest(openssl_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_verify_digest(
    sss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen)
{
#if SSS_HAVE_SSCP
    if (SSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_asymmetric_t *sscp_context = (sss_sscp_asymmetric_t *)context;
        return sss_sscp_asymmetric_verify_digest(sscp_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_ASYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_asymmetric_t *se05x_context = (sss_se05x_asymmetric_t *)context;
        return sss_se05x_asymmetric_verify_digest(se05x_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        return sss_mbedtls_asymmetric_verify_digest(mbedtls_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        return sss_openssl_asymmetric_verify_digest(openssl_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_asymmetric_context_free(sss_asymmetric_t *context)
{
#if SSS_HAVE_SSCP
    if (SSS_ASYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_asymmetric_t *sscp_context = (sss_sscp_asymmetric_t *)context;
        sss_sscp_asymmetric_context_free(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_ASYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_asymmetric_t *se05x_context = (sss_se05x_asymmetric_t *)context;
        sss_se05x_asymmetric_context_free(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        sss_mbedtls_asymmetric_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        sss_openssl_asymmetric_context_free(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_symmetric_context_init(sss_symmetric_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    LOG_D("FN: %s", __FUNCTION__);
    LOG_D("Input:algorithm %02x", algorithm);
    LOG_D("Input:mode %02x", mode);

#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_symmetric_t *sscp_context = (sss_sscp_symmetric_t *)context;
        sss_sscp_session_t *sscp_session   = (sss_sscp_session_t *)session;
        sss_sscp_object_t *sscp_keyObject  = (sss_sscp_object_t *)keyObject;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*sscp_keyObject) <= sizeof(*keyObject));
        return sss_sscp_symmetric_context_init(sscp_context, sscp_session, sscp_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT && SSSFTR_SE05X_AES
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_symmetric_t *se05x_context = (sss_se05x_symmetric_t *)context;
        sss_se05x_session_t *se05x_session   = (sss_se05x_session_t *)session;
        sss_se05x_object_t *se05x_keyObject  = (sss_se05x_object_t *)keyObject;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*se05x_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*se05x_keyObject) <= sizeof(*keyObject));
        return sss_se05x_symmetric_context_init(se05x_context, se05x_session, se05x_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        sss_mbedtls_session_t *mbedtls_session   = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject  = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_symmetric_context_init(mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        sss_openssl_session_t *openssl_session   = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject  = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_symmetric_context_init(openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_one_go(
    sss_symmetric_t *context, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input: IV", iv, ivLen);
    LOG_MAU8_D(" Input: srcData", srcData, dataLen);
#if SSS_HAVE_SSCP
    if (SSS_SYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_symmetric_t *sscp_context = (sss_sscp_symmetric_t *)context;
        return sss_sscp_cipher_one_go(sscp_context, iv, ivLen, srcData, destData, dataLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT && SSSFTR_SE05X_AES
    if (SSS_SYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_symmetric_t *se05x_context = (sss_se05x_symmetric_t *)context;
        return sss_se05x_cipher_one_go(se05x_context, iv, ivLen, srcData, destData, dataLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        return sss_mbedtls_cipher_one_go(mbedtls_context, iv, ivLen, srcData, destData, dataLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        return sss_openssl_cipher_one_go(openssl_context, iv, ivLen, srcData, destData, dataLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_init(sss_symmetric_t *context, uint8_t *iv, size_t ivLen)
{
#if SSS_HAVE_SSCP
    if (SSS_SYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_symmetric_t *sscp_context = (sss_sscp_symmetric_t *)context;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        return sss_sscp_cipher_init(sscp_context, iv, ivLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_symmetric_t *se05x_context = (sss_se05x_symmetric_t *)context;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        return sss_se05x_cipher_init(se05x_context, iv, ivLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_cipher_init(mbedtls_context, iv, ivLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_cipher_init(openssl_context, iv, ivLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_update(
    sss_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if SSS_HAVE_SSCP
    if (SSS_SYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_symmetric_t *sscp_context = (sss_sscp_symmetric_t *)context;
        return sss_sscp_cipher_update(sscp_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_symmetric_t *se05x_context = (sss_se05x_symmetric_t *)context;
        return sss_se05x_cipher_update(se05x_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        return sss_mbedtls_cipher_update(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        return sss_openssl_cipher_update(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_finish(
    sss_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if SSS_HAVE_SSCP
    if (SSS_SYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_symmetric_t *sscp_context = (sss_sscp_symmetric_t *)context;
        return sss_sscp_cipher_finish(sscp_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_symmetric_t *se05x_context = (sss_se05x_symmetric_t *)context;
        return sss_se05x_cipher_finish(se05x_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        return sss_mbedtls_cipher_finish(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        return sss_openssl_cipher_finish(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_crypt_ctr(sss_symmetric_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *initialCounter,
    uint8_t *lastEncryptedCounter,
    size_t *szLeft)
{
#if SSS_HAVE_SSCP
    if (SSS_SYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_symmetric_t *sscp_context = (sss_sscp_symmetric_t *)context;
        return sss_sscp_cipher_crypt_ctr(
            sscp_context, srcData, destData, size, initialCounter, lastEncryptedCounter, szLeft);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_symmetric_t *se05x_context = (sss_se05x_symmetric_t *)context;
        return sss_se05x_cipher_crypt_ctr(
            se05x_context, srcData, destData, size, initialCounter, lastEncryptedCounter, szLeft);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        return sss_mbedtls_cipher_crypt_ctr(
            mbedtls_context, srcData, destData, size, initialCounter, lastEncryptedCounter, szLeft);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        return sss_openssl_cipher_crypt_ctr(
            openssl_context, srcData, destData, size, initialCounter, lastEncryptedCounter, szLeft);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_symmetric_context_free(sss_symmetric_t *context)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_SSCP
    if (SSS_SYMMETRIC_TYPE_IS_SSCP(context)) {
        sss_sscp_symmetric_t *sscp_context = (sss_sscp_symmetric_t *)context;
        sss_sscp_symmetric_context_free(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SYMMETRIC_TYPE_IS_SE05X(context)) {
        sss_se05x_symmetric_t *se05x_context = (sss_se05x_symmetric_t *)context;
        sss_se05x_symmetric_context_free(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        sss_mbedtls_symmetric_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        sss_openssl_symmetric_context_free(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_aead_context_init(
    sss_aead_t *context, sss_session_t *session, sss_object_t *keyObject, sss_algorithm_t algorithm, sss_mode_t mode)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_aead_t *sscp_context     = (sss_sscp_aead_t *)context;
        sss_sscp_session_t *sscp_session  = (sss_sscp_session_t *)session;
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*sscp_keyObject) <= sizeof(*keyObject));
        return sss_sscp_aead_context_init(sscp_context, sscp_session, sscp_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_aead_t *se05x_context     = (sss_se05x_aead_t *)context;
        sss_se05x_session_t *se05x_session  = (sss_se05x_session_t *)session;
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*se05x_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*se05x_keyObject) <= sizeof(*keyObject));
        return sss_se05x_aead_context_init(se05x_context, se05x_session, se05x_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_aead_t *mbedtls_context     = (sss_mbedtls_aead_t *)context;
        sss_mbedtls_session_t *mbedtls_session  = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_aead_context_init(mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_aead_t *openssl_context     = (sss_openssl_aead_t *)context;
        sss_openssl_session_t *openssl_session  = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_aead_context_init(openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_one_go(sss_aead_t *context,
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
#if SSS_HAVE_SSCP
    if (SSS_AEAD_TYPE_IS_SSCP(context)) {
        sss_sscp_aead_t *sscp_context = (sss_sscp_aead_t *)context;
        return sss_sscp_aead_one_go(sscp_context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_AEAD_TYPE_IS_SE05X(context)) {
        sss_se05x_aead_t *se05x_context = (sss_se05x_aead_t *)context;
        return sss_se05x_aead_one_go(se05x_context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_AEAD_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        return sss_mbedtls_aead_one_go(
            mbedtls_context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_AEAD_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        return sss_openssl_aead_one_go(
            openssl_context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_init(
    sss_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen)
{
#if SSS_HAVE_SSCP
    if (SSS_AEAD_TYPE_IS_SSCP(context)) {
        sss_sscp_aead_t *sscp_context = (sss_sscp_aead_t *)context;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        return sss_sscp_aead_init(sscp_context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_AEAD_TYPE_IS_SE05X(context)) {
        sss_se05x_aead_t *se05x_context = (sss_se05x_aead_t *)context;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        return sss_se05x_aead_init(se05x_context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_AEAD_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_aead_init(mbedtls_context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_AEAD_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_aead_init(openssl_context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_update_aad(sss_aead_t *context, const uint8_t *aadData, size_t aadDataLen)
{
#if SSS_HAVE_SSCP
    if (SSS_AEAD_TYPE_IS_SSCP(context)) {
        sss_sscp_aead_t *sscp_context = (sss_sscp_aead_t *)context;
        return sss_sscp_aead_update_aad(sscp_context, aadData, aadDataLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_AEAD_TYPE_IS_SE05X(context)) {
        sss_se05x_aead_t *se05x_context = (sss_se05x_aead_t *)context;
        return sss_se05x_aead_update_aad(se05x_context, aadData, aadDataLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_AEAD_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        return sss_mbedtls_aead_update_aad(mbedtls_context, aadData, aadDataLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_AEAD_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        return sss_openssl_aead_update_aad(openssl_context, aadData, aadDataLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_update(
    sss_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
#if SSS_HAVE_SSCP
    if (SSS_AEAD_TYPE_IS_SSCP(context)) {
        sss_sscp_aead_t *sscp_context = (sss_sscp_aead_t *)context;
        return sss_sscp_aead_update(sscp_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_AEAD_TYPE_IS_SE05X(context)) {
        sss_se05x_aead_t *se05x_context = (sss_se05x_aead_t *)context;
        return sss_se05x_aead_update(se05x_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_AEAD_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        return sss_mbedtls_aead_update(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_AEAD_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        return sss_openssl_aead_update(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_finish(sss_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen)
{
#if SSS_HAVE_SSCP
    if (SSS_AEAD_TYPE_IS_SSCP(context)) {
        sss_sscp_aead_t *sscp_context = (sss_sscp_aead_t *)context;
        return sss_sscp_aead_finish(sscp_context, srcData, srcLen, destData, destLen, tag, tagLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_AEAD_TYPE_IS_SE05X(context)) {
        sss_se05x_aead_t *se05x_context = (sss_se05x_aead_t *)context;
        return sss_se05x_aead_finish(se05x_context, srcData, srcLen, destData, destLen, tag, tagLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_AEAD_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        return sss_mbedtls_aead_finish(mbedtls_context, srcData, srcLen, destData, destLen, tag, tagLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_AEAD_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        return sss_openssl_aead_finish(openssl_context, srcData, srcLen, destData, destLen, tag, tagLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_aead_context_free(sss_aead_t *context)
{
#if SSS_HAVE_SSCP
    if (SSS_AEAD_TYPE_IS_SSCP(context)) {
        sss_sscp_aead_t *sscp_context = (sss_sscp_aead_t *)context;
        sss_sscp_aead_context_free(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_AEAD_TYPE_IS_SE05X(context)) {
        sss_se05x_aead_t *se05x_context = (sss_se05x_aead_t *)context;
        sss_se05x_aead_context_free(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_AEAD_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        sss_mbedtls_aead_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_AEAD_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        sss_openssl_aead_context_free(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_mac_context_init(
    sss_mac_t *context, sss_session_t *session, sss_object_t *keyObject, sss_algorithm_t algorithm, sss_mode_t mode)
{
    LOG_D("FN: %s", __FUNCTION__);
    LOG_D("Input:algorithm %02x", algorithm);
    LOG_D("Input:mode %02x", mode);
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_mac_t *sscp_context      = (sss_sscp_mac_t *)context;
        sss_sscp_session_t *sscp_session  = (sss_sscp_session_t *)session;
        sss_sscp_object_t *sscp_keyObject = (sss_sscp_object_t *)keyObject;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*sscp_keyObject) <= sizeof(*keyObject));
        return sss_sscp_mac_context_init(sscp_context, sscp_session, sscp_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_mac_t *se05x_context      = (sss_se05x_mac_t *)context;
        sss_se05x_session_t *se05x_session  = (sss_se05x_session_t *)session;
        sss_se05x_object_t *se05x_keyObject = (sss_se05x_object_t *)keyObject;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*se05x_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*se05x_keyObject) <= sizeof(*keyObject));
        return sss_se05x_mac_context_init(se05x_context, se05x_session, se05x_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_mac_t *mbedtls_context      = (sss_mbedtls_mac_t *)context;
        sss_mbedtls_session_t *mbedtls_session  = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_mac_context_init(mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_mac_t *openssl_context      = (sss_openssl_mac_t *)context;
        sss_openssl_session_t *openssl_session  = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_mac_context_init(openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_one_go(sss_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen)
{
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input: message", message, messageLen);
    //LOG_MAU8_D(" Output: mac", context, *macLen);
#if SSS_HAVE_SSCP
    if (SSS_MAC_TYPE_IS_SSCP(context)) {
        sss_sscp_mac_t *sscp_context = (sss_sscp_mac_t *)context;
        return sss_sscp_mac_one_go(sscp_context, message, messageLen, mac, macLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_MAC_TYPE_IS_SE05X(context)) {
        sss_se05x_mac_t *se05x_context = (sss_se05x_mac_t *)context;
        return sss_se05x_mac_one_go(se05x_context, message, messageLen, mac, macLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        return sss_mbedtls_mac_one_go(mbedtls_context, message, messageLen, mac, macLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        return sss_openssl_mac_one_go(openssl_context, message, messageLen, mac, macLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_init(sss_mac_t *context)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_SSCP
    if (SSS_MAC_TYPE_IS_SSCP(context)) {
        sss_sscp_mac_t *sscp_context = (sss_sscp_mac_t *)context;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        return sss_sscp_mac_init(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT && SSSFTR_SE05X_AES
    if (SSS_MAC_TYPE_IS_SE05X(context)) {
        sss_se05x_mac_t *se05x_context = (sss_se05x_mac_t *)context;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        return sss_se05x_mac_init(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_mac_init(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_mac_init(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_update(sss_mac_t *context, const uint8_t *message, size_t messageLen)
{
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input: message", message, messageLen);

#if SSS_HAVE_SSCP
    if (SSS_MAC_TYPE_IS_SSCP(context)) {
        sss_sscp_mac_t *sscp_context = (sss_sscp_mac_t *)context;
        return sss_sscp_mac_update(sscp_context, message, messageLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_MAC_TYPE_IS_SE05X(context)) {
        sss_se05x_mac_t *se05x_context = (sss_se05x_mac_t *)context;
        return sss_se05x_mac_update(se05x_context, message, messageLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        return sss_mbedtls_mac_update(mbedtls_context, message, messageLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        return sss_openssl_mac_update(openssl_context, message, messageLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_finish(sss_mac_t *context, uint8_t *mac, size_t *macLen)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_SSCP
    if (SSS_MAC_TYPE_IS_SSCP(context)) {
        sss_sscp_mac_t *sscp_context = (sss_sscp_mac_t *)context;
        return sss_sscp_mac_finish(sscp_context, mac, macLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_MAC_TYPE_IS_SE05X(context)) {
        sss_se05x_mac_t *se05x_context = (sss_se05x_mac_t *)context;
        return sss_se05x_mac_finish(se05x_context, mac, macLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        return sss_mbedtls_mac_finish(mbedtls_context, mac, macLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        return sss_openssl_mac_finish(openssl_context, mac, macLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_mac_context_free(sss_mac_t *context)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_SSCP
    if (SSS_MAC_TYPE_IS_SSCP(context)) {
        sss_sscp_mac_t *sscp_context = (sss_sscp_mac_t *)context;
        sss_sscp_mac_context_free(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_MAC_TYPE_IS_SE05X(context)) {
        sss_se05x_mac_t *se05x_context = (sss_se05x_mac_t *)context;
        sss_se05x_mac_context_free(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        sss_mbedtls_mac_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        sss_openssl_mac_context_free(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_digest_context_init(
    sss_digest_t *context, sss_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode)
{
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_digest_t *sscp_context  = (sss_sscp_digest_t *)context;
        sss_sscp_session_t *sscp_session = (sss_sscp_session_t *)session;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        return sss_sscp_digest_context_init(sscp_context, sscp_session, algorithm, mode);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_digest_t *se05x_context  = (sss_se05x_digest_t *)context;
        sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)session;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*se05x_session) <= sizeof(*session));
        return sss_se05x_digest_context_init(se05x_context, se05x_session, algorithm, mode);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_digest_t *mbedtls_context  = (sss_mbedtls_digest_t *)context;
        sss_mbedtls_session_t *mbedtls_session = (sss_mbedtls_session_t *)session;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        return sss_mbedtls_digest_context_init(mbedtls_context, mbedtls_session, algorithm, mode);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_digest_t *openssl_context  = (sss_openssl_digest_t *)context;
        sss_openssl_session_t *openssl_session = (sss_openssl_session_t *)session;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        return sss_openssl_digest_context_init(openssl_context, openssl_session, algorithm, mode);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_digest_one_go(
    sss_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
#if SSS_HAVE_SSCP
    if (SSS_DIGEST_TYPE_IS_SSCP(context)) {
        sss_sscp_digest_t *sscp_context = (sss_sscp_digest_t *)context;
        return sss_sscp_digest_one_go(sscp_context, message, messageLen, digest, digestLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DIGEST_TYPE_IS_SE05X(context)) {
        sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;
        return sss_se05x_digest_one_go(se05x_context, message, messageLen, digest, digestLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        return sss_mbedtls_digest_one_go(mbedtls_context, message, messageLen, digest, digestLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        return sss_openssl_digest_one_go(openssl_context, message, messageLen, digest, digestLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_digest_init(sss_digest_t *context)
{
#if SSS_HAVE_SSCP
    if (SSS_DIGEST_TYPE_IS_SSCP(context)) {
        sss_sscp_digest_t *sscp_context = (sss_sscp_digest_t *)context;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        return sss_sscp_digest_init(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DIGEST_TYPE_IS_SE05X(context)) {
        sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        return sss_se05x_digest_init(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_digest_init(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_digest_init(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_digest_update(sss_digest_t *context, const uint8_t *message, size_t messageLen)
{
#if SSS_HAVE_SSCP
    if (SSS_DIGEST_TYPE_IS_SSCP(context)) {
        sss_sscp_digest_t *sscp_context = (sss_sscp_digest_t *)context;
        return sss_sscp_digest_update(sscp_context, message, messageLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DIGEST_TYPE_IS_SE05X(context)) {
        sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;
        return sss_se05x_digest_update(se05x_context, message, messageLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        return sss_mbedtls_digest_update(mbedtls_context, message, messageLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        return sss_openssl_digest_update(openssl_context, message, messageLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_digest_finish(sss_digest_t *context, uint8_t *digest, size_t *digestLen)
{
#if SSS_HAVE_SSCP
    if (SSS_DIGEST_TYPE_IS_SSCP(context)) {
        sss_sscp_digest_t *sscp_context = (sss_sscp_digest_t *)context;
        return sss_sscp_digest_finish(sscp_context, digest, digestLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DIGEST_TYPE_IS_SE05X(context)) {
        sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;
        return sss_se05x_digest_finish(se05x_context, digest, digestLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        return sss_mbedtls_digest_finish(mbedtls_context, digest, digestLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        return sss_openssl_digest_finish(openssl_context, digest, digestLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_digest_context_free(sss_digest_t *context)
{
#if SSS_HAVE_SSCP
    if (SSS_DIGEST_TYPE_IS_SSCP(context)) {
        sss_sscp_digest_t *sscp_context = (sss_sscp_digest_t *)context;
        sss_sscp_digest_context_free(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_DIGEST_TYPE_IS_SE05X(context)) {
        sss_se05x_digest_t *se05x_context = (sss_se05x_digest_t *)context;
        sss_se05x_digest_context_free(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        sss_mbedtls_digest_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        sss_openssl_digest_context_free(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
}

sss_status_t sss_rng_context_init(sss_rng_context_t *context, sss_session_t *session)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_rng_context_t *sscp_context = (sss_sscp_rng_context_t *)context;
        sss_sscp_session_t *sscp_session     = (sss_sscp_session_t *)session;
        SSS_ASSERT(sizeof(*sscp_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*sscp_session) <= sizeof(*session));
        return sss_sscp_rng_context_init(sscp_context, sscp_session);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_rng_context_t *se05x_context = (sss_se05x_rng_context_t *)context;
        sss_se05x_session_t *se05x_session     = (sss_se05x_session_t *)session;
        SSS_ASSERT(sizeof(*se05x_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*se05x_session) <= sizeof(*session));
        return sss_se05x_rng_context_init(se05x_context, se05x_session);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_rng_context_t *mbedtls_context = (sss_mbedtls_rng_context_t *)context;
        sss_mbedtls_session_t *mbedtls_session     = (sss_mbedtls_session_t *)session;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        return sss_mbedtls_rng_context_init(mbedtls_context, mbedtls_session);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_rng_context_t *openssl_context = (sss_openssl_rng_context_t *)context;
        sss_openssl_session_t *openssl_session     = (sss_openssl_session_t *)session;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        return sss_openssl_rng_context_init(openssl_context, openssl_session);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_rng_get_random(sss_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_SSCP
    if (SSS_RNG_CONTEXT_TYPE_IS_SSCP(context)) {
        sss_sscp_rng_context_t *sscp_context = (sss_sscp_rng_context_t *)context;
        return sss_sscp_rng_get_random(sscp_context, random_data, dataLen);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_RNG_CONTEXT_TYPE_IS_SE05X(context)) {
        sss_se05x_rng_context_t *se05x_context = (sss_se05x_rng_context_t *)context;
        return sss_se05x_rng_get_random(se05x_context, random_data, dataLen);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_RNG_CONTEXT_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_rng_context_t *mbedtls_context = (sss_mbedtls_rng_context_t *)context;
        return sss_mbedtls_rng_get_random(mbedtls_context, random_data, dataLen);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_RNG_CONTEXT_TYPE_IS_OPENSSL(context)) {
        sss_openssl_rng_context_t *openssl_context = (sss_openssl_rng_context_t *)context;
        return sss_openssl_rng_get_random(openssl_context, random_data, dataLen);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_rng_context_free(sss_rng_context_t *context)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_SSCP
    if (SSS_RNG_CONTEXT_TYPE_IS_SSCP(context)) {
        sss_sscp_rng_context_t *sscp_context = (sss_sscp_rng_context_t *)context;
        return sss_sscp_rng_context_free(sscp_context);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_RNG_CONTEXT_TYPE_IS_SE05X(context)) {
        sss_se05x_rng_context_t *se05x_context = (sss_se05x_rng_context_t *)context;
        return sss_se05x_rng_context_free(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    if (SSS_RNG_CONTEXT_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_rng_context_t *mbedtls_context = (sss_mbedtls_rng_context_t *)context;
        return sss_mbedtls_rng_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    if (SSS_RNG_CONTEXT_TYPE_IS_OPENSSL(context)) {
        sss_openssl_rng_context_t *openssl_context = (sss_openssl_rng_context_t *)context;
        return sss_openssl_rng_context_free(openssl_context);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_tunnel_context_init(sss_tunnel_t *context, sss_session_t *session)
{
#if 0 && SSS_HAVE_SSCP
    if (SSS_SESSION_TYPE_IS_SSCP(session)) {
        sss_sscp_tunnel_t *sscp_context = (sss_sscp_tunnel_t *)context;
        sss_sscp_session_t *sscp_session = (sss_sscp_session_t *)session;
        return sss_sscp_tunnel_context_init(sscp_context, sscp_session);
    }
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_SESSION_TYPE_IS_SE05X(session)) {
        sss_se05x_tunnel_context_t *se05x_context = (sss_se05x_tunnel_context_t *)context;
        sss_se05x_session_t *se05x_session        = (sss_se05x_session_t *)session;
        return sss_se05x_tunnel_context_init(se05x_context, se05x_session);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    /* NA */
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    /* NA */
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_tunnel(sss_tunnel_t *context,
    uint8_t *data,
    size_t dataLen,
    sss_object_t *keyObjects,
    uint32_t keyObjectCount,
    uint32_t tunnelType)
{
#if 0 && SSS_HAVE_SSCP
    if (SSS_TUNNEL_TYPE_IS_SSCP(context)) {
        sss_sscp_tunnel_t *sscp_context = (sss_sscp_tunnel_t *)context;
        sss_sscp_object_t *sscp_keyObjects = (sss_sscp_object_t *)keyObjects;
        return sss_sscp_tunnel(sscp_context,
            data,
            dataLen,
            sscp_keyObjects,
            keyObjectCount,
            tunnelType);
    }
#endif /* SSS_HAVE_SSCP */
#if 0 && SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_TUNNEL_TYPE_IS_SE05X(context)) {
        sss_se05x_tunnel_context_t *se05x_context = (sss_se05x_tunnel_context_t *)context;
        sss_se05x_object_t *se05x_keyObjects = (sss_se05x_object_t *)keyObjects;
        return sss_se05x_tunnel(se05x_context,
            data,
            dataLen,
            se05x_keyObjects,
            keyObjectCount,
            tunnelType);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if 0 && SSS_HAVE_MBEDTLS
    if (SSS_TUNNEL_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_tunnel_t *mbedtls_context = (sss_mbedtls_tunnel_t *)context;
        sss_mbedtls_object_t *mbedtls_keyObjects =
            (sss_mbedtls_object_t *)keyObjects;
        return sss_mbedtls_tunnel(mbedtls_context,
            data,
            dataLen,
            mbedtls_keyObjects,
            keyObjectCount,
            tunnelType);
    }
#endif /* SSS_HAVE_MBEDTLS */
#if 0 && SSS_HAVE_OPENSSL
    if (SSS_TUNNEL_TYPE_IS_OPENSSL(context)) {
        sss_openssl_tunnel_t *openssl_context = (sss_openssl_tunnel_t *)context;
        sss_openssl_object_t *openssl_keyObjects =
            (sss_openssl_object_t *)keyObjects;
        return sss_openssl_tunnel(openssl_context,
            data,
            dataLen,
            openssl_keyObjects,
            keyObjectCount,
            tunnelType);
    }
#endif /* SSS_HAVE_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_tunnel_context_free(sss_tunnel_t *context)
{
#if SSS_HAVE_SSCP
    /* NA */
#endif /* SSS_HAVE_SSCP */
#if SSS_HAVE_APPLET_SE05X_IOT
    if (SSS_TUNNEL_TYPE_IS_SE05X(context)) {
        sss_se05x_tunnel_context_t *se05x_context = (sss_se05x_tunnel_context_t *)context;
        sss_se05x_tunnel_context_free(se05x_context);
    }
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#if SSS_HAVE_MBEDTLS
    /* NA */
#endif /* SSS_HAVE_MBEDTLS */
#if SSS_HAVE_OPENSSL
    /* NA */
#endif /* SSS_HAVE_OPENSSL */
}

#define CASE_X_RETRUN_STR_kStatus_SSS(SUFFIX) \
    case kStatus_SSS_##SUFFIX:                \
        return "kStatus_SSS_" #SUFFIX

const char *sss_status_sz(sss_status_t status)
{
    switch (status) {
        CASE_X_RETRUN_STR_kStatus_SSS(Success);
        CASE_X_RETRUN_STR_kStatus_SSS(Fail);
        CASE_X_RETRUN_STR_kStatus_SSS(InvalidArgument);
        CASE_X_RETRUN_STR_kStatus_SSS(ResourceBusy);
    default:
        LOG_W("sss_status_sz status=0x%X Unknown", status);
        return "Unknown sss_status_t";
    }
}

#define CASE_X_RETRUN_STR_kSSS_CipherType(SUFFIX) \
    case kSSS_CipherType_##SUFFIX:                \
        return "kSSS_CipherType_" #SUFFIX

const char *sss_cipher_type_sz(sss_cipher_type_t cipher_type)
{
    switch (cipher_type) {
        CASE_X_RETRUN_STR_kSSS_CipherType(AES);
        CASE_X_RETRUN_STR_kSSS_CipherType(DES);
        CASE_X_RETRUN_STR_kSSS_CipherType(CMAC);
        CASE_X_RETRUN_STR_kSSS_CipherType(HMAC);
        CASE_X_RETRUN_STR_kSSS_CipherType(MAC);
        CASE_X_RETRUN_STR_kSSS_CipherType(RSA);
        CASE_X_RETRUN_STR_kSSS_CipherType(RSA_CRT);
        CASE_X_RETRUN_STR_kSSS_CipherType(EC_NIST_P);
        CASE_X_RETRUN_STR_kSSS_CipherType(EC_NIST_K);
        CASE_X_RETRUN_STR_kSSS_CipherType(EC_MONTGOMERY);
        CASE_X_RETRUN_STR_kSSS_CipherType(EC_TWISTED_ED);
        CASE_X_RETRUN_STR_kSSS_CipherType(EC_BRAINPOOL);
        CASE_X_RETRUN_STR_kSSS_CipherType(EC_BARRETO_NAEHRIG);
        CASE_X_RETRUN_STR_kSSS_CipherType(UserID);
        CASE_X_RETRUN_STR_kSSS_CipherType(Certificate);
        CASE_X_RETRUN_STR_kSSS_CipherType(Binary);
        CASE_X_RETRUN_STR_kSSS_CipherType(Count);
        CASE_X_RETRUN_STR_kSSS_CipherType(PCR);
        CASE_X_RETRUN_STR_kSSS_CipherType(ReservedPin);
    default:
        LOG_W("sss_cipher_type_sz status=0x%X Unknown", cipher_type);
        return "Unknown sss_cipher_type_t";
    }
}

#endif /* SSS_HAVE_SSS > 1 */
