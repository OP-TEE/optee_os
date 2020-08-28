/*
 * Copyright 2018-2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * Implementation of key association between NXP Secure Element and mbedtls.
 * @par History
 * 1.0   30-jan-2018 : Initial version
 *
 *****************************************************************************/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECP_ALT) && SSS_HAVE_ALT_SSS

/** @ingroup ax_mbed_tls */
/** @{ */

#include <fsl_sss_util_asn1_der.h>
#include <nxLog_sss.h>
#include <string.h>

#include "fsl_sss_api.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/version.h"
#include "sss_mbedtls.h"
#if defined(FLOW_VERBOSE) && (FLOW_VERBOSE == 1)
#define LOG_API_CALLS 1
#else
#define LOG_API_CALLS 0
#endif /* FLOW_VERBOSE */

#ifndef LOG_API_CALLS
#define LOG_API_CALLS 1 /* Log by default */
#endif

extern mbedtls_pk_info_t ax_mbedtls_rsakeypair_info;
extern mbedtls_pk_info_t ax_mbedtls_rsapubkey_info;

static size_t sss_eckey_get_bitlen(const void *ctx);
static int sss_eckey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);
static int sss_eckey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len);
static int sss_eckey_check_pair(const void *pub, const void *prv);
static int sss_eckeypair_can_do(mbedtls_pk_type_t type);
static int sss_ecpubkey_can_do(mbedtls_pk_type_t type);
static void sss_eckeypair_free_func(void *ctx);
static void sss_ecpubkey_free_func(void *ctx);

static const mbedtls_pk_info_t ax_mbedtls_eckeypair_info = {
    MBEDTLS_PK_ECKEY,
    "AxEC_Keypair",
    &sss_eckey_get_bitlen,
    &sss_eckeypair_can_do,
    NULL,
    &sss_eckey_sign,
    NULL, // decrypt_func,
    NULL, // encrypt_func,
    &sss_eckey_check_pair,
    NULL, //&ax_eckey_alloc,
    &sss_eckeypair_free_func,
    NULL, //&ax_eckey_debug,
};

static const mbedtls_pk_info_t ax_mbedtls_ecpubkey_info = {
    MBEDTLS_PK_ECKEY,
    "AxEC_pubkey",
    &sss_eckey_get_bitlen,
    &sss_ecpubkey_can_do,
    &sss_eckey_verify,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &sss_ecpubkey_free_func,
    NULL,
};

/* clang-format off */
typedef struct _object_identifiers
{
    uint32_t identifier[16];
    size_t indentifier_len;
    int groupId;
    char* name;
} object_identifiers_t;
object_identifiers_t object_identifiers_gvar[] = {

    { { 1, 2, 840, 10045, 3, 1, 1 },       7,    MBEDTLS_ECP_DP_SECP192R1, "MBEDTLS_ECP_DP_SECP192R1" },
    { { 1, 3, 132, 0, 33 },                5,    MBEDTLS_ECP_DP_SECP224R1, "MBEDTLS_ECP_DP_SECP224R1" },
    { { 1, 2, 840, 10045, 3, 1, 7 },       7,    MBEDTLS_ECP_DP_SECP256R1, "MBEDTLS_ECP_DP_SECP256R1" },
    { { 1, 3, 132, 0, 34 },                5,    MBEDTLS_ECP_DP_SECP384R1, "MBEDTLS_ECP_DP_SECP384R1" },
    { { 1, 3, 132, 0, 35 },                5,    MBEDTLS_ECP_DP_SECP521R1, "MBEDTLS_ECP_DP_SECP521R1" },

    { { 1, 3, 36, 3, 3, 2, 8, 1, 1, 7 },  10,    MBEDTLS_ECP_DP_BP256R1, "MBEDTLS_ECP_DP_BP256R1" },
    { { 1, 3, 24, 3, 3, 2, 8, 1, 1, 7 },  10,    MBEDTLS_ECP_DP_BP256R1, "MBEDTLS_ECP_DP_BP256R1" },
    { { 1, 3, 36, 3, 3, 2, 8, 1, 1, 11},  10,    MBEDTLS_ECP_DP_BP384R1, "MBEDTLS_ECP_DP_BP384R1" },
    { { 1, 3, 36, 3, 3, 2, 8, 1, 1, 13},  10,    MBEDTLS_ECP_DP_BP512R1, "MBEDTLS_ECP_DP_BP512R1" },

    { { 1, 3, 132, 0, 31 },                5,    MBEDTLS_ECP_DP_SECP192K1, "MBEDTLS_ECP_DP_SECP192K1" },
    { { 1, 3, 132, 0, 32 },                5,    MBEDTLS_ECP_DP_SECP224K1, "MBEDTLS_ECP_DP_SECP224K1" },
    { { 1, 3, 132, 0, 10 },                5,    MBEDTLS_ECP_DP_SECP256K1, "MBEDTLS_ECP_DP_SECP256K1" },
    {{0,}, 0, 0},
};
/* clang-format on */

#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif

int get_group_id(uint32_t *objectid, uint8_t objectIdLen)
{
    size_t i = 0, j = 0;
    int groupId = -1;

    while (1) {
        if (object_identifiers_gvar[i].indentifier_len == 0) {
            break;
        }

        if (object_identifiers_gvar[i].indentifier_len != objectIdLen) {
            i++;
            continue;
        }

        for (j = 0; j < object_identifiers_gvar[i].indentifier_len; j++) {
            if (object_identifiers_gvar[i].identifier[j] != objectid[j]) {
                i++;
                goto skip_oid;
            }
        }

        groupId = object_identifiers_gvar[i].groupId;
        LOG_I("Group id found - %s \n", object_identifiers_gvar[i].name);
        break;
    skip_oid:
        continue;
    }

    return groupId;
}

int sss_mbedtls_associate_keypair(mbedtls_pk_context *pkey, sss_object_t *pkeyObject)
{
    void *pax_ctx         = NULL;
    uint32_t objectId[16] = {
        0,
    };
    uint8_t objectIdLen = sizeof(objectId);
    sss_status_t status = kStatus_SSS_Fail;

    memset(pkey, 0, sizeof(*pkey));

    if (pkeyObject->cipherType == kSSS_CipherType_EC_NIST_P || pkeyObject->cipherType == kSSS_CipherType_EC_NIST_K ||
        pkeyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL ||
        pkeyObject->cipherType == kSSS_CipherType_EC_MONTGOMERY ||
        pkeyObject->cipherType == kSSS_CipherType_EC_TWISTED_ED) {
        LOG_D("Associating ECC key-pair '0x%08X'", pkeyObject->keyId);

        pkey->pk_info = &ax_mbedtls_eckeypair_info;
        pax_ctx       = (mbedtls_ecp_keypair *)mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
        ((mbedtls_ecp_keypair *)pax_ctx)->grp.pSSSObject = pkeyObject;
        status = sss_util_asn1_get_oid_from_sssObj(pkeyObject, objectId, &objectIdLen);
        if (status != kStatus_SSS_Success) {
            if (pax_ctx != NULL) {
                mbedtls_free(pax_ctx);
            }
            return 1;
        }

        ((mbedtls_ecp_keypair *)pax_ctx)->grp.id = get_group_id(objectId, objectIdLen);
        if (((mbedtls_ecp_keypair *)pax_ctx)->grp.id == MBEDTLS_ECP_DP_NONE) {
            LOG_E(" sss_mbedtls_associate_keypair: Group id not found...\n");
            if (pax_ctx != NULL) {
                mbedtls_free(pax_ctx);
            }
            return 1;
        }
        pkey->pk_ctx = pax_ctx;
    }
#ifdef MBEDTLS_RSA_ALT
    else if (pkeyObject->cipherType == kSSS_CipherType_RSA || pkeyObject->cipherType == kSSS_CipherType_RSA_CRT) {
        uint8_t pbKey[1024];
        size_t pbKeyBitLen   = 0;
        size_t pbKeyBytetLen = sizeof(pbKey);
        uint8_t *modulus     = NULL;
        size_t modlen        = 0;
        uint8_t *pubExp      = NULL;
        size_t pubExplen     = 0;

        LOG_D("Associating RSA key-pair '0x%08X'", pkeyObject->keyId);

        pkey->pk_info = &ax_mbedtls_rsakeypair_info;
        pax_ctx       = (mbedtls_rsa_context *)mbedtls_calloc(1, sizeof(mbedtls_rsa_context));
        ((mbedtls_rsa_context *)pax_ctx)->pSSSObject = pkeyObject;

        status = sss_key_store_get_key(pkeyObject->keyStore, pkeyObject, pbKey, &pbKeyBytetLen, &pbKeyBitLen);
        if (status != kStatus_SSS_Success) {
            return 1;
        }

        status = sss_util_asn1_rsa_parse_public(pbKey, pbKeyBytetLen, &modulus, &modlen, &pubExp, &pubExplen);
        if (modulus != NULL) {
            SSS_FREE(modulus);
            modulus = NULL;
        }
        if (pubExp != NULL) {
            SSS_FREE(pubExp);
            pubExp = NULL;
        }
        if (status != kStatus_SSS_Success) {
            return 1;
        }

        ((mbedtls_rsa_context *)pax_ctx)->len = (modlen * 8);
    }
#endif /* MBEDTLS_RSA_ALT */
    else {
        return 1;
    }

    pkey->pk_ctx = pax_ctx;
    return 0;
}

int sss_mbedtls_associate_pubkey(mbedtls_pk_context *pkey, sss_object_t *pkeyObject)
{
    void *pax_ctx         = NULL;
    uint32_t objectId[16] = {
        0,
    };
    uint8_t objectIdLen = sizeof(objectId);
    sss_status_t status = kStatus_SSS_Fail;

    memset(pkey, 0, sizeof(*pkey));

    if (pkeyObject->cipherType == kSSS_CipherType_EC_NIST_P || pkeyObject->cipherType == kSSS_CipherType_EC_NIST_K ||
        pkeyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL ||
        pkeyObject->cipherType == kSSS_CipherType_EC_MONTGOMERY ||
        pkeyObject->cipherType == kSSS_CipherType_EC_TWISTED_ED) {
        LOG_D("Associating ECC public key '0x%08X'", pkeyObject->keyId);

        pkey->pk_info = &ax_mbedtls_ecpubkey_info;
        pax_ctx       = (mbedtls_ecp_keypair *)mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
        ((mbedtls_ecp_keypair *)pax_ctx)->grp.pSSSObject = pkeyObject;

        status = sss_util_asn1_get_oid_from_sssObj(pkeyObject, objectId, &objectIdLen);
        if (status != kStatus_SSS_Success) {
            if (pax_ctx != NULL) {
                mbedtls_free(pax_ctx);
            }
            return 1;
        }

        ((mbedtls_ecp_keypair *)pax_ctx)->grp.id = get_group_id(objectId, objectIdLen);
        if (((mbedtls_ecp_keypair *)pax_ctx)->grp.id == MBEDTLS_ECP_DP_NONE) {
            LOG_E(" sss_mbedtls_associate_pubkey: Group id not found...\n");
            if (pax_ctx != NULL) {
                mbedtls_free(pax_ctx);
            }
            return 1;
        }
    }
#ifdef MBEDTLS_RSA_ALT
    else if (pkeyObject->cipherType == kSSS_CipherType_RSA || pkeyObject->cipherType == kSSS_CipherType_RSA_CRT) {
        uint8_t pbKey[1400];
        size_t pbKeyBitLen   = 0;
        size_t pbKeyBytetLen = sizeof(pbKey);
        uint8_t *modulus     = NULL;
        size_t modlen        = 0;
        uint8_t *pubExp      = NULL;
        size_t pubExplen     = 0;

        LOG_D("Associating RSA public key '0x%08X'", pkeyObject->keyId);

        pax_ctx       = (mbedtls_rsa_context *)mbedtls_calloc(1, sizeof(mbedtls_rsa_context));
        pkey->pk_ctx  = pax_ctx;
        pkey->pk_info = &ax_mbedtls_rsapubkey_info;
        ((mbedtls_rsa_context *)pax_ctx)->pSSSObject = pkeyObject;

        status = sss_key_store_get_key(pkeyObject->keyStore, pkeyObject, pbKey, &pbKeyBytetLen, &pbKeyBitLen);
        if (status != kStatus_SSS_Success) {
            return 1;
        }

        status = sss_util_asn1_rsa_parse_public(pbKey, pbKeyBytetLen, &modulus, &modlen, &pubExp, &pubExplen);
        if (modulus != NULL) {
            SSS_FREE(modulus);
            modulus = NULL;
        }
        if (pubExp != NULL) {
            SSS_FREE(pubExp);
            pubExp = NULL;
        }
        if (status != kStatus_SSS_Success) {
            return 1;
        }

        ((mbedtls_rsa_context *)pax_ctx)->len = (modlen * 8);
    }
#endif /* MBEDTLS_RSA_ALT */
    else {
        return 1;
    }

    pkey->pk_ctx = pax_ctx;
    return 0;
}

int sss_mbedtls_associate_ecdhctx(
    mbedtls_ssl_handshake_params *handshake, sss_object_t *pSSSObject, sss_key_store_t *hostKs)
{
    sss_status_t status   = kStatus_SSS_Fail;
    uint32_t objectId[16] = {
        0,
    };
    uint8_t objectIdLen = sizeof(objectId);

    status = sss_util_asn1_get_oid_from_sssObj(pSSSObject, objectId, &objectIdLen);
    if (status != kStatus_SSS_Success) {
        return 1;
    }

    handshake->ecdh_ctx.grp.id = get_group_id(objectId, objectIdLen);

    handshake->ecdh_ctx.grp.pSSSObject = pSSSObject;
    handshake->ecdh_ctx.grp.hostKs     = hostKs;
#if LOG_API_CALLS > 1
    LOG_I("Associating ECC key-pair '%d' for handshake.\r\n", key_index);
#endif
    return 0;
}

static size_t sss_eckey_get_bitlen(const void *ctx)
{
    return ((64 << 1) + 1);
}

static int sss_eckey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len)
{
    sss_status_t status = kStatus_SSS_Success;
    sss_asymmetric_t asymVerifyCtx;
    sss_object_t *sssObject = NULL;
    sss_algorithm_t algorithm;
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;

    sssObject = pax_ctx->grp.pSSSObject;

    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_SSS_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_SSS_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_SSS_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_SSS_SHA512;
        break;
    default:
        return 1;
    }

    LOG_D("Using ECC key-pair '0x%08X'", pax_ctx->grp.pSSSObject->keyId);

    status = sss_asymmetric_context_init(
        &asymVerifyCtx, sssObject->keyStore->session, sssObject, algorithm, kMode_SSS_Verify);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_context_init verify context Failed...\n");
        return 1;
    }
    status = sss_asymmetric_verify_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, (uint8_t *)sig, sig_len);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_verify_digest Failed...\n");
        return 1;
    }

    return (0);
}

static int sss_eckey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    int ret            = 0;
    size_t u16_sig_len = 1024;
    sss_asymmetric_t asymVerifyCtx;
    sss_status_t status          = kStatus_SSS_Success;
    sss_object_t *sssObject      = NULL;
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    sss_algorithm_t algorithm;

    sssObject = pax_ctx->grp.pSSSObject;
    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_SSS_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_SSS_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_SSS_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_SSS_SHA512;
        break;
    default:
        return 1;
    }

    status =
        sss_asymmetric_context_init(&asymVerifyCtx, sssObject->keyStore->session, sssObject, algorithm, kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_context_init verify context Failed...\n");
        return 1;
    }

    LOG_D("Signing using key %08lX\r\n", pax_ctx->grp.pSSSObject->keyId);

    status = sss_asymmetric_sign_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, sig, &u16_sig_len);
    if (status != kStatus_SSS_Success) {
        LOG_W(" sss_asymmetric_sign_digest Failed...\n");
        return 1;
    }

    *sig_len = u16_sig_len;

    return (ret);
}

static int sss_eckey_check_pair(const void *pub, const void *prv)
{
    return 0;
}

static int sss_eckeypair_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECKEY_DH || type == MBEDTLS_PK_ECDSA);
}

static int sss_ecpubkey_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECKEY_DH || type == MBEDTLS_PK_ECDSA);
}

static void sss_eckeypair_free_func(void *ctx)
{
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    if (pax_ctx != NULL) {
        mbedtls_free(ctx);
    }
    return;
}

static void sss_ecpubkey_free_func(void *ctx)
{
    mbedtls_ecp_keypair *pax_ctx = (mbedtls_ecp_keypair *)ctx;
    if (pax_ctx != NULL) {
        mbedtls_free(ctx);
    }
    return;
}

/** @} */

#endif /* MBEDTLS_ECP_ALT */
