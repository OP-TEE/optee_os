/*
 * Copyright 2018-2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file sss_mbedtls_rsa.c
 *
 * @par Description
 * Implementation of key association between SSS and mbedtls.
 *
 *****************************************************************************/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/** @ingroup ax_mbed_tls */
/** @{ */

#if defined(MBEDTLS_RSA_ALT)

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

static size_t sss_rsakey_get_bitlen(const void *ctx);
static int sss_rsakey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);
static int sss_rsakey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len);
static int sss_rsakey_check_pair(const void *pub, const void *prv);
static int sss_rsakeypair_can_do(mbedtls_pk_type_t type);
static int sss_rsapubkey_can_do(mbedtls_pk_type_t type);
static void sss_rsakeypair_free_func(void *ctx);
static void sss_rsapubkey_free_func(void *ctx);

const mbedtls_pk_info_t ax_mbedtls_rsakeypair_info = {
    MBEDTLS_PK_RSA,
    "AxRSA_Keypair",
    &sss_rsakey_get_bitlen,
    &sss_rsakeypair_can_do,
    NULL,
    &sss_rsakey_sign,
    NULL, // decrypt_func,
    NULL, // encrypt_func,
    &sss_rsakey_check_pair,
    NULL, //&ax_rsakey_alloc,
    &sss_rsakeypair_free_func,
    NULL, //&ax_rsakey_debug,
};

const mbedtls_pk_info_t ax_mbedtls_rsapubkey_info = {
    MBEDTLS_PK_RSA,
    "AxRSA_pubkey",
    &sss_rsakey_get_bitlen,
    &sss_rsapubkey_can_do,
    &sss_rsakey_verify,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &sss_rsapubkey_free_func,
    NULL,
};

static size_t sss_rsakey_get_bitlen(const void *ctx)
{
    mbedtls_rsa_context *pax_ctx = (mbedtls_rsa_context *)ctx;
    return pax_ctx->len;
}

static int sss_rsakey_verify(void *ctx,
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
    mbedtls_rsa_context *pax_ctx = (mbedtls_rsa_context *)ctx;

    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
        break;
    default:
        return 1;
    }
    sssObject = (sss_object_t *)pax_ctx->pSSSObject;

    LOG_D("Using RSA key-pair '0x%08X'", pax_ctx->pSSSObject->keyId);

    status = sss_asymmetric_context_init(
        &asymVerifyCtx, sssObject->keyStore->session, sssObject, algorithm, kMode_SSS_Verify);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_context_init verify context Failed.");
        return 1;
    }
    status = sss_asymmetric_verify_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, (uint8_t *)sig, sig_len);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_verify_digest Failed.");
        return 1;
    }

    return (0);
}

static int sss_rsakey_sign(void *ctx,
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
    mbedtls_rsa_context *pax_ctx = NULL;
    sss_algorithm_t algorithm;

    pax_ctx   = (mbedtls_rsa_context *)ctx;
    sssObject = (sss_object_t *)pax_ctx->pSSSObject;

    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
        break;
    default:
        return 1;
    }

    status =
        sss_asymmetric_context_init(&asymVerifyCtx, sssObject->keyStore->session, sssObject, algorithm, kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_context_init verify context Failed.");
        return 1;
    }

    LOG_D("Signing using key %08lX\r\n", pax_ctx->pSSSObject->keyId);

    status = sss_asymmetric_sign_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, sig, &u16_sig_len);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_asymmetric_sign_digest failed.");
        return 1;
    }

    *sig_len = u16_sig_len;

    return (ret);
}

static int sss_rsakey_check_pair(const void *pub, const void *prv)
{
    return 0;
}

static int sss_rsakeypair_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_RSA || type == MBEDTLS_PK_RSASSA_PSS);
}

static int sss_rsapubkey_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_RSA || type == MBEDTLS_PK_RSASSA_PSS);
}

static void sss_rsakeypair_free_func(void *ctx)
{
    mbedtls_rsa_context *pax_ctx = (mbedtls_rsa_context *)ctx;
    if (pax_ctx != NULL) {
        mbedtls_free(ctx);
    }
    return;
}

static void sss_rsapubkey_free_func(void *ctx)
{
    mbedtls_rsa_context *pax_ctx = (mbedtls_rsa_context *)ctx;
    if (pax_ctx != NULL) {
        mbedtls_free(ctx);
    }
    return;
}

#endif /* MBEDTLS_RSA_ALT */

/** @} */
