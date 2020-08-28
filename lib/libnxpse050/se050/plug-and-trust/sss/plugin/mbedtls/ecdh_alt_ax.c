/*
 * Copyright 2017-2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * Implementation of key association between NXP Secure Element and mbedtls.
 *
 *****************************************************************************/
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECDH_ALT) && SSS_HAVE_ALT_SSS

#include <fsl_sss_util_asn1_der.h>
#include <nxLog_sss.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/version.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(FLOW_VERBOSE) && FLOW_VERBOSE == 1
#include "sm_printf.h"
#include "sm_types.h"
#endif /* FLOW_VERBOSE */

extern int mbedtls_ecdh_gen_public_o(mbedtls_ecp_group *grp,
    mbedtls_mpi *d,
    mbedtls_ecp_point *Q,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);
extern int mbedtls_ecdh_compute_shared_o(mbedtls_ecp_group *grp,
    mbedtls_mpi *z,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);
extern int mbedtls_ecdh_get_params_o(mbedtls_ecdh_context *ctx, const mbedtls_ecp_keypair *key, mbedtls_ecdh_side side);

int get_header_and_bit_Length(int groupid, int *headerLen, int *bitLen)
{
    switch (groupid) {
    case MBEDTLS_ECP_DP_SECP192R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp192_header_len;
        if (bitLen != NULL)
            *bitLen = 192;
        break;
    case MBEDTLS_ECP_DP_SECP224R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp224_header_len;
        if (bitLen != NULL)
            *bitLen = 224;
        break;
    case MBEDTLS_ECP_DP_SECP256R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp256_header_len;
        if (bitLen != NULL)
            *bitLen = 256;
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp384_header_len;
        if (bitLen != NULL)
            *bitLen = 384;
        break;
    case MBEDTLS_ECP_DP_SECP521R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp521_header_len;
        if (bitLen != NULL)
            *bitLen = 521;
        break;
    case MBEDTLS_ECP_DP_BP256R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_bp256_header_len;
        if (bitLen != NULL)
            *bitLen = 256;
        break;
    case MBEDTLS_ECP_DP_BP384R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_bp384_header_len;
        if (bitLen != NULL)
            *bitLen = 384;
        break;
    case MBEDTLS_ECP_DP_BP512R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_bp512_header_len;
        if (bitLen != NULL)
            *bitLen = 512;
        break;
    case MBEDTLS_ECP_DP_SECP192K1:
        if (headerLen != NULL)
            *headerLen = der_ecc_192k_header_len;
        if (bitLen != NULL)
            *bitLen = 192;
        break;
    case MBEDTLS_ECP_DP_SECP224K1:
        if (headerLen != NULL)
            *headerLen = der_ecc_224k_header_len;
        if (bitLen != NULL)
            *bitLen = 224;
        break;
    case MBEDTLS_ECP_DP_SECP256K1:
        if (headerLen != NULL)
            *headerLen = der_ecc_256k_header_len;
        if (bitLen != NULL)
            *bitLen = 256;
        break;
    case MBEDTLS_ECP_DP_CURVE25519:
        if (headerLen != NULL)
            *headerLen = 0;
        if (bitLen != NULL)
            *bitLen = 256;
        break;
    case MBEDTLS_ECP_DP_CURVE448:
        if (headerLen != NULL)
            *headerLen = 0;
        if (bitLen != NULL)
            *bitLen = 448;
        break;
    default:
        LOG_E("get_header_and_bit_Length: Group id not supported");
        return 1;
    }

    return 0;
}

/*
 * Generate public key: simple wrapper around mbedtls_ecp_gen_keypair
 */
int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp,
    mbedtls_mpi *d,
    mbedtls_ecp_point *Q,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    sss_status_t status    = kStatus_SSS_Fail;
    uint8_t publickey[256] = {
        0,
    };
    int headerLen          = 0;
    size_t publickeylen    = sizeof(publickey);
    size_t publickeyBitLen = publickeylen * 8;

    if (grp->pSSSObject == NULL) {
        return mbedtls_ecdh_gen_public_o(grp, d, Q, f_rng, p_rng);
    }
    else if (grp->pSSSObject->objectType == kSSS_KeyPart_Pair &&
             (grp->pSSSObject->cipherType == kSSS_CipherType_EC_NIST_P ||
                 grp->pSSSObject->cipherType == kSSS_CipherType_EC_NIST_K ||
                 grp->pSSSObject->cipherType == kSSS_CipherType_EC_BRAINPOOL ||
                 grp->pSSSObject->cipherType == kSSS_CipherType_EC_MONTGOMERY ||
                 grp->pSSSObject->cipherType == kSSS_CipherType_EC_TWISTED_ED)) {
        if (get_header_and_bit_Length(grp->id, &headerLen, NULL)) {
            return 1;
        }

        mbedtls_mpi_free(d);
        status = sss_key_store_get_key(
            grp->pSSSObject->keyStore, grp->pSSSObject, publickey, &publickeylen, &publickeyBitLen);
        if (kStatus_SSS_Success == status) {
            publickeylen -= headerLen;
            return mbedtls_ecp_point_read_binary(grp, Q, &publickey[headerLen], publickeylen);
        }
        else {
            return 1;
        }
    }
    return 1;
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp,
    mbedtls_mpi *z,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    int ret                      = 1;
    sss_key_part_t keyType       = kSSS_KeyPart_NONE;
    sss_cipher_type_t cipherType = kSSS_CipherType_NONE;
    int headerLen                = 0;
    uint8_t OtherPublicKey[256];
    size_t OtherPublickeylen = sizeof(OtherPublicKey);
    int keyBitLen            = 0;
    sss_status_t status;
    sss_object_t otherPartyKeyObject;
    sss_object_t derivedKeyObject;
    sss_derive_key_t context;
    uint8_t SharedSecret[128];
    uint16_t SharedSecretlen = sizeof(SharedSecret);
    uint8_t buf[256];
    size_t bitLen                              = 500;
    size_t bufByteLen                          = sizeof(buf);
    sss_cipher_type_t OtherPublickeycipherType = kSSS_CipherType_NONE;

    if (get_header_and_bit_Length(grp->id, &headerLen, &keyBitLen)) {
        return 1;
    }

    if (grp->pSSSObject == NULL) {
        ret = mbedtls_ecdh_compute_shared_o(grp, z, Q, d, f_rng, p_rng);
    }
    else if (grp->pSSSObject->cipherType == kSSS_CipherType_EC_NIST_P ||
             grp->pSSSObject->cipherType == kSSS_CipherType_EC_NIST_K ||
             grp->pSSSObject->cipherType == kSSS_CipherType_EC_BRAINPOOL ||
             grp->pSSSObject->cipherType == kSSS_CipherType_EC_MONTGOMERY) {
        if (0 == mbedtls_ecp_point_write_binary(grp,
                     Q,
                     MBEDTLS_ECP_PF_UNCOMPRESSED,
                     &OtherPublickeylen,
                     (OtherPublicKey + headerLen),
                     sizeof(OtherPublicKey))) {
            switch (grp->id) {
            case MBEDTLS_ECP_DP_SECP192R1:
                memcpy(OtherPublicKey, gecc_der_header_nist192, der_ecc_nistp192_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_nistp192_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_SECP224R1:
                memcpy(OtherPublicKey, gecc_der_header_nist224, der_ecc_nistp224_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_nistp224_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_SECP256R1:
                memcpy(OtherPublicKey, gecc_der_header_nist256, der_ecc_nistp256_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_nistp256_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_SECP384R1:
                memcpy(OtherPublicKey, gecc_der_header_nist384, der_ecc_nistp384_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_nistp384_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_SECP521R1:
                memcpy(OtherPublicKey, gecc_der_header_nist521, der_ecc_nistp521_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_nistp521_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_BP256R1:
                memcpy(OtherPublicKey, gecc_der_header_bp256, der_ecc_bp256_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_bp256_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
                break;
            case MBEDTLS_ECP_DP_BP384R1:
                memcpy(OtherPublicKey, gecc_der_header_bp384, der_ecc_bp384_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_bp384_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
                break;
            case MBEDTLS_ECP_DP_BP512R1:
                memcpy(OtherPublicKey, gecc_der_header_bp512, der_ecc_bp512_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_bp512_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
                break;
            case MBEDTLS_ECP_DP_SECP192K1:
                memcpy(OtherPublicKey, gecc_der_header_192k, der_ecc_192k_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_192k_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
                break;
            case MBEDTLS_ECP_DP_SECP224K1:
                memcpy(OtherPublicKey, gecc_der_header_224k, der_ecc_224k_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_224k_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
                break;
            case MBEDTLS_ECP_DP_SECP256K1:
                memcpy(OtherPublicKey, gecc_der_header_256k, der_ecc_256k_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_256k_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
                break;
            case MBEDTLS_ECP_DP_CURVE25519:
                memcpy(OtherPublicKey, gecc_der_header_mont_dh_25519, der_ecc_mont_dh_25519_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_mont_dh_25519_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_MONTGOMERY;
                break;
            case MBEDTLS_ECP_DP_CURVE448:
                memcpy(OtherPublicKey, gecc_der_header_mont_dh_448, der_ecc_mont_dh_448_header_len);
                OtherPublickeylen        = OtherPublickeylen + der_ecc_mont_dh_448_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_MONTGOMERY;
                break;
            default:
                return 1;
            }

            do {
                //For The derived shared secret init and allocate
                status = sss_key_object_init(&derivedKeyObject, grp->hostKs);
                if (status != kStatus_SSS_Success) {
                    printf(
                        " sss_key_object_init for derivedKeyObject "
                        "Failed...\n");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                keyType    = kSSS_KeyPart_Default;
                cipherType = kSSS_CipherType_AES;

                status = sss_key_object_allocate_handle(
                    &derivedKeyObject, (__LINE__), keyType, cipherType, SharedSecretlen, kKeyObject_Mode_Transient);
                if (status != kStatus_SSS_Success) {
                    LOG_E(
                        " sss_key_object_allocate_handle for derivedKeyObject "
                        "Failed");
                    ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
                    break;
                }

                //  SSCP Transient Object for the othe party public key init and allocate
                status = sss_key_object_init(&otherPartyKeyObject, grp->hostKs);
                if (status != kStatus_SSS_Success) {
                    LOG_E(
                        " sss_key_object_init for otherPartyKeyObject "
                        "Failed");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                status = sss_key_object_allocate_handle(&otherPartyKeyObject,
                    (__LINE__),
                    kSSS_KeyPart_Public,
                    OtherPublickeycipherType,
                    (sizeof(OtherPublicKey)),
                    kKeyObject_Mode_Transient);
                if (status != kStatus_SSS_Success) {
                    LOG_E(
                        " sss_key_object_allocate_handle for "
                        "otherPartyKeyObject Failed");
                    ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
                    break;
                }

                //setting  the other party public key
                status = sss_key_store_set_key(
                    grp->hostKs, &otherPartyKeyObject, OtherPublicKey, OtherPublickeylen, keyBitLen, NULL, 0);
                if (status != kStatus_SSS_Success) {
                    LOG_E(" sss_key_store_set_key  for keyPair Failed");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                status = sss_derive_key_context_init(&context,
                    grp->pSSSObject->keyStore->session,
                    grp->pSSSObject,
                    kAlgorithm_SSS_ECDH,
                    kMode_SSS_ComputeSharedSecret);
                if (status != kStatus_SSS_Success) {
                    printf(" sss_derive_key_context_init Failed...\n");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                status = sss_derive_key_dh(&context, &otherPartyKeyObject, &derivedKeyObject);
                if (status != kStatus_SSS_Success) {
                    printf(" sss_derive_key_dh Failed...\n");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                status = sss_key_store_get_key(grp->hostKs, &derivedKeyObject, buf, &bufByteLen, &bitLen);
                if (status != kStatus_SSS_Success) {
                    printf(" sss_key_store_get_key Failed...\n");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }
                ret = mbedtls_mpi_read_binary(z, buf, bufByteLen);
            } while (0);
            sss_key_object_free(&otherPartyKeyObject);
            sss_key_object_free(&derivedKeyObject);
        }
    }
    else {
        ret = 1; //Failed
    }
    return (ret);
}

/*
 * Get parameters from a keypair
 */
int mbedtls_ecdh_get_params(mbedtls_ecdh_context *ctx, const mbedtls_ecp_keypair *key, mbedtls_ecdh_side side)
{
    int ret;
    sss_object_t *backup_type_SSS_Object = ctx->grp.pSSSObject;
    sss_key_store_t *backup_type_hostKs  = ctx->grp.hostKs;
    ret                                  = mbedtls_ecdh_get_params_o(ctx, key, side);
    ctx->grp.pSSSObject                  = backup_type_SSS_Object;
    ctx->grp.hostKs                      = backup_type_hostKs;
    return (ret);
}

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef mbedtls_ecdh_context mbedtls_ecdh_context_mbed;

int ecdh_get_params_internal(mbedtls_ecdh_context_mbed *ctx, const mbedtls_ecp_keypair *key, mbedtls_ecdh_side side)
{
    return mbedtls_ecdh_get_params(ctx, key, side);
}

#endif

#endif /* defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECDH_ALT) */
