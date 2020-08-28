/*
* Copyright 2018-2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#include <fsl_sss_util_asn1_der.h>
#include <nxEnsure.h>
#include <nxLog_sss.h>
#include <stdlib.h>
#include <string.h>

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_se05x_apis.h>
#endif

#if SSS_HAVE_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#endif

#if SSS_HAVE_OPENSSL
#include <fsl_sss_openssl_apis.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#define IS_VALID_TAG(x)                                                                             \
    (x == ASN_TAG_SEQUENCE || x == ASN_TAG_OBJ_IDF || x == ASN_TAG_BITSTRING || x == ASN_TAG_INT || \
        x == ASN_TAG_OCTETSTRING || x == ASN_TAG_CNT_SPECIFIC || x == ASN_TAG_CRL_EXTENSIONS) ?     \
        1 :                                                                                         \
        0

#define IS_VALID_RFC8410_TAG(x)                                                                     \
    (x == ASN_TAG_SEQUENCE || x == ASN_TAG_OBJ_IDF || x == ASN_TAG_BITSTRING || x == ASN_TAG_INT || \
        x == ASN_TAG_OCTETSTRING || x == ASN_TAG_CNT_SPECIFIC || x == ASN_TAG_CRL_EXTENSIONS ||     \
        x == (ASN_TAG_CNT_SPECIFIC_PRIMITIVE | 0x01)) ?                                             \
        1 :                                                                                         \
        0

/* clang-format off */

/* RSA Header */
const uint8_t grsa512PubHeader[] = {
    0x30, 0x5C, 0x30, 0x0D,     0x06, 0x09, 0x2A, 0x86,  \
    0x48, 0x86, 0xF7, 0x0D,     0x01, 0x01, 0x01, 0x05,  \
    0x00, 0x03, 0x4B, 0x00,     0x30, 0x48, 0x02 };

const uint8_t grsa1kPubHeader[] = {
    0x30, 0x81, 0x9F, 0x30,     0x0D, 0x06, 0x09, 0x2A,  \
    0x86, 0x48, 0x86, 0xF7,     0x0D, 0x01, 0x01, 0x01,  \
    0x05, 0x00, 0x03, 0x81,     0x8D, 0x00, 0x30, 0x81,  \
    0x89, 0x02 };

const uint8_t grsa1152PubHeader[] = {
    0x30, 0x81, 0xAF, 0x30,     0x0D, 0x06, 0x09, 0x2A,  \
    0x86, 0x48, 0x86, 0xF7,     0x0D, 0x01, 0x01, 0x01,  \
    0x05, 0x00, 0x03, 0x81,     0x9D, 0x00, 0x30, 0x81,  \
    0x99, 0x02 };

const uint8_t grsa2kPubHeader[] = {
    0x30, 0x82, 0x01, 0x22,     0x30, 0x0D, 0x06, 0x09,  \
    0x2A, 0x86, 0x48, 0x86,     0xF7, 0x0D, 0x01, 0x01,  \
    0x01, 0x05, 0x00, 0x03,     0x82, 0x01, 0x0F, 0x00,  \
    0x30, 0x82, 0x01, 0x0A,     0x02 };

const uint8_t grsa3kPubHeader[] = {
    0x30, 0x82, 0x01, 0xA2,     0x30, 0x0D, 0x06, 0x09,  \
    0x2A, 0x86, 0x48, 0x86,     0xF7, 0x0D, 0x01, 0x01,  \
    0x01, 0x05, 0x00, 0x03,     0x82, 0x01, 0x8F, 0x00,  \
    0x30, 0x82, 0x01, 0x8A,     0x02 };

const uint8_t grsa4kPubHeader[] = {
    0x30, 0x82, 0x02, 0x22,     0x30, 0x0D, 0x06, 0x09,  \
    0x2A, 0x86, 0x48, 0x86,     0xF7, 0x0D, 0x01, 0x01,  \
    0x01, 0x05, 0x00, 0x03,     0x82, 0x02, 0x0F, 0x00,  \
    0x30, 0x82, 0x02, 0x0A,     0x02 };

/* ECC Header */
const uint8_t gecc_der_header_nist192[] = {
    0x30, 0x49, 0x30, 0x13,     0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02,     0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D,     0x03, 0x01, 0x01, 0x03,
    0x32, 0x00, };

const uint8_t gecc_der_header_nist224[] = {
    0x30, 0x4E, 0x30, 0x10,     0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02,     0x01, 0x06, 0x05, 0x2B,
    0x81, 0x04, 0x00, 0x21,     0x03, 0x3A, 0x00, };

const uint8_t gecc_der_header_nist256[] = {
    0x30, 0x59, 0x30, 0x13,     0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02,     0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D,     0x03, 0x01, 0x07, 0x03,
    0x42, 0x00 };

const uint8_t gecc_der_header_nist384[] = {
    0x30, 0x76, 0x30, 0x10,     0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02,     0x01, 0x06, 0x05, 0x2B,
    0x81, 0x04, 0x00, 0x22,     0x03, 0x62, 0x00, };

const uint8_t gecc_der_header_nist521[] = {
    0x30, 0x81, 0x9B, 0x30,     0x10, 0x06, 0x07, 0x2A,
    0x86, 0x48, 0xCE, 0x3D,     0x02, 0x01, 0x06, 0x05,
    0x2B, 0x81, 0x04, 0x00,     0x23, 0x03, 0x81, 0x86,
    0x00, };

const uint8_t gecc_der_header_160k[] = {
    0x30, 0x3e, 0x30, 0x10,     0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02,     0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x09,     0x03, 0x2a, 0x00, };

const uint8_t gecc_der_header_192k[] = {
    0x30, 0x46, 0x30, 0x10,     0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02,     0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x1f,     0x03, 0x32, 0x00, };

const uint8_t gecc_der_header_224k[] = {
    0x30, 0x4e, 0x30, 0x10,     0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02,     0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x20,     0x03, 0x3a, 0x00, };

const uint8_t gecc_der_header_256k[] = {
    0x30, 0x56, 0x30, 0x10,     0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02,     0x01, 0x06, 0x05, 0x2B,
    0x81, 0x04, 0x00, 0x0A,     0x03, 0x42, 0x00 };

const uint8_t gecc_der_header_bp160[] = {
    0x30, 0x42, 0x30, 0x14,     0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02,     0x01, 0x06, 0x09, 0x2b,
    0x24, 0x03, 0x03, 0x02,     0x08, 0x01, 0x01, 0x01,
    0x03, 0x2a, 0x00, };

const uint8_t gecc_der_header_bp192[] = {
    0x30, 0x4a, 0x30, 0x14,     0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02,     0x01, 0x06, 0x09, 0x2b,
    0x24, 0x03, 0x03, 0x02,     0x08, 0x01, 0x01, 0x03,
    0x03, 0x32, 0x00, };

const uint8_t gecc_der_header_bp224[] = {
    0x30, 0x52, 0x30, 0x14,     0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02,     0x01, 0x06, 0x09, 0x2b,
    0x24, 0x03, 0x03, 0x02,     0x08, 0x01, 0x01, 0x05,
    0x03, 0x3a, 0x00, };

const uint8_t gecc_der_header_bp256[] = {
    0x30, 0x5a, 0x30, 0x14,     0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02,     0x01, 0x06, 0x09, 0x2b,
    0x24, 0x03, 0x03, 0x02,     0x08, 0x01, 0x01, 0x07,
    0x03, 0x42, 0x00, };

const uint8_t gecc_der_header_bp320[] = {
    0x30, 0x6a, 0x30, 0x14,     0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02,     0x01, 0x06, 0x09, 0x2b,
    0x24, 0x03, 0x03, 0x02,     0x08, 0x01, 0x01, 0x09,
    0x03, 0x52, 0x00,
};

const uint8_t gecc_der_header_bp384[] = {
    0x30, 0x7A, 0x30, 0x14,     0x06, 0x07, 0x2A, 0x86,  \
    0x48, 0xCE, 0x3D, 0x02,     0x01, 0x06, 0x09, 0x2B,  \
    0x24, 0x03, 0x03, 0x02,     0x08, 0x01, 0x01, 0x0B,  \
    0x03, 0x62, 0x00, };

const uint8_t gecc_der_header_bp512[] = {
    0x30, 0x81, 0x9B, 0x30,     0x14, 0x06, 0x07, 0x2A,
    0x86, 0x48, 0xCE, 0x3D,     0x02, 0x01, 0x06, 0x09,
    0x2B, 0x24, 0x03, 0x03,     0x02, 0x08, 0x01, 0x01,
    0x0D, 0x03, 0x81, 0x82,     0x00, };

const uint8_t gecc_der_header_mont_dh_448[] = {
    0x30, 0x42, 0x30, 0x05,     0x06, 0x03, 0x2b, 0x65,
    0x6f, 0x03, 0x39, 0x00, };

const uint8_t gecc_der_header_mont_dh_25519[] = {
    0x30, 0x2a, 0x30, 0x05,     0x06, 0x03, 0x2b, 0x65,
    0x6e, 0x03, 0x21, 0x00, };

const uint8_t gecc_der_header_twisted_ed_25519[] = {
    0x30, 0x2a, 0x30, 0x05,     0x06, 0x03, 0x2b, 0x65,
    0x70, 0x03, 0x21, 0x00, };

/* clang-format on */

size_t const der_ecc_nistp192_header_len         = sizeof(gecc_der_header_nist192);
size_t const der_ecc_nistp224_header_len         = sizeof(gecc_der_header_nist224);
size_t const der_ecc_nistp256_header_len         = sizeof(gecc_der_header_nist256);
size_t const der_ecc_nistp384_header_len         = sizeof(gecc_der_header_nist384);
size_t const der_ecc_nistp521_header_len         = sizeof(gecc_der_header_nist521);
size_t const der_ecc_160k_header_len             = sizeof(gecc_der_header_160k);
size_t const der_ecc_192k_header_len             = sizeof(gecc_der_header_192k);
size_t const der_ecc_224k_header_len             = sizeof(gecc_der_header_224k);
size_t const der_ecc_256k_header_len             = sizeof(gecc_der_header_256k);
size_t const der_ecc_bp160_header_len            = sizeof(gecc_der_header_bp160);
size_t const der_ecc_bp192_header_len            = sizeof(gecc_der_header_bp192);
size_t const der_ecc_bp224_header_len            = sizeof(gecc_der_header_bp224);
size_t const der_ecc_bp256_header_len            = sizeof(gecc_der_header_bp256);
size_t const der_ecc_bp320_header_len            = sizeof(gecc_der_header_bp320);
size_t const der_ecc_bp384_header_len            = sizeof(gecc_der_header_bp384);
size_t const der_ecc_bp512_header_len            = sizeof(gecc_der_header_bp512);
size_t const der_ecc_mont_dh_448_header_len      = sizeof(gecc_der_header_mont_dh_448);
size_t const der_ecc_mont_dh_25519_header_len    = sizeof(gecc_der_header_mont_dh_25519);
size_t const der_ecc_twisted_ed_25519_header_len = sizeof(gecc_der_header_twisted_ed_25519);

static int check_tag(int tag);

/* ************************************************************************** */
/* Functions : ASN.1 Functions                                                */
/* ************************************************************************** */

sss_status_t sss_util_asn1_rsa_parse_private(const uint8_t *key,
    size_t keylen,
    sss_cipher_type_t cipher_type,
    uint8_t **modulus,
    size_t *modlen,
    uint8_t **pubExp,
    size_t *pubExplen,
    uint8_t **priExp,
    size_t *priExplen,
    uint8_t **prime1,
    size_t *prime1len,
    uint8_t **prime2,
    size_t *prime2len,
    uint8_t **exponent1,
    size_t *exponent1len,
    uint8_t **exponent2,
    size_t *exponent2len,
    uint8_t **coefficient,
    size_t *coefficientlen)
{
    uint8_t *pBuf   = (uint8_t *)key;
    size_t taglen   = 0;
    size_t bufIndex = 0;
    uint8_t tag;
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    /* Parse ASN.1 Sequence */
    /* Example:
        0x30, 0x82, 0x02, 0x77,     ;SEQUENCE
            0x02, 0x01,             ;INTEGER
                0x00,               ;Algorithm version
            0x30, 0x0D,             ;Sequence
                0x06, 0x09,         ;ObjectIdentifier
                    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                    0x01,
                0x05, 0x00,         ;Null
            0x04, 0x82, 0x02, 0x61,         ;OctetString
                0x30, 0x82, 0x02, 0x5D,     ;Sequence
                    0x02, 0x01, 0x00,       ;Integer
                    0x02, 0x81, 0x81,       ;Integer    - Modulus
        */
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (taglen != (keylen - bufIndex)) {
        LOG_E("Invlaid Key");
        goto exit;
    }
    /* No need of algorithem Version */
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    if (pBuf[bufIndex] == ASN_TAG_INT) {
        bufIndex += 3;
    }
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    tag = pBuf[bufIndex];
    while (tag != ASN_TAG_INT) {
        ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* Private Key Header Nested TLV */
        if (ret != 0)
            goto exit;
        if (tag == ASN_TAG_SEQUENCE && pBuf[bufIndex] != ASN_TAG_INT)
            bufIndex += taglen;
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        tag = pBuf[bufIndex];
    }

    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    if (pBuf[bufIndex] == ASN_TAG_INT && pBuf[bufIndex + 1] == 1) {
        bufIndex += 3;
    }
    /* Get the Modulus*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (modlen != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *modlen = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *modlen = taglen;
        *modulus = SSS_MALLOC(*modlen);
        if ((*modulus != NULL) && ((*modlen) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*modulus, pBuf + bufIndex, *modlen);
            bufIndex += *modlen;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Public Exponent */
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (pubExplen != NULL) {
        *pubExplen = taglen;
        *pubExp    = SSS_MALLOC(*pubExplen);
        if ((*pubExp != NULL) && ((*pubExplen) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*pubExp, pBuf + bufIndex, *pubExplen);
            bufIndex += *pubExplen;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Private Exponent*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (priExplen != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *priExplen = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *priExplen = taglen;
        *priExp = SSS_MALLOC(*priExplen);
        if ((*priExp != NULL) && ((*priExplen) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*priExp, pBuf + bufIndex, *priExplen);
            bufIndex += *priExplen;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get First prime (p)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (prime1len != NULL) {
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *prime1len = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *prime1len = taglen;
        *prime1 = SSS_MALLOC(*prime1len);
        if ((*prime1 != NULL) && ((*prime1len) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*prime1, pBuf + bufIndex, *prime1len);
            bufIndex += *prime1len;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Second prime (q)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (prime2len != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *prime2len = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *prime2len = taglen;
        *prime2 = SSS_MALLOC(*prime2len);
        if (*prime2 == NULL) {
            LOG_E("malloc failed");
            goto exit;
        }
        if (*prime2len > 0) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*prime2, pBuf + bufIndex, *prime2len);
            bufIndex += *prime2len;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get First exponent (dP)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (exponent1len != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *exponent1len = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *exponent1len = taglen;
        *exponent1 = SSS_MALLOC(*exponent1len);
        if ((*exponent1 != NULL) && ((*exponent1len) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*exponent1, pBuf + bufIndex, *exponent1len);
            bufIndex += *exponent1len;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Second  exponent (dQ)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (exponent2len != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *exponent2len = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *exponent2len = taglen;
        *exponent2 = SSS_MALLOC(*exponent2len);
        if (*exponent2 == NULL) {
            LOG_E("malloc failed");
            goto exit;
        }
        if (*exponent2len > 0) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*exponent2, pBuf + bufIndex, *exponent2len);
            bufIndex += *exponent2len;
        }
        else {
            LOG_E("exponent2len improper");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Coefficient (qinv)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    if (coefficientlen != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *coefficientlen = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *coefficientlen = taglen;
        *coefficient = SSS_MALLOC(*coefficientlen);
        if ((*coefficient != NULL) && ((*coefficientlen) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*coefficient, pBuf + bufIndex, *coefficientlen);
            bufIndex += *coefficientlen;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_util_asn1_rsa_parse_private_allow_invalid_key(const uint8_t *key,
    size_t keylen,
    sss_cipher_type_t cipher_type,
    uint8_t **modulus,
    size_t *modlen,
    uint8_t **pubExp,
    size_t *pubExplen,
    uint8_t **priExp,
    size_t *priExplen,
    uint8_t **prime1,
    size_t *prime1len,
    uint8_t **prime2,
    size_t *prime2len,
    uint8_t **exponent1,
    size_t *exponent1len,
    uint8_t **exponent2,
    size_t *exponent2len,
    uint8_t **coefficient,
    size_t *coefficientlen)
{
    uint8_t *pBuf   = (uint8_t *)key;
    size_t taglen   = 0;
    size_t bufIndex = 0;
    uint8_t tag;
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    /* Parse ASN.1 Sequence */
    /* Example:
        0x30, 0x82, 0x02, 0x77,     ;SEQUENCE
            0x02, 0x01,             ;INTEGER
                0x00,               ;Algorithm version
            0x30, 0x0D,             ;Sequence
                0x06, 0x09,         ;ObjectIdentifier
                    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                    0x01,
                0x05, 0x00,         ;Null
            0x04, 0x82, 0x02, 0x61,         ;OctetString
                0x30, 0x82, 0x02, 0x5D,     ;Sequence
                    0x02, 0x01, 0x00,       ;Integer
                    0x02, 0x81, 0x81,       ;Integer    - Modulus
        */
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    // if (taglen != (keylen - bufIndex)) {
    //     LOG_E("Invlaid Key");
    //     goto exit;
    // }
    /* No need of algorithem Version */
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    if (pBuf[bufIndex] == ASN_TAG_INT) {
        bufIndex += 3;
    }

    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    tag = pBuf[bufIndex];
    while (tag != ASN_TAG_INT) {
        ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* Private Key Head*/
        ENSURE_OR_GO_EXIT(0 == ret);

        if (tag == ASN_TAG_SEQUENCE && pBuf[bufIndex] != ASN_TAG_INT)
            bufIndex += taglen;
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        tag = pBuf[bufIndex];
    }

    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    if (pBuf[bufIndex] == ASN_TAG_INT && pBuf[bufIndex + 1] == 1) {
        bufIndex += 3;
    }
    /* Get the Modulus*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    if (modlen != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *modlen = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *modlen = taglen;
        *modulus = SSS_MALLOC(*modlen);
        if ((*modulus != NULL) && ((*modlen) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*modulus, pBuf + bufIndex, *modlen);
            bufIndex += *modlen;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Public Exponent */
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    if (pubExplen != NULL) {
        *pubExplen = taglen;
        *pubExp    = SSS_MALLOC(*pubExplen);
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if ((*pubExp != NULL) && ((*pubExplen) > 0)) {
            memcpy(*pubExp, pBuf + bufIndex, *pubExplen);
            bufIndex += *pubExplen;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Private Exponent*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    if (priExplen != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *priExplen = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *priExplen = taglen;
        *priExp = SSS_MALLOC(*priExplen);
        if ((*priExp != NULL) && ((*priExplen) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*priExp, pBuf + bufIndex, *priExplen);
            bufIndex += *priExplen;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get First prime (p)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    if (prime1len != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *prime1len = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *prime1len = taglen;
        *prime1 = SSS_MALLOC(*prime1len);
        if ((*prime1 != NULL) && ((*prime1len) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*prime1, pBuf + bufIndex, *prime1len);
            bufIndex += *prime1len;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Second prime (q)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    if (prime2len != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *prime2len = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *prime2len = taglen;
        *prime2 = SSS_MALLOC(*prime2len);
        if (*prime2 == NULL) {
            LOG_E("malloc failed");
            goto exit;
        }
        if (*prime2len > 0) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*prime2, pBuf + bufIndex, *prime2len);
            bufIndex += *prime2len;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get First exponent (dP)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    if (exponent1len != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *exponent1len = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *exponent1len = taglen;
        *exponent1 = SSS_MALLOC(*exponent1len);
        if ((*exponent1 != NULL) && ((*exponent1len) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*exponent1, pBuf + bufIndex, *exponent1len);
            bufIndex += *exponent1len;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Second  exponent (dQ)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    if (exponent2len != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *exponent2len = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *exponent2len = taglen;
        *exponent2 = SSS_MALLOC(*exponent2len);
        if (*exponent2 == NULL) {
            LOG_E("malloc failed");
            goto exit;
        }
        if (*exponent2len > 0) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*exponent2, pBuf + bufIndex, *exponent2len);
            bufIndex += *exponent2len;
        }
        else {
            LOG_E("exponent2len improper");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    /* Get Coefficient (qinv)*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    ENSURE_OR_GO_EXIT(0 == ret);

    if (coefficientlen != NULL) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        if (pBuf[bufIndex] == 0x00) {
            if (taglen) {
                *coefficientlen = taglen - 1; /*Exclude Starting Null*/
                bufIndex++;
            }
            else {
                goto exit;
            }
        }
        else
            *coefficientlen = taglen;
        *coefficient = SSS_MALLOC(*coefficientlen);
        if ((*coefficient != NULL) && ((*coefficientlen) > 0)) {
            ENSURE_OR_GO_EXIT(bufIndex < keylen);
            memcpy(*coefficient, pBuf + bufIndex, *coefficientlen);
            bufIndex += *coefficientlen;
        }
        else {
            LOG_E("Either malloc failed or improper length");
            goto exit;
        }
    }
    else
        bufIndex += taglen;

    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_util_asn1_rsa_parse_public_nomalloc(
    const uint8_t *key, size_t keylen, uint8_t *modulus, size_t *modlen, uint8_t *pubExp, size_t *pubExplen)
{
    uint8_t *pBuf   = (uint8_t *)key;
    size_t taglen   = 0;
    size_t bufIndex = 0;
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    size_t temp_modlen = 0, temp_pubExplen = 0;

    if ((key == NULL) || (modulus == NULL) || (modlen == NULL) || (pubExp == NULL) || (pubExplen == NULL)) {
        goto exit;
    }

    //int tag = (key[1] == 0x82) ? 4 : 3;
    /* Parse Header Information
    Public Key contains 3 Sequences as header */
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* ASN.1 Sequence */
    if (ret != 0)
        goto exit;
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* Public Header Nested TLV */
    if (ret != 0)
        goto exit;
    bufIndex += taglen;

    /* Bit-String + NULL Byte */
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    bufIndex++;

    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* Sequence of interger*/
    if (ret != 0)
        goto exit;
    /* Get the Modulus*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    if (pBuf[bufIndex] == 0x00) {
        if (taglen) {
            temp_modlen = taglen - 1; /*Exclude Starting Null*/
            bufIndex++;
        }
        else {
            goto exit;
        }
    }
    else
        temp_modlen = taglen;

    if (*modlen < temp_modlen) {
        LOG_E("modulus overflow");
        goto exit;
    }

    *modlen = temp_modlen;
    if ((*modlen) > 0) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        memcpy(modulus, pBuf + bufIndex, *modlen);
        bufIndex += *modlen;
    }
    else {
        LOG_E("Either malloc failed or improper length");
        goto exit;
    }

    /* Get Public Exponent */
    ret            = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    temp_pubExplen = taglen;
    if (*pubExplen < temp_pubExplen) {
        LOG_E("pubExp overflow");
        goto exit;
    }
    *pubExplen = temp_pubExplen;
    if (*pubExplen > 0) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        memcpy(pubExp, pBuf + bufIndex, *pubExplen);
        bufIndex += *pubExplen;
        status = kStatus_SSS_Success;
    }
exit:
    return status;
}

sss_status_t sss_util_asn1_rsa_parse_public_nomalloc_complete_modulus(
    const uint8_t *key, size_t keylen, uint8_t *modulus, size_t *modlen, uint8_t *pubExp, size_t *pubExplen)
{
    uint8_t *pBuf   = (uint8_t *)key;
    size_t taglen   = 0;
    size_t bufIndex = 0;
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    size_t temp_modlen = 0, temp_pubExplen = 0;

    if ((key == NULL) || (modulus == NULL) || (modlen == NULL) || (pubExp == NULL) || (pubExplen == NULL)) {
        goto exit;
    }

    //int tag = (key[1] == 0x82) ? 4 : 3;
    /* Parse Header Information
    Public Key contains 3 Sequences as header */
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* ASN.1 Sequence */
    if (ret != 0)
        goto exit;
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* Public Header Nested TLV */
    if (ret != 0)
        goto exit;
    bufIndex += taglen;

    /* Bit-String + NULL Byte */
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    bufIndex++;

    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* Sequence of interger*/
    if (ret != 0)
        goto exit;
    /* Get the Modulus*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    temp_modlen = taglen;

    if (*modlen < temp_modlen) {
        LOG_E("modulus overflow");
        goto exit;
    }

    *modlen = temp_modlen;
    if ((*modlen) > 0) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        memcpy(modulus, pBuf + bufIndex, *modlen);
        bufIndex += *modlen;
    }
    else {
        LOG_E("Either malloc failed or improper length");
        goto exit;
    }

    /* Get Public Exponent */
    ret            = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    temp_pubExplen = taglen;
    if (*pubExplen < temp_pubExplen) {
        LOG_E("pubExp overflow");
        goto exit;
    }
    *pubExplen = temp_pubExplen;
    if (*pubExplen > 0) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        memcpy(pubExp, pBuf + bufIndex, *pubExplen);
        bufIndex += *pubExplen;
        status = kStatus_SSS_Success;
    }
exit:
    return status;
}

sss_status_t sss_util_asn1_rsa_parse_public(
    const uint8_t *key, size_t keylen, uint8_t **modulus, size_t *modlen, uint8_t **pubExp, size_t *pubExplen)
{
    uint8_t *pBuf   = (uint8_t *)key;
    size_t taglen   = 0;
    size_t bufIndex = 0;
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    //int tag = (key[1] == 0x82) ? 4 : 3;
    /* Parse Header Information
    Public Key contains 3 Sequences as header */
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* ASN.1 Sequence */
    if (ret != 0)
        goto exit;
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* Public Header Nested TLV */
    if (ret != 0)
        goto exit;
    bufIndex += taglen;

    /* Bit-String + NULL Byte */
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    bufIndex++;

    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex); /* Sequence of interger*/
    if (ret != 0)
        goto exit;
    /* Get the Modulus*/
    ret = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    if (ret != 0)
        goto exit;
    ENSURE_OR_GO_EXIT(bufIndex < keylen);
    if (pBuf[bufIndex] == 0x00) {
        if (taglen) {
            *modlen = taglen - 1; /*Exclude Starting Null*/
            bufIndex++;
        }
        else {
            goto exit;
        }
    }
    else
        *modlen = taglen;
    *modulus = SSS_MALLOC(*modlen);
    if ((*modulus != NULL) && ((*modlen) > 0)) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        memcpy(*modulus, pBuf + bufIndex, *modlen);
        bufIndex += *modlen;
    }
    else {
        LOG_E("Either malloc failed or improper length");
        goto exit;
    }

    /* Get Public Exponent */
    ret        = asn_1_parse_tlv(pBuf, &taglen, &bufIndex);
    *pubExplen = taglen;
    *pubExp    = SSS_MALLOC(*pubExplen);
    if (*pubExp == NULL) {
        LOG_E("malloc failed");
        goto exit;
    }
    if (*pubExplen > 0) {
        ENSURE_OR_GO_EXIT(bufIndex < keylen);
        memcpy(*pubExp, pBuf + bufIndex, *pubExplen);
        bufIndex += *pubExplen;
        status = kStatus_SSS_Success;
    }
exit:
    return status;
}

sss_status_t sss_util_asn1_rsa_get_public(
    uint8_t *key, size_t *keylen, uint8_t *modulus, size_t modlen, uint8_t *pubExp, size_t pubExplen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t pbkeylen     = modlen + pubExplen + sizeof(grsa1kPubHeader) + 3 + 3;
    size_t index        = 0;
    size_t intModLEn    = modlen + 1; // RSA Key has null byte before moduls start
    if (*keylen < pbkeylen) {
        LOG_E("Buffer not sufficient");
        goto exit;
    }

    /* Copy the Public Header According to key bit len*/
    if (modlen == 0x40) {
        memcpy(key, grsa512PubHeader, sizeof(grsa512PubHeader));
        index += sizeof(grsa512PubHeader);
    }
    else if (modlen == 0x80) {
        memcpy(key, grsa1kPubHeader, sizeof(grsa1kPubHeader));
        index += sizeof(grsa1kPubHeader);
    }
    else if (modlen == 0x90) {
        memcpy(key, grsa1152PubHeader, sizeof(grsa1152PubHeader));
        index += sizeof(grsa1152PubHeader);
    }
    else if (modlen == 0x100) {
        memcpy(key, grsa2kPubHeader, sizeof(grsa2kPubHeader));
        index += sizeof(grsa2kPubHeader);
    }
    else if (modlen == 0x180) {
        memcpy(key, grsa3kPubHeader, sizeof(grsa3kPubHeader));
        index += sizeof(grsa3kPubHeader);
    }
    else if (modlen == 0x200) {
        memcpy(key, grsa4kPubHeader, sizeof(grsa4kPubHeader));
        index += sizeof(grsa4kPubHeader);
    }

    if (intModLEn < 0x7f)
        key[index++] = (uint8_t)intModLEn;
    else if (intModLEn < 0xFF) {
        key[index++] = 0x81;
        key[index++] = (uint8_t)intModLEn;
    }
    else {
        key[index++] = 0x82;
        key[index++] = (uint8_t)(intModLEn >> 8);
        key[index++] = (uint8_t)intModLEn & 0xFF;
    }

    key[index++] = 0x00; // Null byte
    memcpy(key + index, modulus, modlen);
    index += modlen;

    /*Copy the public Exponent*/
    key[index++] = 0x02;                    // tag
    key[index++] = (uint8_t)pubExplen;      // length
    memcpy(key + index, pubExp, pubExplen); // value
    index += pubExplen;
    *keylen = index;
    status  = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_util_asn1_ecdaa_get_signature(
    uint8_t *signature, size_t *signatureLen, uint8_t *rawSignature, size_t rawSignatureLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t signAsn1Len, r_len, s_len;

    r_len = rawSignatureLen / 2;
    s_len = rawSignatureLen / 2;
    // SEQUENCE (2B) + INTEGER(2B)  + INTEGER(2B)
    signAsn1Len = 6 + rawSignatureLen;
    if (*signatureLen < signAsn1Len) {
        LOG_E("ECDAA Signature buffer overflow");
        goto exit;
    }

    /*
        Example:
        30 44                                ; SEQUENCE (68 Bytes)
            02 20                            ; INTEGER (32 Bytes)
            |  3d 46 28 7b 8c 6e 8c 8c  26 1c 1b 88 f2 73 b0 9a
            |  32 a6 cf 28 09 fd 6e 30  d5 a7 9f 26 37 00 8f 54
            02 20                            ; INTEGER (32 Bytes)
            |  4e 72 23 6e a3 90 a9 a1  7b cf 5f 7a 09 d6 3a b2
            |  17 6c 92 bb 8e 36 c0 41  98 a2 7b 90 9b 6e 8f 13
    */
    *signatureLen = signAsn1Len;
    if (rawSignatureLen == 0x40) {                     // TPM_ECC_BN_P256
        signature[0] = 0x30;                           //SEQUENCE
        signature[1] = (uint8_t)(rawSignatureLen + 4); //INTEGER(2B)  + INTEGER(2B)
        signature[2] = 0x02;                           //INTEGER
        signature[3] = (uint8_t)r_len;                 //lenght of r
        memcpy(&signature[4], &rawSignature[0], r_len);
        signature[3 + r_len + 1] = 0x02;           //INTEGER
        signature[3 + r_len + 2] = (uint8_t)s_len; //lenght of s
        memcpy(&signature[3 + r_len + 3], &rawSignature[r_len], s_len);
    }
    else {
        LOG_E("Invalid ECDAA Signature data");
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

#if 0
static  uint8_t *asn_1_parse_header(uint8_t *key, size_t keylen)
{
    uint8_t *pBuf = key;
    uint16_t taglen = 0;
    sss_status_t status = kStatus_SSS_Fail;
    int tag = (key[1] == 0x82) ? 4 : 3;
    /* Parse Header Information*/
    pBuf = asn_1_parse_tlv(pBuf, &taglen);
    if (taglen != (keylen - tag))
    {
        LOG_E("Invlaid Key");
        return status;
    }
}
#endif

int asn_1_parse_tlv(uint8_t *pbuf, size_t *taglen, size_t *bufindex)
{
    size_t Len;
    uint8_t *buf = pbuf + *bufindex;
    int tag;
    tag     = *buf++; /*Exclude The Tag*/
    Len     = *buf++;
    int ret = 0;
    if (check_tag(tag)) {
        ret = 1;
        goto exit;
    }
    if (Len <= 0x7FU) {
        *taglen = Len;
        *bufindex += 1 + 1;
        goto exit;
    }
    else if (Len == 0x81) {
        *taglen = *buf++;
        *bufindex += 1 + 2;
        goto exit;
    }
    else if (Len == 0x82) {
        *taglen = *buf++;
        *taglen = (*taglen << 8) | (*buf++);
        *bufindex += 1 + 3;
        goto exit;
    }
    ret = 1;
exit:
    return ret;
}

static int check_tag(int tag)
{
    int ret = 0;
    switch (tag) {
    case ASN_TAG_INT:
    case ASN_TAG_SEQUENCE:
    case ASN_TAG_BITSTRING:
    case ASN_TAG_OBJ_IDF:
    case ASN_TAG_OCTETSTRING:
        break;
    default:
        LOG_E("Wrong Tag parsed -- %d \n", tag);
        ret = 1;
        break;
    }
    return ret;
}

#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif

sss_status_t sss_util_asn1_get_oid_from_header(uint8_t *input, size_t inLen, uint32_t *output, uint8_t *outLen)
{
    size_t i            = 0;
    size_t taglen       = 0;
    int objectIdCnt     = 0;
    int tag             = 0;
    uint8_t outBufindex = 0;
    sss_status_t status = kStatus_SSS_Fail;

    for (;;) {
        ENSURE_OR_GO_EXIT(i < inLen);
        tag = input[i++];
        if (tag == ASN_TAG_SEQUENCE || tag == ASN_TAG_OBJ_IDF) {
            ENSURE_OR_GO_EXIT(i < inLen);
            taglen = input[i++];
            if (taglen == 0x81) {
                taglen = input[i];
                i      = i + 1;
            }
            else if (taglen == 0x82) {
                ENSURE_OR_GO_EXIT(i < (inLen - 1));
                taglen = input[i] | input[i + 1] << 8;
                i      = i + 2;
            }

            if (taglen > inLen)
                goto exit;

            if (tag == ASN_TAG_OBJ_IDF)
                objectIdCnt++;

            if (objectIdCnt == 2) {
                if (taglen <= 0)
                    goto exit;
                ENSURE_OR_GO_EXIT(i < inLen);
                ENSURE_OR_GO_EXIT(outBufindex < (*outLen));
                output[outBufindex++] = input[i] / 40;
                output[outBufindex++] = input[i++] % 40;
                taglen--;

                while (taglen--) {
                    uint32_t cnt  = 0;
                    uint32_t temp = 0;
                    do {
                        ENSURE_OR_GO_EXIT(i < inLen);
                        temp = temp << (7 * cnt);
                        temp = temp | (input[i] & 0x7F);
                        cnt++;
                    } while (input[i++] > 0x7F);

                    taglen = taglen - (cnt - 1);
                    ENSURE_OR_GO_EXIT(outBufindex < (*outLen));
                    output[outBufindex++] = temp;
                }
                break;
            }
            else {
                if (tag == 0x06) {
                    i = i + taglen;
                    if (i > inLen)
                        goto exit;
                }
            }
        }
        else {
            goto exit;
        }
    }

    *outLen = outBufindex;
    status  = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_util_asn1_get_oid_from_sssObj(sss_object_t *pkeyObject, uint32_t *output, uint8_t *outLen)
{
    sss_status_t status  = kStatus_SSS_Fail;
    uint8_t pbKey[256]   = {0};
    size_t pbKeyBitLen   = 0;
    size_t pbKeyBytetLen = sizeof(pbKey);

    status = sss_key_store_get_key(pkeyObject->keyStore, pkeyObject, pbKey, &pbKeyBytetLen, &pbKeyBitLen);

    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_util_asn1_get_oid_from_header(pbKey, pbKeyBytetLen, output, outLen);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_util_pkcs8_asn1_get_ec_public_key_index(
    const uint8_t *input, size_t inLen, uint16_t *outkeyIndex, size_t *publicKeyLen)
{
    size_t i            = 0;
    size_t taglen       = 0;
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t value_index = 0;

    for (;;) {
        ENSURE_OR_GO_EXIT(i < inLen);
        int tag = input[i++];
        if (IS_VALID_TAG(tag)) {
            ENSURE_OR_GO_EXIT(i < inLen);
            taglen = input[i++];
            if (taglen == 0x81) {
                ENSURE_OR_GO_EXIT(i < inLen);
                taglen = input[i];
                i      = i + 1;
            }
            else if (taglen == 0x82) {
                ENSURE_OR_GO_EXIT(i < (inLen - 1));
                taglen = input[i] | input[i + 1] << 8;
                i      = i + 2;
            }

            if (taglen > inLen)
                goto exit;

            value_index = (uint8_t)i;

            if (tag == ASN_TAG_SEQUENCE) {
                if (i + taglen != inLen) {
                    i = i + taglen;
                }

                continue;
            }

            if (tag == ASN_TAG_BITSTRING) {
                *outkeyIndex  = value_index;
                *publicKeyLen = taglen;
                ENSURE_OR_GO_EXIT(value_index < inLen);
                if (input[value_index] == 0x00 || input[value_index] == 0x01) {
                    *outkeyIndex  = *outkeyIndex + 1;
                    *publicKeyLen = *publicKeyLen - 1;
                }
                break;
            }
        }
        else {
            goto exit;
        }
    }

    ENSURE_OR_GO_EXIT((*outkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT(((*outkeyIndex) + (*publicKeyLen)) <= inLen);
    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_util_pkcs8_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint16_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint16_t *prvkeyIndex,
    size_t *privateKeyLen)
{
    size_t i            = 0;
    size_t taglen       = 0;
    sss_status_t status = kStatus_SSS_Fail;
    //uint8_t octate_string_start = 0;

    for (;;) {
        ENSURE_OR_GO_EXIT(i < inLen);
        int tag = input[i++];
        if (IS_VALID_TAG(tag)) {
            ENSURE_OR_GO_EXIT(i < inLen);
            taglen = input[i++];
            if (taglen == 0x81) {
                ENSURE_OR_GO_EXIT(i < inLen);
                taglen = input[i];
                i      = i + 1;
            }
            else if (taglen == 0x82) {
                ENSURE_OR_GO_EXIT(i < (inLen - 1));
                taglen = input[i] | input[i + 1] << 8;
                i      = i + 2;
            }

            if (taglen > inLen)
                goto exit;

            if (tag == ASN_TAG_OCTETSTRING) {
                if (i + taglen == inLen) {
                    continue;
                }
                else {
                    *prvkeyIndex   = (uint16_t)i;
                    *privateKeyLen = taglen;
                }
            }

            if (tag == ASN_TAG_BITSTRING) {
                *pubkeyIndex  = (uint16_t)i;
                *publicKeyLen = taglen;
                ENSURE_OR_GO_EXIT(i < inLen);
                if (input[i] == 0x00 || input[i] == 0x01) {
                    *pubkeyIndex  = *pubkeyIndex + 1;
                    *publicKeyLen = *publicKeyLen - 1;
                }
                break;
            }

            if (i + taglen == inLen) {
                continue;
            }
            else {
                i = i + taglen;
            }
        }
        else {
            goto exit;
        }
    }

    ENSURE_OR_GO_EXIT((*pubkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT(((*pubkeyIndex) + (*publicKeyLen)) <= inLen);
    ENSURE_OR_GO_EXIT((*prvkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT(((*prvkeyIndex) + (*privateKeyLen)) <= inLen);
    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_util_rfc8410_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint16_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint16_t *prvkeyIndex,
    size_t *privateKeyLen)
{
    size_t i            = 0;
    size_t taglen       = 0;
    sss_status_t status = kStatus_SSS_Fail;
    //uint8_t octate_string_start = 0;

    for (;;) {
        ENSURE_OR_GO_EXIT(i < inLen);
        int tag = input[i++];
        if (IS_VALID_RFC8410_TAG(tag)) {
            ENSURE_OR_GO_EXIT(i < inLen);
            taglen = input[i++];
            if (taglen == 0x81) {
                ENSURE_OR_GO_EXIT(i < inLen);
                taglen = input[i];
                i      = i + 1;
            }
            else if (taglen == 0x82) {
                ENSURE_OR_GO_EXIT(i < (inLen - 1));
                taglen = input[i] | input[i + 1] << 8;
                i      = i + 2;
            }

            if (taglen > inLen)
                goto exit;

            if (tag == ASN_TAG_OCTETSTRING) {
                // With RFC8410, the private key is an Octet String packed inside an Octet String
                // Following code will only work for Lengths upto 127 byte
                ENSURE_OR_GO_EXIT(taglen >= 2);
                ENSURE_OR_GO_EXIT(ASN_TAG_OCTETSTRING == input[i]);
                ENSURE_OR_GO_EXIT(taglen - 2 == (size_t)(input[i + 1]));
                i += 2;
                taglen -= 2;
                *prvkeyIndex   = (uint16_t)i;
                *privateKeyLen = taglen;
            }

            if (tag == (ASN_TAG_CNT_SPECIFIC_PRIMITIVE | 0x01)) {
                *pubkeyIndex  = (uint16_t)i;
                *publicKeyLen = taglen;
                ENSURE_OR_GO_EXIT(i < inLen);
                if (input[i] == 0x00 || input[i] == 0x01) {
                    *pubkeyIndex  = *pubkeyIndex + 1;
                    *publicKeyLen = *publicKeyLen - 1;
                }
                break;
            }

            if (i + taglen == inLen) {
                continue;
            }
            else {
                i = i + taglen;
            }
        }
        else {
            goto exit;
        }
    }

    ENSURE_OR_GO_EXIT((*pubkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT(((*pubkeyIndex) + (*publicKeyLen)) <= inLen);
    ENSURE_OR_GO_EXIT((*prvkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT(((*prvkeyIndex) + (*privateKeyLen)) <= inLen);
    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_util_openssl_read_pkcs12(
    const char *pkcs12_cert, const char *password, uint8_t *private_key, uint8_t *cert)
{
    sss_status_t retval = kStatus_SSS_Success;

#if SSS_HAVE_OPENSSL
    int status = 0;
    FILE *pkcs12_cert_file;
    PKCS12 *p12_cert;
    X509 *x509_cert;
    EVP_PKEY *p_key;
    BIO *pem_key_bio                 = BIO_new(BIO_s_mem());
    BIO *cert_bio                    = BIO_new(BIO_s_mem());
    STACK_OF(X509) *additional_certs = NULL;

    // Open PKCS12 certificate file
    pkcs12_cert_file = fopen(pkcs12_cert, "rb");
    if (pkcs12_cert_file == NULL) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }
    p12_cert = d2i_PKCS12_fp(pkcs12_cert_file, NULL);
    fclose(pkcs12_cert_file);

    // Parse PKCS12 key and certificates to seperate pem and certificates
    status = PKCS12_parse(p12_cert, password, &p_key, &x509_cert, &additional_certs);
    if (!status) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }
    PKCS12_free(p12_cert);

    // Dump pem key to buffer
    PEM_write_bio_PrivateKey(pem_key_bio, p_key, NULL, NULL, 0, NULL, NULL);
    BIO_read(pem_key_bio, private_key, 10000);

    // Dump certificate to buffer
    PEM_write_bio_X509(cert_bio, x509_cert);
    BIO_read(cert_bio, cert, 20000);

exit:
#endif
    return retval;
}

sss_status_t sss_util_openssl_write_pkcs12(sss_session_t *session,
    sss_key_store_t *ks,
    sss_object_t *obj,
    const char *pkcs12_cert,
    const char *password,
    const char *ref_key,
    long ref_key_length,
    const char *cert_bytes,
    const char *cert_subject)
{
    sss_status_t retval = kStatus_SSS_Success;

#if SSS_HAVE_OPENSSL
    FILE *pkcs12_file;
    X509 *x509_cert = X509_new();
    EVP_PKEY *p_key = 0;
    PKCS12 *p12;
    BIO *pem_key_bio = BIO_new(BIO_s_mem());

    // Parse Private key
    BIO_write(pem_key_bio, ref_key, ref_key_length);
    PEM_read_bio_PrivateKey(pem_key_bio, &p_key, NULL, NULL);
    if (p_key == NULL) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    //Generate certificate
    retval = sss_util_openssl_generate_cert_pkcs12(session, ks, obj, x509_cert, cert_bytes, cert_subject);
    if (retval != kStatus_SSS_Success || x509_cert == NULL) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    // Generate PKCS12 key and certificate
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    p12 = PKCS12_create((char *)password,
#else
    p12 = PKCS12_create(password,
#endif
        NULL,
        p_key,
        x509_cert,
        NULL,
        0,
        0,
        PKCS12_DEFAULT_ITER,
        1,
        NID_key_usage);
    if (p12 == NULL) {
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    //write into file
    pkcs12_file = fopen(pkcs12_cert, "wb");
    if (i2d_PKCS12_fp(pkcs12_file, p12) != 1) {
        retval = kStatus_SSS_Fail;
    }

    fclose(pkcs12_file);
exit:
#endif

    return retval;
}

sss_status_t sss_util_openssl_generate_cert_pkcs12(sss_session_t *session,
    sss_key_store_t *ks,
    sss_object_t *obj,
    void *certificate_in,
    const char *cert_bytes,
    const char *cert_subject)
{
    sss_status_t status = kStatus_SSS_Fail;

#if SSS_HAVE_OPENSSL
    X509 *certificate = (X509 *)certificate_in;
    if (!X509_set_version(certificate, 2)) {
        return status;
    }

    ASN1_INTEGER *serialNumber = ASN1_INTEGER_new();
    if (!ASN1_INTEGER_set(serialNumber, 1) || !X509_set_serialNumber(certificate, serialNumber)) {
        return status;
    }

    X509_NAME *subjectName = X509_NAME_new();
    if (!X509_NAME_add_entry_by_txt(subjectName,
            "CN",
            MBSTRING_ASC,
            (const unsigned char *)cert_bytes,
            -1 /* len */,
            -1 /* loc */,
            0 /* set */) ||
        !X509_set_subject_name(certificate, subjectName)) {
        return status;
    }

    if (!X509_set_issuer_name(certificate, subjectName)) {
        return status;
    }

    ASN1_TIME *notBefore  = ASN1_TIME_new();
    time_t activeDateTime = time(NULL);
    if (!ASN1_TIME_set(notBefore, activeDateTime) || !X509_set_notBefore(certificate, notBefore)) {
        return status;
    }

    ASN1_TIME *notAfter = ASN1_TIME_new();
    time_t notAfterTime = time(NULL);
    if (!ASN1_TIME_set(notAfter, notAfterTime * 2) || !X509_set_notAfter(certificate, notAfter)) {
        return status;
    }

    /*Get public key*/
    uint8_t key[1024];
    size_t keybytelen = sizeof(key);
    size_t keybitlen  = keybytelen * 8;
    status            = sss_key_store_get_key(ks, obj, key, &keybytelen, &keybitlen);
    LOG_I("sss_key_store_get_key status %x", status);
    if (status != kStatus_SSS_Success)
        return status;

    status   = kStatus_SSS_Fail;
    BIO *bio = BIO_new_mem_buf(key, (int)sizeof(key));
    if (bio == NULL) {
        return status;
    }

    EVP_PKEY *pKey = d2i_PUBKEY_bio(bio, NULL);
    if (pKey == NULL) {
        return status;
    }
    /*Add public key*/

    if (!X509_set_pubkey(certificate, pKey)) {
        return status;
    }

    X509V3_CTX x509v3_ctx = {0};

    char *basicConstraints        = "CA:TRUE";
    X509_EXTENSION *extension_SAN = X509V3_EXT_nconf_nid(NULL, &x509v3_ctx, NID_subject_alt_name, (char *)cert_subject);
    if (!X509_add_ext(certificate, extension_SAN, -1)) {
        return status;
    }
    X509_EXTENSION *extension_BasicConstraints =
        X509V3_EXT_nconf_nid(NULL, &x509v3_ctx, NID_basic_constraints, basicConstraints);
    if (!X509_add_ext(certificate, extension_BasicConstraints, -1)) {
        return status;
    }

    int type = NID_ecdsa_with_SHA256;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    X509_ALGOR *tbs_algo = certificate->cert_info->signature;
    X509_ALGOR *algo     = certificate->sig_alg;
    X509_ALGOR_set0(algo, OBJ_nid2obj(type), V_ASN1_NULL, NULL);
#else

    X509_ALGOR *tbs_algo = (X509_ALGOR *)X509_get0_tbs_sigalg(certificate);
#endif
    X509_ALGOR_set0(tbs_algo, OBJ_nid2obj(type), V_ASN1_NULL, NULL);

    /*Convert to DER format to sign*/
    int len = 0;

    uint8_t tbs_bytes[1024];
    uint8_t *p_tbs_bytes = &tbs_bytes[0];

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    X509_CINF *cinf = certificate->cert_info;
    len             = i2d_X509_CINF(cinf, &p_tbs_bytes);
#else
    len                  = i2d_re_X509_tbs(certificate, &p_tbs_bytes);
    LOG_I("len = %d", len);
#endif

    /*Calculate digest for signing*/
    uint8_t digest[32] = {0};
    size_t digestLen   = sizeof(digest);
    sss_digest_t digestCtx;
    status = sss_digest_context_init(&digestCtx, session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    status = sss_digest_one_go(&digestCtx, &tbs_bytes[0], len, digest, &digestLen);
    sss_digest_context_free(&digestCtx);
    if (status != kStatus_SSS_Success)
        return status;

    status = kStatus_SSS_Fail;
    /*Sign digest*/
    sss_asymmetric_t asymmCtx;
    uint8_t signature[512];
    uint8_t *p_signature      = &signature[0];
    size_t signatureLen       = sizeof(signature);
    sss_algorithm_t hash_algo = kAlgorithm_SSS_SHA256;
    if (obj->cipherType == kSSS_CipherType_RSA || obj->cipherType == kSSS_CipherType_RSA_CRT)
        hash_algo = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256;
    status = sss_asymmetric_context_init(&asymmCtx, session, obj, hash_algo, kMode_SSS_Sign);
    status = sss_asymmetric_sign_digest(&asymmCtx, digest, digestLen, signature, &signatureLen);
    if (status != kStatus_SSS_Success)
        return status;

        /*Add signature to certificate structure*/
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ASN1_BIT_STRING *sig = certificate->signature;
#else
    ASN1_BIT_STRING *sig;
    X509_ALGOR *algo;
    X509_get0_signature((const ASN1_BIT_STRING **)&sig, (const X509_ALGOR **)&algo, certificate);
    X509_ALGOR_set0(algo, OBJ_nid2obj(type), V_ASN1_NULL, NULL);
#endif
    len = ASN1_BIT_STRING_set(sig, p_signature, (int)signatureLen);
#endif

    return status;
}
