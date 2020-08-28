/*
* Copyright 2018-2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef FSL_SSS_UTIL_ASN1_DER_H
#define FSL_SSS_UTIL_ASN1_DER_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <fsl_sss_api.h>

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */
#define ASN_TAG_INT 0x02
#define ASN_TAG_SEQUENCE 0x30
#define ASN_TAG_BITSTRING 0x03
#define ASN_TAG_OCTETSTRING 0x04
#define ASN_TAG_OBJ_IDF 0x06
#define ASN_TAG_CNT_SPECIFIC 0xA1
#define ASN_TAG_CNT_SPECIFIC_PRIMITIVE 0x80
#define ASN_TAG_CRL_EXTENSIONS 0xA0

extern const uint8_t grsa1kPubHeader[];
extern const uint8_t grsa1152PubHeader[];
extern const uint8_t grsa2kPubHeader[];
extern const uint8_t grsa3kPubHeader[];
extern const uint8_t grsa4kPubHeader[];
extern const uint8_t gecc_der_header_nist192[];
extern const uint8_t gecc_der_header_nist224[];
extern const uint8_t gecc_der_header_nist256[];
extern const uint8_t gecc_der_header_nist384[];
extern const uint8_t gecc_der_header_nist521[];
extern const uint8_t gecc_der_header_160k[];
extern const uint8_t gecc_der_header_192k[];
extern const uint8_t gecc_der_header_224k[];
extern const uint8_t gecc_der_header_256k[];
extern const uint8_t gecc_der_header_bp160[];
extern const uint8_t gecc_der_header_bp192[];
extern const uint8_t gecc_der_header_bp224[];
extern const uint8_t gecc_der_header_bp256[];
extern const uint8_t gecc_der_header_bp320[];
extern const uint8_t gecc_der_header_bp384[];
extern const uint8_t gecc_der_header_bp512[];
extern const uint8_t gecc_der_header_mont_dh_448[];
extern const uint8_t gecc_der_header_mont_dh_25519[];
extern const uint8_t gecc_der_header_twisted_ed_25519[];

extern const size_t der_ecc_nistp192_header_len;
extern const size_t der_ecc_nistp224_header_len;
extern const size_t der_ecc_nistp256_header_len;
extern const size_t der_ecc_nistp384_header_len;
extern const size_t der_ecc_nistp521_header_len;
extern const size_t der_ecc_160k_header_len;
extern const size_t der_ecc_192k_header_len;
extern const size_t der_ecc_224k_header_len;
extern const size_t der_ecc_256k_header_len;
extern const size_t der_ecc_bp160_header_len;
extern const size_t der_ecc_bp192_header_len;
extern const size_t der_ecc_bp224_header_len;
extern const size_t der_ecc_bp256_header_len;
extern const size_t der_ecc_bp320_header_len;
extern const size_t der_ecc_bp384_header_len;
extern const size_t der_ecc_bp512_header_len;
extern const size_t der_ecc_mont_dh_448_header_len;
extern const size_t der_ecc_mont_dh_25519_header_len;
extern const size_t der_ecc_twisted_ed_25519_header_len;

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */
/**/
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
    size_t *coefficientlen);

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
    size_t *coefficientlen);

sss_status_t sss_util_asn1_rsa_parse_public_nomalloc(
    const uint8_t *key, size_t keylen, uint8_t *modulus, size_t *modlen, uint8_t *pubExp, size_t *pubExplen);

sss_status_t sss_util_asn1_rsa_parse_public_nomalloc_complete_modulus(
    const uint8_t *key, size_t keylen, uint8_t *modulus, size_t *modlen, uint8_t *pubExp, size_t *pubExplen);

sss_status_t sss_util_asn1_rsa_parse_public(
    const uint8_t *key, size_t keylen, uint8_t **modulus, size_t *modlen, uint8_t **pubExp, size_t *pubExplen);

sss_status_t sss_util_asn1_rsa_get_public(
    uint8_t *key, size_t *keylen, uint8_t *modulus, size_t modlen, uint8_t *pubExp, size_t pubExplen);

sss_status_t sss_util_asn1_ecdaa_get_signature(
    uint8_t *signature, size_t *signatureLen, uint8_t *rawSignature, size_t rawSignatureLen);

sss_status_t sss_util_asn1_get_oid_from_header(uint8_t *input, size_t inLen, uint32_t *output, uint8_t *outLen);

sss_status_t sss_util_asn1_get_oid_from_sssObj(sss_object_t *pkeyObject, uint32_t *output, uint8_t *outLen);

sss_status_t sss_util_pkcs8_asn1_get_ec_public_key_index(
    const uint8_t *input, size_t inLen, uint16_t *outkeyIndex, size_t *publicKeyLen);

sss_status_t sss_util_pkcs8_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint16_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint16_t *prvkeyIndex,
    size_t *privateKeyLen);

sss_status_t sss_util_rfc8410_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint16_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint16_t *prvkeyIndex,
    size_t *privateKeyLen);

int asn_1_parse_tlv(uint8_t *pbuf, size_t *taglen, size_t *bufindex);

sss_status_t sss_util_asn1_rsa_parse_public_nomalloc(
    const uint8_t *key, size_t keylen, uint8_t *modulus, size_t *modlen, uint8_t *pubExp, size_t *pubExplen);

sss_status_t sss_util_asn1_rsa_parse_public_nomalloc_complete_modulus(
    const uint8_t *key, size_t keylen, uint8_t *modulus, size_t *modlen, uint8_t *pubExp, size_t *pubExplen);

sss_status_t sss_util_openssl_read_pkcs12(
    const char *pkcs12_cert, const char *password, uint8_t *private_key, uint8_t *cert);

sss_status_t sss_util_openssl_write_pkcs12(sss_session_t *session,
    sss_key_store_t *ks,
    sss_object_t *obj,
    const char *pkcs12_cert,
    const char *password,
    const char *ref_key,
    long ref_key_length,
    const char *cert_bytes,
    const char *cert_subject);

sss_status_t sss_util_openssl_generate_cert_pkcs12(sss_session_t *session,
    sss_key_store_t *ks,
    sss_object_t *obj,
    void *certificate_in,
    const char *cert_bytes,
    const char *cert_subject);

#endif
