/*
*  The RSA public-key cryptosystem
*
*  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
*  Copyright 2019,2020 NXP, All Rights Reserved
*  SPDX-License-Identifier: Apache-2.0
*
*  Licensed under the Apache License, Version 2.0 (the "License"); you may
*  not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*  This file is part of mbed TLS (https://tls.mbed.org)
*/

/*
*  The following sources were referenced in the design of this implementation
*  of the RSA algorithm:
*
*  [1] A method for obtaining digital signatures and public-key cryptosystems
*      R Rivest, A Shamir, and L Adleman
*      http://people.csail.mit.edu/rivest/pubs.html#RSA78
*
*  [2] Handbook of Applied Cryptography - 1997, Chapter 8
*      Menezes, van Oorschot and Vanstone
*
*  [3] Malware Guard Extension: Using SGX to Conceal Cache Attacks
*      Michael Schwarz, Samuel Weiser, Daniel Gruss, Clementine Maurice and
*      Stefan Mangard
*      https://arxiv.org/abs/1702.08719v2
*
*/

#include <fsl_sss_se05x_apis.h>
#include <nxLog_sss.h>
#include <stdlib.h>
#include <string.h>

#if SSS_HAVE_APPLET_SE05X_IOT && SSSFTR_RSA

#include "se05x_APDU.h"

uint8_t pkcs1_v15_encode(
    sss_se05x_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen)
{
    size_t oid_size  = 0;
    size_t nb_pad    = 0;
    unsigned char *p = out;
    /* clang-format off */
    char oid1[16] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, };
    /* clang-format on */
    size_t outlength        = 0;
    uint16_t key_size_bytes = 0;
    smStatus_t ret_val      = SM_NOT_OK;

    /* Constants */
    const uint8_t RSA_Sign          = 0x01;
    const uint8_t ASN1_sequence     = 0x10;
    const uint8_t ASN1_constructed  = 0x20;
    const uint8_t ASN1_oid          = 0x06;
    const uint8_t ASN1_null         = 0x05;
    const uint8_t ASN1_octat_string = 0x04;

    ret_val = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &key_size_bytes);
    if (ret_val != SM_OK) {
        return 1;
    }

    outlength = key_size_bytes;
    nb_pad    = outlength;

    switch (context->algorithm) {
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1:
        oid1[0]  = 0x2b;
        oid1[1]  = 0x0e;
        oid1[2]  = 0x03;
        oid1[3]  = 0x02;
        oid1[4]  = 0x1a;
        oid_size = 5;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224:
        oid1[8]  = 0x04;
        oid_size = 9;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256:
        oid1[8]  = 0x01;
        oid_size = 9;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384:
        oid1[8]  = 0x02;
        oid_size = 9;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512:
        oid1[8]  = 0x03;
        oid_size = 9;
        break;
    default:
        return 1;
    }

    if (outlength < (hashlen + oid_size + 6 /* DigestInfo TLV overhead */)) {
        LOG_E("Intended encoded message length too short");
        return 1;
    }

    if (*outLen < outlength) {
        LOG_E("Out buffer memory is less ");
        return 1;
    }
    *outLen = outlength;

    /* Double-check that 8 + hashlen + oid_size can be used as a
        * 1-byte ASN.1 length encoding and that there's no overflow. */
    if (8 + hashlen + oid_size >= 0x80)
        return 1;

    /*
        * Static bounds check:
        * - Need 10 bytes for five tag-length pairs.
        *   (Insist on 1-byte length encodings to protect against variants of
        *    Bleichenbacher's forgery attack against lax PKCS#1v1.5 verification)
        * - Need hashlen bytes for hash
        * - Need oid_size bytes for hash alg OID.
        */
    if (nb_pad < 10 + hashlen + oid_size)
        return 1;
    nb_pad -= 10 + hashlen + oid_size;

    /* Need space for signature header and padding delimiter (3 bytes),
        * and 8 bytes for the minimal padding */
    if (nb_pad < 3 + 8)
        return 1;
    nb_pad -= 3;

    /* Now nb_pad is the amount of memory to be filled
        * with padding, and at least 8 bytes long. */

    /* Write signature header and padding */
    *p++ = 0;
    *p++ = RSA_Sign;
    memset(p, 0xFF, nb_pad);
    p += nb_pad;
    *p++ = 0;

    /* Signing hashed data, add corresponding ASN.1 structure
        *
        * DigestInfo ::= SEQUENCE {
        *   digestAlgorithm DigestAlgorithmIdentifier,
        *   digest Digest }
        * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
        * Digest ::= OCTET STRING
        *
        * Schematic:
        * TAG-SEQ + LEN [ TAG-SEQ + LEN [ TAG-OID  + LEN [ OID  ]
        *                                 TAG-NULL + LEN [ NULL ] ]
        *                 TAG-OCTET + LEN [ HASH ] ]
        */
    *p++ = ASN1_sequence | ASN1_constructed;
    *p++ = (unsigned char)(0x08 + oid_size + hashlen);
    *p++ = ASN1_sequence | ASN1_constructed;
    *p++ = (unsigned char)(0x04 + oid_size);
    *p++ = ASN1_oid;
    *p++ = (unsigned char)oid_size;
    memcpy(p, oid1, oid_size);
    p += oid_size;
    *p++ = ASN1_null;
    *p++ = 0x00;
    *p++ = ASN1_octat_string;
    *p++ = (unsigned char)hashlen;
    memcpy(p, hash, hashlen);
    p += hashlen;

    /* Just a sanity-check, should be automatic
    * after the initial bounds check. */
    if (p != out + outlength) {
        memset(out, 0, outlength);
        return 1;
    }

    return 0;
}

uint8_t pkcs1_v15_encode_no_hash(
    sss_se05x_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen)
{
    uint16_t key_size_bytes = 0;
    smStatus_t ret_val      = SM_NOT_OK;

    ret_val = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &key_size_bytes);
    if (ret_val != SM_OK) {
        return 1;
    }

    if (hashlen > (size_t)(key_size_bytes - 11)) {
        return 1;
    }

    if (*outLen < key_size_bytes) {
        return 1;
    }

    memset(out, 0xFF, *outLen);
    out[0]                            = 0x00;
    out[1]                            = 0x01;
    out[key_size_bytes - hashlen - 1] = 0x00;
    memcpy(&out[key_size_bytes - hashlen], hash, hashlen);

    *outLen = key_size_bytes;

    return 0;
}

uint8_t sss_mgf_mask_func(uint8_t *dst,
    size_t dlen,
    uint8_t *src,
    size_t slen,
    sss_algorithm_t sha_algorithm,
    sss_se05x_asymmetric_t *context)
{
    uint8_t mask[64]; /* MAX - SHA512*/
    uint8_t counter[4];
    uint8_t *p;
    size_t i, use_len;
    uint8_t ret         = 1;
    sss_status_t status = kStatus_SSS_Fail;
    sss_digest_t digest;
    size_t digestLen  = 512; /* MAX - SHA512*/
    size_t hashlength = slen;

    memset(mask, 0, 64);
    memset(counter, 0, 4);

    status = sss_digest_context_init(&digest, (sss_session_t *)context->session, sha_algorithm, kMode_SSS_Digest);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    /* Generate and apply dbMask */
    p = dst;

    while (dlen > 0) {
        use_len = hashlength;
        if (dlen < hashlength)
            use_len = dlen;

        status = sss_digest_init(&digest);
        if (status != kStatus_SSS_Success) {
            goto exit;
        }

        status = sss_digest_update(&digest, src, slen);
        if (status != kStatus_SSS_Success) {
            goto exit;
        }

        status = sss_digest_update(&digest, counter, 4);
        if (status != kStatus_SSS_Success) {
            goto exit;
        }

        status = sss_digest_finish(&digest, mask, &digestLen);
        if (status != kStatus_SSS_Success) {
            goto exit;
        }

        for (i = 0; i < use_len; ++i)
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }

    sss_digest_context_free(&digest);

    ret = 0;

exit:
    return ret;
}

// Note-1: This function does not implement the full EMSA-PSS Encoding Operation operation
//         (refer to RFC 8017 Section 9.1 Figure 2), the caller MUST pass 'mHash' (= Hash(M)) as input
//         via function argument(s) hash / haslen.
//
// Note-2: Any hash value passed as input that does not match (in byte length)
//         the hash requested for the signature (kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHAxxx)
//         will be rejected.
//
uint8_t emsa_encode(sss_se05x_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen)
{
    size_t outlength = 0;
    uint8_t *p       = out;
    uint8_t salt[64] = {
        0,
    };
    uint32_t saltlength = 0;
    uint32_t hashlength = 0;
    uint32_t offset     = 0;
    uint8_t ret         = 1;
    size_t msb;
    sss_rng_context_t rng;
    sss_digest_t digest;
    sss_algorithm_t sha_algorithm = -1;
    size_t digestLen              = 512; /* MAX - SHA512*/
    sss_status_t status           = kStatus_SSS_Fail;
    uint16_t key_size_bytes       = 0;
    smStatus_t ret_val            = SM_NOT_OK;

    ret_val = Se05x_API_ReadSize(&context->session->s_ctx, context->keyObject->keyId, &key_size_bytes);
    if (ret_val != SM_OK) {
        goto exit;
    }

    outlength = key_size_bytes;

    switch (context->algorithm) {
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1:
        hashlength    = 20;
        sha_algorithm = kAlgorithm_SSS_SHA1;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224:
        hashlength    = 28;
        sha_algorithm = kAlgorithm_SSS_SHA224;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256:
        if (key_size_bytes <= 64) { /* RSA Key size = 512 */
            LOG_E("SHA256 not supported with this RSA key");
            goto exit;
        }
        hashlength    = 32;
        sha_algorithm = kAlgorithm_SSS_SHA256;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384:
        if (key_size_bytes <= 64) { /* RSA Key size = 512 */
            LOG_E("SHA384 not supported with this RSA key");
            goto exit;
        }
        hashlength    = 48;
        sha_algorithm = kAlgorithm_SSS_SHA384;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512:
        if (key_size_bytes <= 128) { /* RSA Key size = 1024 and 512 */
            LOG_E("SHA512 not supported with this RSA key");
            goto exit;
        }
        hashlength    = 64;
        sha_algorithm = kAlgorithm_SSS_SHA512;
        break;
    default:
        goto exit;
    }

    if (hashlength != hashlen) {
        ret_val = SM_NOT_OK;
        goto exit;
    }

    saltlength = hashlength;
    *outLen    = outlength;

    /* Generate salt of length saltlength */
    status = sss_rng_context_init(&rng, (sss_session_t *)context->session /* session */);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_rng_get_random(&rng, salt, saltlength);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    msb = (outlength * 8) - 1;
    p += outlength - hashlength * 2 - 2;
    *p++ = 0x01;
    memcpy(p, salt, saltlength);
    p += saltlength;

    status = sss_digest_context_init(&digest, (sss_session_t *)context->session, sha_algorithm, kMode_SSS_Digest);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_init(&digest);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_update(&digest, p, 8);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_update(&digest, hash, hashlen);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_update(&digest, salt, saltlength);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_finish(&digest, p, &digestLen);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    sss_digest_context_free(&digest);

    if (msb % 8 == 0)
        offset = 1;

    /* Apply MGF Mask */
    if (0 !=
        sss_mgf_mask_func(out + offset, outlength - hashlength - 1 - offset, p, hashlength, sha_algorithm, context))
        goto exit;

    out[0] &= 0xFF >> (outlength * 8 - msb);

    p += hashlength;
    *p++ = 0xBC;

    ret = 0;

exit:
    return ret;
}

uint8_t emsa_decode_and_compare(
    sss_se05x_asymmetric_t *context, uint8_t *sig, size_t siglen, uint8_t *hash, size_t hashlen)
{
    uint8_t *p;
    uint8_t *hash_start;
    uint8_t result[512];
    uint8_t ret = 1;
    uint32_t hlen;
    uint8_t zeros[8];
    uint32_t observed_salt_len, msb;
    uint8_t buf[1024];
    sss_algorithm_t sha_algorithm = -1;
    sss_digest_t digest;
    size_t digestLen    = 512; /* MAX - SHA512*/
    sss_status_t status = kStatus_SSS_Fail;

    memcpy(buf, sig, siglen);

    switch (context->algorithm) {
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1:
        hlen          = 20;
        sha_algorithm = kAlgorithm_SSS_SHA1;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224:
        hlen          = 28;
        sha_algorithm = kAlgorithm_SSS_SHA224;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256:
        hlen          = 32;
        sha_algorithm = kAlgorithm_SSS_SHA256;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384:
        hlen          = 48;
        sha_algorithm = kAlgorithm_SSS_SHA384;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512:
        hlen          = 64;
        sha_algorithm = kAlgorithm_SSS_SHA512;
        break;
    default:
        goto exit;
    }

    p = buf;

    if (buf[siglen - 1] != 0xBC) {
        goto exit;
    }

    memset(zeros, 0, 8);

    msb = (hlen * 8) - 1;

    if (buf[0] >> (8 - siglen * 8 + msb))
        goto exit;

    if (siglen < hlen + 2)
        goto exit;
    hash_start = p + siglen - hlen - 1;

    if (0 != sss_mgf_mask_func(p, siglen - hlen - 1, hash_start, hlen, sha_algorithm, context))
        goto exit;

    buf[0] &= 0xFF >> ((siglen * 8 - msb) % 8);

    while (p < hash_start - 1 && *p == 0)
        p++;

    if (*p++ != 0x01) {
        goto exit;
    }

    observed_salt_len = hash_start - p;

    status = sss_digest_context_init(&digest, (sss_session_t *)context->session, sha_algorithm, kMode_SSS_Digest);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_init(&digest);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_update(&digest, zeros, 8);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_update(&digest, hash, hashlen);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_update(&digest, p, observed_salt_len);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = sss_digest_finish(&digest, result, &digestLen);
    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    sss_digest_context_free(&digest);

    if (memcmp(hash_start, result, hlen) != 0) {
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

#endif
