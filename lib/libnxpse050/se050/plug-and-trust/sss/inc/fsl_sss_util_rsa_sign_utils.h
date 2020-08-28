/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FSL_SSS_UTIL_RSA_SIGN_H
#define FSL_SSS_UTIL_RSA_SIGN_H

uint8_t pkcs1_v15_encode(
    sss_se05x_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen);

uint8_t pkcs1_v15_encode_no_hash(
    sss_se05x_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen);

uint8_t sss_mgf_mask_func(uint8_t *dst,
    size_t dlen,
    uint8_t *src,
    size_t slen,
    sss_algorithm_t sha_algorithm,
    sss_se05x_asymmetric_t *context);

uint8_t emsa_encode(sss_se05x_asymmetric_t *context, const uint8_t *hash, size_t hashlen, uint8_t *out, size_t *outLen);

uint8_t emsa_decode_and_compare(
    sss_se05x_asymmetric_t *context, uint8_t *sig, size_t siglen, uint8_t *hash, size_t hashlen);

#endif
