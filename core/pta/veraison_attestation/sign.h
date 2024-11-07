/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#ifndef PTA_VERAISON_ATTESTATION_SIGN_H
#define PTA_VERAISON_ATTESTATION_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/**
 * Sign a message with ECDSA w/ SHA-256
 * @param msg       The message to sign
 * @param msg_len   The length of the message to sign
 * @param sig       [out] Where to store the signature. The signature format
 *                  follows the specifications in RFC 7518 Section 3.4. This
 *                  means the signature will be output in a 'plain signature'
 *                  format, diverging from the traditional ASN.1 DER encoding.
 *                  In this context, 'plain signature' refers to the direct
 *                  concatenation of the r and s values of the ECDSA signature,
 *                  each occupying exactly half of the signature space. When
 *                  using a 256-bit ECDSA key, r and s are each 32 bytes long.
 *                  In a plain signature, these values are simply concatenated
 *                  to produce a total signature of 64 bytes.
 * @param sig_len   [in/out] The max size and resulting size of the signature.
 *                  It is important to ensure that the provided buffer is
 *                  sufficiently large to hold the signature in its specified
 *                  format. The resulting size will indicate the actual size of
 *                  the signature in bytes.
 * @return TEE_SUCCESS if successful
 */
TEE_Result sign_ecdsa_sha256(const uint8_t *msg, size_t msg_len, uint8_t *sig,
			     size_t *sig_len);

#endif /*PTA_VERAISON_ATTESTATION_SIGN_H*/
