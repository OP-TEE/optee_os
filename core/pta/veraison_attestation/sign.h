/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#ifndef PTA_VERAISON_ATTESTATION_SIGN_H
#define PTA_VERAISON_ATTESTATION_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define SIGNING_KEY_COORD_SIZE 32
/*
 * Largest private key: with the CAAM ECC driver the scalar comes as a
 * serialized CAAM key, a black key in a CAAM blob (48 bytes of overhead)
 * behind a 12-byte header.
 */
#define SIGNING_KEY_PRIV_MAX_SIZE 128
#define INSTANCE_ID_LEN 33

/*
 * The ECDSA P-256 key that signs the evidence.
 *
 * @pub_x, @pub_y  Public key coordinates
 * @priv_len       Length of @priv
 * @priv           Private key: the scalar, or with the CAAM ECC driver its
 *                 serialized CAAM key, which the driver unwraps and uses
 *                 inside the CAAM
 */
struct signing_key {
	uint8_t pub_x[SIGNING_KEY_COORD_SIZE];
	uint8_t pub_y[SIGNING_KEY_COORD_SIZE];
	size_t priv_len;
	uint8_t priv[SIGNING_KEY_PRIV_MAX_SIZE];
};

#ifdef CFG_VERAISON_ATTESTATION_PTA_TEST_KEY
/**
 * Get the embedded test key
 * @return The key
 */
const struct signing_key *sign_test_key(void);
#endif

/**
 * Compute the PSA instance-id of a key: 0x01 followed by the SHA-256 of
 * the SEC 1 uncompressed point (0x04 || X || Y) of its public key
 * @param skey         The key
 * @param instance_id  [out] INSTANCE_ID_LEN bytes
 * @return TEE_SUCCESS if successful
 */
TEE_Result compute_instance_id(const struct signing_key *skey,
			       uint8_t instance_id[INSTANCE_ID_LEN]);

/**
 * Sign a message with ECDSA w/ SHA-256
 * @param skey      The key to sign with
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
 * @return TEE_SUCCESS if successful, an error if the key does not sign or
 *         its public key does not verify the signature
 */
TEE_Result sign_ecdsa_sha256(const struct signing_key *skey,
			     const uint8_t *msg, size_t msg_len, uint8_t *sig,
			     size_t *sig_len);

#endif /*PTA_VERAISON_ATTESTATION_SIGN_H*/
