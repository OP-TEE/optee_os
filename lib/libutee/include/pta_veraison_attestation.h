/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#ifndef __PTA_VERAISON_ATTESTATION_H
#define __PTA_VERAISON_ATTESTATION_H

#define PTA_VERAISON_ATTESTATION_UUID                                  \
	{                                                              \
		0xa77955f9, 0xeea1, 0x44fd,                            \
		{                                                      \
			0xad, 0xd5, 0x4a, 0x9d, 0x96, 0x2a, 0xfc, 0xf5 \
		}                                                      \
	}

/*
 * Return a CBOR(COSE) evidence
 *
 * [in]     memref[0]        Nonce
 * [out]    memref[1]        Output buffer
 * [in]     memref[2]        Implementation ID
 * [in]     memref[3]        (optional) Signing key: public key X (32
 *                           bytes) || public key Y (32 bytes) || private
 *                           key, either the plain P-256 scalar or a CAAM
 *                           black key in its serialized form. Without it
 *                           the embedded test key signs.
 *
 * The PSA instance-id of the evidence is derived from the public key of
 * the key in use: 0x01 || SHA-256(0x04 || X || Y).
 *
 * Main return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_DENIED   - Caller is not a user space TA
 * TEE_ERROR_BAD_PARAMETERS  - Incorrect input param, or the public key
 *                             does not belong to the private key
 * TEE_ERROR_SHORT_BUFFER    - Output buffer size less than required
 * TEE_ERROR_NOT_IMPLEMENTED - Command not implemented
 */
#define PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE 0x0

/*
 * Generate an ECDSA P-256 key pair in the CAAM, for GET_CBOR_EVIDENCE
 *
 * [out]    memref[0]        Private key, a serialized CAAM black key
 * [out]    memref[1]        Public key X (32 bytes)
 * [out]    memref[2]        Public key Y (32 bytes)
 *
 * Main return codes:
 * TEE_SUCCESS
 * TEE_ERROR_BAD_PARAMETERS  - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER    - A buffer is too small, its size is updated
 * TEE_ERROR_NOT_SUPPORTED   - Built without the CAAM ECC driver
 */
#define PTA_VERAISON_ATTESTATION_GENERATE_KEYPAIR 0x1

/*
 * Wrap a plain ECDSA P-256 private key into a serialized CAAM black key
 *
 * [in]     memref[0]        Plain private key (32 bytes)
 * [out]    memref[1]        Private key, a serialized CAAM black key
 *
 * Main return codes:
 * TEE_SUCCESS
 * TEE_ERROR_BAD_PARAMETERS  - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER    - The buffer is too small, its size is updated
 * TEE_ERROR_NOT_SUPPORTED   - Built without the CAAM ECC driver
 */
#define PTA_VERAISON_ATTESTATION_CONVERT_TO_BLACKKEY 0x2

#endif /* __PTA_VERAISON_ATTESTATION_H */
