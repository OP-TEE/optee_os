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

#endif /* __PTA_VERAISON_ATTESTATION_H */
