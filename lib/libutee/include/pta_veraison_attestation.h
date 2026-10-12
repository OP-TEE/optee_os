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
 * The evidence is signed with an ECDSA P-256 key that the PTA keeps in
 * its secure storage, or, when the PTA is built with
 * CFG_VERAISON_ATTESTATION_PTA_TEST_KEY=y, with an embedded test key.
 * The stored key is generated on first use, or installed before that
 * with PTA_VERAISON_ATTESTATION_IMPORT_KEY, and never replaced: it is
 * the key of every TA's evidence. The key never leaves the PTA; callers
 * only get the public key, from which the PSA instance-id of the
 * evidence is derived.
 *
 * Only user TAs can open a session with the PTA.
 */

/*
 * Return a CBOR(COSE) evidence
 *
 * [in]     memref[0]        Nonce
 * [out]    memref[1]        Output buffer
 * [in]     memref[2]        Implementation ID
 *
 * Main return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_DENIED   - Caller is not a user space TA
 * TEE_ERROR_BAD_PARAMETERS  - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER    - Output buffer size less than required
 * TEE_ERROR_NOT_IMPLEMENTED - Command not implemented
 */
#define PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE 0x0

/*
 * Return the public key of the signing key, generating the key first if
 * there is none yet. The parameters are checked before that.
 *
 * [out]    memref[0]        Public key X (32 bytes)
 * [out]    memref[1]        Public key Y (32 bytes)
 *
 * Main return codes:
 * TEE_SUCCESS
 * TEE_ERROR_BAD_PARAMETERS  - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER    - A buffer is too small, its size is updated
 */
#define PTA_VERAISON_ATTESTATION_GET_PUBLIC_KEY 0x1

/*
 * Install a signing key generated and registered elsewhere, for a
 * provisioning flow. Only possible while the PTA has no key, that is
 * before the first evidence or public key was requested.
 *
 * [in]     memref[0]        Public key X (32 bytes)
 * [in]     memref[1]        Public key Y (32 bytes)
 * [in]     memref[2]        Private key (32 bytes)
 *
 * Main return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_CONFLICT - The PTA already has a key
 * TEE_ERROR_BAD_PARAMETERS  - Incorrect input param, or the private key
 *                             does not match the public key
 * TEE_ERROR_NOT_SUPPORTED   - Built with the test key
 */
#define PTA_VERAISON_ATTESTATION_IMPORT_KEY 0x2

#endif /* __PTA_VERAISON_ATTESTATION_H */
