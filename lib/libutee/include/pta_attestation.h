/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

/*
 * Provide remote attestation services
 */

#ifndef __PTA_ATTESTATION_H
#define __PTA_ATTESTATION_H

#define PTA_ATTESTATION_UUID { 0x39800861, 0x182a, 0x4720, \
		{ 0x9b, 0x67, 0x2b, 0xcd, 0x62, 0x2b, 0xc0, 0xb5 } }

/*
 * Get the RSA public key that should be used to verify the values returned by
 * other commands.
 *
 * [out]    memref[0]        Public key exponent in big endian order
 * [out]    memref[1]        Modulus in big endian order
 * [out]    value[2]         Signature algorithm used by other commands.
 *                           Currently always
 *                           TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_GENERIC - Internal error
 * TEE_ERROR_SHORT_BUFFER - One or both buffers are too small, required size
 *                          is provided in memref[i].size
 */
#define PTA_ATTESTATION_GET_PUBKEY 0x0

/*
 * Return the digest found in the header of a Trusted Application binary or a
 * Trusted Shared library
 *
 * [in]     memref[0]        UUID of the TA or shared library
 * [in]     memref[1]        Nonce (random non-NULL, non-empty buffer of any
 *                           size to prevent replay attacks)
 * [out]    memref[2]        Output buffer. Receives the signed digest.
 *                           - The first 32 bytes are the digest itself (from
 *                             the TA signed header: struct shdr::hash)
 *                           - The following bytes are a signature:
 *                               SIG(SHA256(Nonce | digest))
 *                           - The algorithm is
 *                             TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 with a salt
 *                             length of 32.
 *                           - The key pair is generated internally and stored
 *                             in secure storage. The public key can be
 *                             retrieved with command PTA_ATTESTATION_GET_PUBKEY
 *                             (typically during device provisioning).
 *                           Given that the sigature length is equal to the
 *                           RSA modulus size in bytes, the output buffer size
 *                           should be at least (digest size + modulus size)
 *                           bytes. For example, for a 32-byte SHA256 digest and
 *                           2048 bit key (256 bytes) the minimum buffer size is
 *                           288 bytes.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_GET_TA_SHDR_DIGEST 0x1

/*
 * Return a signed hash for a running user space TA, which must be the caller
 * of this PTA. It is a runtime measurement of the memory pages that contain
 * immutable data (code and read-only data).
 *
 * [in]     memref[0]        Nonce
 * [out]    memref[1]        SHA256 hash of the TA memory followed by a
 *                           signature. See PTA_ATTESTATION_GET_TA_HDR_DIGEST
 *                           for a description of the signature.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_DENIED - Caller is not a user space TA
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_HASH_TA_MEMORY 0x2

/*
 * Return a signed hash of the TEE OS (kernel) memory. It is a runtime
 * measurement of the memory pages that contain immutable data (code and
 * read-only data).
 *
 * [in]     memref[0]        Nonce
 * [out]    memref[1]        SHA256 hash of the TEE memory followed by a
 *                           signature. See PTA_ATTESTATION_GET_TA_HDR_DIGEST
 *                           for a description of the signature.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_HASH_TEE_MEMORY 0x3

#endif /* __PTA_ATTESTATION_H */
