/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

/*
 * Provide remote attestation services
 */

#ifndef __PTA_ATTESTATION_H
#define __PTA_ATTESTATION_H

#define PTA_ATTESTATION_UUID { 0x59590731, 0x6966, 0x4b76, \
		{ 0x9c, 0xad, 0xb8, 0xf9, 0x0d, 0x9a, 0x77, 0xcd } }

/*
 * Get signed hash for a Trusted Application binary or for a shared library
 *
 * [in]     memref[0]        UUID of the TA or shared library to measure
 * [in]     memref[1]        Nonce (random value of any size to prevent replay
 *                           attacks)
 * [out]    memref[2]        Output buffer. Receives a signed SHA256 hash that
 *                           uniquely represents the content of the TA binary
 *                           file.
 *                           - The first 32 bytes are the hash itself (TA hash)
 *                           - The following bytes are a signature:
 *                               SIG(SHA256(Nonce | TA hash))
 *                           - The algorithm is
 *                             TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 with a salt
 *                             length of 32.
 *                           - The key pair is defined at build time by
 *                             CFG_ATTESTATION_PTA_SIGN_KEY.
 *                           Given that the sigature length is equal to the
 *                           RSA modulus size in bytes, the output buffer size
 *                           should be at least 32 + modulus size bytes. For
 *                           example, for a 3072 bit key (384 bytes) the minimum
 *                           buffer size is 416 bytes.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_HASH_TA		0x0

#endif /* __PTA_ATTESTATION_H */
