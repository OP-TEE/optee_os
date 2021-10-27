/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

/*
 * Provide remote attestation services
 */

#ifndef __PTA_ATTESTATION_H
#define __PTA_ATTESTATION_H

#define PTA_ATTESTATION_UUID { 0x0dc571c7, 0xb1a7, 0x43fb, \
		{ 0xa8, 0x78, 0x72, 0xc7, 0xb8, 0xc5, 0x88, 0xbb } }

/*
 * Get [signed TBD] hash for a running user space TA, which must be the caller
 * of this PTA.
 *
 * Parameters to pass to TEE_OpenTASession():
 *
 * [in]     value[0].a       Hash method (PTA_ATTESTATION_HASH_METHOD_* below)
 * [out]    memref[1]        SHA256 hash of all the TA memory pages that contain
 *                           immutable data (code, RO data)
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_DENIED - Caller is not a user space TA
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */

/*
 * Hash all the TA memory pages that contain immutable data (code, RO data).
 * Can be used for authentication as well as periodic integrity checking.
 */
#define PTA_ATTESTATION_HASH_METHOD_FULL	0x0
/*
 * Hash the tags computed at load time. Faster than "full" mode but cannot
 * detect memory corruption.
 */
#define PTA_ATTESTATION_HASH_METHOD_TAGS	0x1

#endif /* __PTA_ATTESTATION_H */
