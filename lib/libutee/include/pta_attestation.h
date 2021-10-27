/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

/*
 * Provide remote attestation services
 */

#ifndef __PTA_ATTESTATION_H
#define __PTA_ATTESTATION_H

#define PTA_ATTESTATION_UUID { 0x4bf4cf49, 0x0a36, 0x49b0, \
		{ 0x80, 0x98, 0x17, 0x42, 0x4a, 0xb3, 0xe6, 0xc7 } }

/*
 * Get [signed TBD] hash for a running user space TA
 *
 * [in]     value[0].a       Session ID
 * [in]     value[0].b       Hash mode (PTA_ATTESTATION_HASH_MODE_* below)
 * [out]    memref[1]        SHA256 hash of all the TA memory pages that contain
 *                           immutable data (code, RO data)
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_DENIED - Caller is not a non-secure CA
 * TEE_ERROR_ITEM_NOT_FOUND - No TA found running the specified session ID
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_HASH_TA		0x0

/*
 * Hash all the TA memory pages that contain immutable data (code, RO data).
 * Can be used for authentication as well as periodic integrity checking.
 */
#define PTA_ATTESTATION_HASH_MODE_FULL	0x0
/*
 * Hash the tags computed at load time. Faster than "full" mode but cannot
 * detect memory corruption.
 */
#define PTA_ATTESTATION_HASH_MODE_TAGS	0x1

#endif /* __PTA_ATTESTATION_H */
