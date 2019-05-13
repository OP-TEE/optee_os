/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019, Linaro Limited
 */

/*
 * This pseudo TA is used to seal/unseal the REE Kernel (Linux)
 * Trusted Keys.
 */

#ifndef __PTA_TRUSTED_KEY_H
#define __PTA_TRUSTED_KEY_H

#define PTA_TRUSTED_KEY_UUID { 0xf04a0fe7, 0x1f5d, 0x4b9b, \
		{ 0xab, 0xf7, 0x61, 0x9b, 0x85, 0xb4, 0xce, 0x8c } }

/*
 * Get random data for symmetric key
 *
 * [out]     memref[0]        Random data
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define TA_CMD_GET_RANDOM	0x0

/*
 * Seal trusted key using hardware unique key
 *
 * [in]      memref[0]        Plain key
 * [out]     memref[1]        Sealed key datablob
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define TA_CMD_SEAL		0x1

/*
 * Unseal trusted key using hardware unique key
 *
 * [in]      memref[0]        Sealed key datablob
 * [out]     memref[1]        Plain key
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define TA_CMD_UNSEAL		0x2

#endif /* __PTA_TRUSTED_KEY_H */
