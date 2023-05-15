/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019-2020, Linaro Limited
 */

#ifndef TRUSTED_KEYS_H
#define TRUSTED_KEYS_H

#define TRUSTED_KEYS_UUID { 0xf04a0fe7, 0x1f5d, 0x4b9b, \
		{ 0xab, 0xf7, 0x61, 0x9b, 0x85, 0xb4, 0xce, 0x8c } }

/*
 * Get random data for symmetric key
 *
 * [out]     memref[0]        Random data
 */
#define TA_CMD_GET_RANDOM	0x0

/*
 * Seal trusted key using hardware unique key
 *
 * [in]      memref[0]        Plain key
 * [out]     memref[1]        Sealed key datablob
 */
#define TA_CMD_SEAL		0x1

/*
 * Unseal trusted key using hardware unique key
 *
 * [in]      memref[0]        Sealed key datablob
 * [out]     memref[1]        Plain key
 */
#define TA_CMD_UNSEAL		0x2

#endif /* TRUSTED_KEYS_H */
