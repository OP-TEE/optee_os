/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All Rights Reserved.
 *
 */

#ifndef __ASU_CRYPTO_COMMON_H_
#define __ASU_CRYPTO_COMMON_H_

#include <tee_api_types.h>

/*
 * asu_shadev_acquire() - Claim a SHA engine slot by module ID.
 * @module: ASU_MODULE_SHA2_ID or ASU_MODULE_SHA3_ID
 *
 * Return: TEE_SUCCESS if claimed, TEE_ERROR_NOT_IMPLEMENTED if busy.
 */
TEE_Result asu_shadev_acquire(uint8_t module);

/*
 * asu_shadev_release() - Release a previously claimed SHA engine slot.
 * @module: ASU_MODULE_SHA2_ID or ASU_MODULE_SHA3_ID
 */
void asu_shadev_release(uint8_t module);

#endif /* __ASU_CRYPTO_COMMON_H_ */
