/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef __TEE_TEE_CRYP_PBKDF2_H
#define __TEE_TEE_CRYP_PBKDF2_H

#include <tee_api_types.h>

TEE_Result tee_cryp_pbkdf2(uint32_t hash_id, const uint8_t *password,
			   size_t password_len, const uint8_t *salt,
			   size_t salt_len, uint32_t iteration_count,
			   uint8_t *derived_key, size_t derived_key_len);

#endif /* __TEE_TEE_CRYP_PBKDF2_H */
