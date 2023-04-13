/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022 HiSilicon Limited.
 */
#ifndef __PBKDF2_SUPPORT_H__
#define __PBKDF2_SUPPORT_H__

#include <stdint.h>

TEE_Result hw_pbkdf2(uint32_t hash_id, const uint8_t *password,
		     size_t password_len, const uint8_t *salt,
		     size_t salt_len, uint32_t iteration_count,
		     uint8_t *derived_key, size_t derived_key_len);

#endif /* __PBKDF2_SUPPORT_H__ */
