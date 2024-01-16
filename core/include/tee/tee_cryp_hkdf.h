/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef __TEE_TEE_CRYP_HKDF_H
#define __TEE_TEE_CRYP_HKDF_H

#include <tee_api_types.h>

TEE_Result tee_cryp_hkdf(uint32_t hash_id, const uint8_t *ikm, size_t ikm_len,
			 const uint8_t *salt, size_t salt_len,
			 const uint8_t *info, size_t info_len, uint8_t *okm,
			 size_t okm_len);

#endif /* __TEE_TEE_CRYP_HKDF_H */
