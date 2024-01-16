/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef __TEE_TEE_CRYP_CONCAT_KDF_H
#define __TEE_TEE_CRYP_CONCAT_KDF_H

#include <tee_api_types.h>

TEE_Result tee_cryp_concat_kdf(uint32_t hash_id, const uint8_t *shared_secret,
			       size_t shared_secret_len,
			       const uint8_t *other_info,
			       size_t other_info_len, uint8_t *derived_key,
			       size_t derived_key_len);

#endif /* __TEE_TEE_CRYP_CONCAT_KDF_H */
