/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef TEE_FS_KEY_MANAGER_H
#define TEE_FS_KEY_MANAGER_H

#include <tee_api_types.h>
#include <utee_defines.h>

#define TEE_FS_KM_CHIP_ID_LENGTH    U(32)
#define TEE_FS_KM_HMAC_ALG          TEE_ALG_HMAC_SHA256
#define TEE_FS_KM_ENC_FEK_ALG       TEE_ALG_AES_ECB_NOPAD
#define TEE_FS_KM_SSK_SIZE          TEE_SHA256_HASH_SIZE
#define TEE_FS_KM_TSK_SIZE          TEE_SHA256_HASH_SIZE
#define TEE_FS_KM_FEK_SIZE          U(16)  /* bytes */

TEE_Result tee_fs_generate_fek(const TEE_UUID *uuid, void *encrypted_fek,
			       size_t fek_size);
TEE_Result tee_fs_crypt_block(const TEE_UUID *uuid, uint8_t *out,
			      const uint8_t *in, size_t size,
			      uint16_t blk_idx, const uint8_t *encrypted_fek,
			      TEE_OperationMode mode);

TEE_Result tee_fs_fek_crypt(const TEE_UUID *uuid, TEE_OperationMode mode,
			    const uint8_t *in_key, size_t size,
			    uint8_t *out_key);

#endif
