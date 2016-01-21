/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TEE_FS_KEY_MANAGER_H
#define TEE_FS_KEY_MANAGER_H

#include <tee_api_types.h>

#define TEE_FS_KM_CHIP_ID_LENGTH    32
#define TEE_FS_KM_HMAC_ALG          TEE_ALG_HMAC_SHA256
#define TEE_FS_KM_AUTH_ENC_ALG      TEE_ALG_AES_GCM
#define TEE_FS_KM_ENC_FEK_ALG       TEE_ALG_AES_ECB_NOPAD
#define TEE_FS_KM_SSK_SIZE          TEE_SHA256_HASH_SIZE
#define TEE_FS_KM_FEK_SIZE          16  /* bytes */
#define TEE_FS_KM_IV_LEN            12  /* bytes */
#define TEE_FS_KM_MAX_TAG_LEN       16  /* bytes */

enum tee_fs_file_type {
	META_FILE,
	BLOCK_FILE
};

struct common_header {
	uint8_t iv[TEE_FS_KM_IV_LEN];
	uint8_t tag[TEE_FS_KM_MAX_TAG_LEN];
};

struct meta_header {
	uint8_t encrypted_key[TEE_FS_KM_FEK_SIZE];
	struct common_header common;
};

struct block_header {
	struct common_header common;
};

size_t tee_fs_get_header_size(enum tee_fs_file_type type);
TEE_Result tee_fs_generate_fek(uint8_t *encrypted_fek, int fek_size);
TEE_Result tee_fs_encrypt_file(enum tee_fs_file_type file_type,
		const uint8_t *plaintext, size_t plaintext_size,
		uint8_t *ciphertext, size_t *ciphertext_size,
		const uint8_t *encrypted_fek);
TEE_Result tee_fs_decrypt_file(enum tee_fs_file_type file_type,
		const uint8_t *data_in, size_t data_in_size,
		uint8_t *plaintext, size_t *plaintext_size,
		uint8_t *encrypted_fek);
TEE_Result tee_fs_crypt_block(uint8_t *out, const uint8_t *in, size_t size,
			      uint16_t blk_idx, const uint8_t *encrypted_fek,
			      TEE_OperationMode mode);
#endif
