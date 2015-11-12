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

#define BLOCK_FILE_SHIFT	12
#define BLOCK_FILE_SIZE		(1 << BLOCK_FILE_SHIFT)
#define NUM_BLOCKS_PER_FILE	1024
#define MAX_FILE_SIZE	(BLOCK_FILE_SIZE * NUM_BLOCKS_PER_FILE)

#define TMP_PREFIX "."
#define FILE_HEADER_NAME "file_header"
#define DATA_BLOCK_NAME "data_block"

#define TEE_FS_NAME_MAX 350

#define TEE_FS_KM_CHIP_ID_LENGTH    32
#define TEE_FS_KM_HMAC_ALG          TEE_ALG_HMAC_SHA256
#define TEE_FS_KM_AUTH_ENC_ALG      TEE_ALG_AES_GCM
#define TEE_FS_KM_ENC_FEK_ALG       TEE_ALG_AES_ECB_NOPAD
#define TEE_FS_KM_SSK_SIZE          TEE_SHA256_HASH_SIZE
#define TEE_FS_KM_FEK_SIZE          16  /* bytes */
#define TEE_FS_KM_IV_LEN            12  /* bytes */
#define TEE_FS_KM_MAX_TAG_LEN       16  /* bytes */


enum tee_file_data_type {
	FILE_HEADER,
	DATA_BLOCK
};

/*
 * TEE File Header := |<Cipher Header>|<Cipher Text>|
 * Cipher Header   := |Encrypted FEK|Header IV|Tag|
 * Cipher Text     := |Encrypted Meta Data|
 * File Header AAD := |Encrypted FEK|UUID|Object ID|
 */

struct fh_cipher_header {
	uint8_t encrypted_fek[TEE_FS_KM_FEK_SIZE];
	uint8_t iv[TEE_FS_KM_IV_LEN];
	uint8_t tag[TEE_FS_KM_MAX_TAG_LEN];
};

struct fh_meta_data {
	uint32_t file_size;
	uint32_t data_block_backup_version[NUM_BLOCKS_PER_FILE / 32];
};

/* filename contains UUID and Object ID information" */
struct fh_aad {
	uint8_t encrypted_fek[TEE_FS_KM_FEK_SIZE];
	uint8_t filename[TEE_FS_NAME_MAX];
};


/*
 * Data Block      := |<Cipher Header>|<Cipher Text>|
 * Cipher Header   := |Data Block IV|Tag|
 * Cipher Text     := |Encrypted TEE Data|
 * Data Block AAD  := |Block number|
 */

struct block_cipher_header {
	uint8_t iv[TEE_FS_KM_IV_LEN];
	uint8_t tag[TEE_FS_KM_MAX_TAG_LEN];
};

struct block_aad {
	uint32_t block_num;
};

struct tee_fs_key_manager_operations {
	uint32_t (*get_cipher_header_size)(enum tee_file_data_type data_type);
	TEE_Result (*generate_fek)(uint8_t *encrypted_fek, int fek_size);
	TEE_Result (*get_encrypted_fek)(const uint8_t *in, uint32_t in_size,
			uint8_t *out, uint32_t *out_size);
	TEE_Result (*do_encryption)(enum tee_file_data_type data_type,
			const uint8_t *encrypted_fek,
			uint8_t *aad, uint32_t aad_len,
			uint8_t *in, uint32_t in_size,
			uint8_t *out, size_t *out_size);
	TEE_Result (*do_decryption)(enum tee_file_data_type data_type,
			uint8_t *encrypted_fek,
			uint8_t *aad, uint32_t aad_len,
			uint8_t *in, uint32_t in_size,
			uint8_t *out, size_t *out_size);
};

extern struct tee_fs_key_manager_operations key_manager_ops;

#endif
