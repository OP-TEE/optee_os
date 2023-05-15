/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef TEE_TA_ENC_MANAGER_H
#define TEE_TA_ENC_MANAGER_H

#include <signed_hdr.h>
#include <tee_api_types.h>
#include <utee_defines.h>

#define TEE_TA_ENC_KEY_SIZE		TEE_SHA256_HASH_SIZE

TEE_Result tee_ta_decrypt_init(void **enc_ctx, struct shdr_encrypted_ta *ehdr,
			       size_t len);
TEE_Result tee_ta_decrypt_update(void *enc_ctx, uint8_t *dst, uint8_t *src,
				 size_t len);
TEE_Result tee_ta_decrypt_final(void *enc_ctx, struct shdr_encrypted_ta *ehdr,
				uint8_t *dst, uint8_t *src, size_t len);

#endif
