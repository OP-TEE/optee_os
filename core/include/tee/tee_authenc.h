/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#ifndef TEE_AUTHENC_H
#define TEE_AUTHENC_H

#include <tee_api_types.h>

/*
 * Algorithms in this files are as specified with the TEE_ALG_XXX from
 * TEE Internal API.
 */

TEE_Result tee_authenc_get_ctx_size(uint32_t algo, size_t *size);

TEE_Result tee_authenc_init(
	void *ctx, uint32_t algo, TEE_OperationMode mode, const uint8_t *key,
	size_t key_len, const uint8_t *nonce,
	size_t nonce_len, size_t tag_len, size_t aad_len, size_t payload_len);

TEE_Result tee_authenc_update_aad(
	void *ctx, uint32_t algo, TEE_OperationMode mode,
	  const uint8_t *data, size_t len);

TEE_Result tee_authenc_update_payload(
	void *ctx, uint32_t algo, TEE_OperationMode mode,
	const uint8_t *src_data, size_t src_len, uint8_t *dst_data);

TEE_Result tee_authenc_enc_final(
	void *ctx, uint32_t algo, const uint8_t *src_data,
	 size_t src_len, uint8_t *dst_data,
	 uint8_t *dst_tag, size_t *dst_tag_len);

TEE_Result tee_authenc_dec_final(
	void *ctx, uint32_t algo, const uint8_t *src_data,
	size_t src_len, uint8_t *dst_data, const uint8_t *tag, size_t tag_len);

void tee_authenc_final(void *ctx, uint32_t algo);

#endif /* TEE_AUTHENC_H */
