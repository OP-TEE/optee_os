/*
 * Copyright (c) 2014, Linaro Limited
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

#ifndef TEE_CRYP_UTL_H
#define TEE_CRYP_UTL_H

#include <tee_api_types.h>

#if !defined(CFG_WITH_SOFTWARE_PRNG)
TEE_Result get_rng_array(void *buffer, int len);
#endif

TEE_Result tee_hash_get_digest_size(uint32_t algo, size_t *size);
TEE_Result tee_hash_createdigest(uint32_t algo, const uint8_t *data,
				 size_t datalen, uint8_t *digest,
				 size_t digestlen);
TEE_Result tee_mac_get_digest_size(uint32_t algo, size_t *size);
TEE_Result tee_cipher_get_block_size(uint32_t algo, size_t *size);
TEE_Result tee_do_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode, bool last_block,
				const uint8_t *data, size_t len, uint8_t *dst);
TEE_Result tee_aes_cbc_cts_update(void *cbc_ctx, void *ecb_ctx,
				  TEE_OperationMode mode, bool last_block,
				  const uint8_t *data, size_t len,
				  uint8_t *dst);

TEE_Result tee_prng_add_entropy(const uint8_t *in, size_t len);
void plat_prng_add_jitter_entropy(void);
/*
 * The _norpc version must not invoke Normal World, or infinite recursion
 * may occur. As an exception however, using mutexes is allowed.
 */
void plat_prng_add_jitter_entropy_norpc(void);

#endif
