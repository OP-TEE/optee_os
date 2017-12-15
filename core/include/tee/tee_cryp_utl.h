/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
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
