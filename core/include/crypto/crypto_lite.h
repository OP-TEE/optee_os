/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __CRYPTO_LITE_H
#define __CRYPTO_LITE_H

#include <tee_api_types.h>

#if defined(_CFG_CRYPTO_WITH_ACIPHER)
#define LTC_VARIABLE_NUMBER         (50)

#define LTC_MEMPOOL_U32_SIZE \
	mpa_scratch_mem_size_in_U32(LTC_VARIABLE_NUMBER, \
				    CFG_CORE_BIGNUM_MAX_BITS)
#endif

/* Symmetric ciphers */
TEE_Result _crypto_cipher_alloc_ctx(void **ctx, uint32_t algo);
TEE_Result _crypto_cipher_init(void *ctx, uint32_t algo,
			      TEE_OperationMode mode,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2, size_t key2_len,
			      const uint8_t *iv, size_t iv_len);
TEE_Result _crypto_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode, bool last_block,
				const uint8_t *data, size_t len, uint8_t *dst);
void _crypto_cipher_final(void *ctx, uint32_t algo);
TEE_Result _crypto_cipher_get_block_size(uint32_t algo, size_t *size);
void _crypto_cipher_free_ctx(void *ctx, uint32_t algo);
void _crypto_cipher_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo);

TEE_Result crypto_cipher_lite_alloc_ctx(void **ctx, uint32_t algo);
TEE_Result crypto_cipher_lite_init(void *ctx, uint32_t algo,
			      TEE_OperationMode mode,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2, size_t key2_len,
			      const uint8_t *iv, size_t iv_len);
TEE_Result crypto_cipher_lite_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode, bool last_block,
				const uint8_t *data, size_t len, uint8_t *dst);
void crypto_cipher_lite_final(void *ctx, uint32_t algo);
TEE_Result crypto_cipher_lite_get_block_size(uint32_t algo, size_t *size);
void crypto_cipher_lite_free_ctx(void *ctx, uint32_t algo);
void crypto_cipher_lite_copy_state(void *dst_ctx, void *src_ctx,
				uint32_t algo);

/* Message Authentication Code functions */
TEE_Result _crypto_mac_alloc_ctx(void **ctx, uint32_t algo);
TEE_Result _crypto_mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			   size_t len);
TEE_Result _crypto_mac_update(void *ctx, uint32_t algo, const uint8_t *data,
			     size_t len);
TEE_Result _crypto_mac_final(void *ctx, uint32_t algo, uint8_t *digest,
			    size_t digest_len);
void _crypto_mac_free_ctx(void *ctx, uint32_t algo);
void _crypto_mac_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo);

TEE_Result crypto_cbc_mac_alloc_ctx(void **ctx, uint32_t algo);
TEE_Result crypto_cbc_mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			   size_t len);
TEE_Result crypto_cbc_mac_update(void *ctx, uint32_t algo, const uint8_t *data,
			     size_t len);
TEE_Result crypto_cbc_mac_final(void *ctx, uint32_t algo, uint8_t *digest,
			    size_t digest_len);
void crypto_cbc_mac_free_ctx(void *ctx, uint32_t algo);
void crypto_cbc_mac_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo);

TEE_Result crypto_lite_init(void);
struct tee_ltc_prng *tee_ltc_get_prng(void);

#endif /*__CRYPTO_LITE_H*/
