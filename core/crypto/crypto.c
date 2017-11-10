/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <compiler.h>
#include <tee/tee_cryp_provider.h>

#if !defined(_CFG_CRYPTO_WITH_HASH)
TEE_Result crypto_hash_get_ctx_size(uint32_t algo __unused,
				    size_t *size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_hash_init(void *ctx __unused, uint32_t algo __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
TEE_Result crypto_hash_update(void *ctx __unused, uint32_t algo __unused,
			      const uint8_t *data __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
TEE_Result crypto_hash_final(void *ctx __unused, uint32_t algo __unused,
			     uint8_t *digest __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*_CFG_CRYPTO_WITH_HASH*/

#if !defined(_CFG_CRYPTO_WITH_CIPHER)
TEE_Result crypto_cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	return TEE_ERROR_NOT_IMPLEMENTED
}

TEE_Result crypto_cipher_init(void *ctx __unused, uint32_t algo __unused,
			      TEE_OperationMode mode __unused,
			      const uint8_t *key1 __unused,
			      size_t key1_len __unused,
			      const uint8_t *key2 __unused,
			      size_t key2_len __unused,
			      const uint8_t *iv __unused,
			      size_t iv_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED
}

TEE_Result crypto_cipher_update(void *ctx __unused, uint32_t algo __unused,
				TEE_OperationMode mode __unused,
				bool last_block __unused,
				const uint8_t *data __unused,
				size_t len __unused, uint8_t *dst __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED
}

void crypto_cipher_final(void *ctx __unused, uint32_t algo __unused)
{
}

TEE_Result crypto_cipher_get_block_size(uint32_t algo __unused,
					size_t *size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED
}
#endif /*_CFG_CRYPTO_WITH_CIPHER*/

#if !defined(_CFG_CRYPTO_WITH_MAC)
TEE_Result crypto_mac_get_ctx_size(uint32_t algo __unused,
				   size_t *size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_init(void *ctx __unused, uint32_t algo __unused,
			   const uint8_t *key __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_update(void *ctx __unused, uint32_t algo __unused,
			     const uint8_t *data __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_final(void *ctx __unused, uint32_t algo __unused,
			    uint8_t *digest __unused,
			    size_t digest_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*_CFG_CRYPTO_WITH_MAC*/

#if !defined(_CFG_CRYPTO_WITH_AUTHENC)
TEE_Result crypto_authenc_get_ctx_size(uint32_t algo __unused,
				       size_t *size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_authenc_init(void *ctx __unused, uint32_t algo __unused,
			       TEE_OperationMode mode __unused,
			       const uint8_t *key __unused,
			       size_t key_len __unused,
			       const uint8_t *nonce __unused,
			       size_t nonce_len __unused,
			       size_t tag_len __unused,
			       size_t aad_len __unused,
			       size_t payload_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_authenc_update_aad(void *ctx __unused, uint32_t algo __unused,
				     TEE_OperationMode mode __unused,
				     const uint8_t *data __unused,
				     size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_authenc_update_payload(void *ctx __unused,
					 uint32_t algo __unused,
					 TEE_OperationMode mode __unused,
					 const uint8_t *src_data __unused,
					 size_t src_len __unused,
					 uint8_t *dst_data __unused,
					 size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_authenc_enc_final(void *ctx __unused, uint32_t algo __unused,
				    const uint8_t *src_data __unused,
				    size_t src_len __unused,
				    uint8_t *dst_data __unused,
				    size_t *dst_len __unused,
				    uint8_t *dst_tag __unused,
				    size_t *dst_tag_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_authenc_dec_final(void *ctx __unused, uint32_t algo __unused,
				    const uint8_t *src_data __unused,
				    size_t src_len __unused,
				    uint8_t *dst_data __unused,
				    size_t *dst_len __unused,
				    const uint8_t *tag __unused,
				    size_t tag_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_authenc_final(void *ctx __unused, uint32_t algo __unused)
{
}
#endif /*_CFG_CRYPTO_WITH_AUTHENC*/
