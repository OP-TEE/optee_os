/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <compiler.h>
#include <kernel/panic.h>
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

#if !defined(_CFG_CRYPTO_WITH_ACIPHER)
struct bignum *crypto_bignum_allocate(size_t size_bits __unused)
{
	return NULL;
}

TEE_Result crypto_bignum_bin2bn(const uint8_t *from __unused,
				size_t fromsize __unused,
				struct bignum *to __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

size_t crypto_bignum_num_bytes(struct bignum *a __unused)
{
	return 0;
}

size_t crypto_bignum_num_bits(struct bignum *a __unused)
{
	return 0;
}

/*
 * crypto_bignum_allocate() and crypto_bignum_bin2bn() failing should be
 * enough to guarantee that the functions calling this function aren't
 * called, but just in case add a panic() here to avoid unexpected
 * behavoir.
 */
static void bignum_cant_happen(void)
{
	volatile bool b = true;

	/* Avoid warning about function does not return */
	if (b)
		panic();
}

void crypto_bignum_bn2bin(const struct bignum *from __unused,
			  uint8_t *to __unused)
{
	bignum_cant_happen();
}

void crypto_bignum_copy(struct bignum *to __unused,
			const struct bignum *from __unused)
{
	bignum_cant_happen();
}

void crypto_bignum_free(struct bignum *a)
{
	if (a)
		panic();
}

void crypto_bignum_clear(struct bignum *a __unused)
{
	bignum_cant_happen();
}

/* return -1 if a<b, 0 if a==b, +1 if a>b */
int32_t crypto_bignum_compare(struct bignum *a __unused,
			      struct bignum *b __unused)
{
	bignum_cant_happen();
	return -1;
}
#endif /*!_CFG_CRYPTO_WITH_ACIPHER*/
