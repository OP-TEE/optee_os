// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto_impl.h>

TEE_Result
sw_crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s __unused,
				    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
sw_crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s __unused,
				       size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void sw_crypto_acipher_free_rsa_public_key(struct rsa_public_key *s __unused)
{
}

void sw_crypto_acipher_free_rsa_keypair(struct rsa_keypair *s __unused)
{
}

TEE_Result
sw_crypto_acipher_gen_rsa_key(struct rsa_keypair *key __unused,
			      size_t key_size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
sw_crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key __unused,
				   const uint8_t *src __unused,
				   size_t src_len __unused,
				   uint8_t *dst __unused,
				   size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
sw_crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key __unused,
				   const uint8_t *src __unused,
				   size_t src_len __unused,
				   uint8_t *dst __unused,
				   size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
sw_crypto_acipher_rsaes_decrypt(uint32_t algo __unused,
				struct rsa_keypair *key __unused,
				const uint8_t *label __unused,
				size_t label_len __unused,
				const uint8_t *src __unused,
				size_t src_len __unused,
				uint8_t *dst __unused,
				size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
sw_crypto_acipher_rsaes_encrypt(uint32_t algo __unused,
				struct rsa_public_key *key __unused,
				const uint8_t *label __unused,
				size_t label_len __unused,
				const uint8_t *src __unused,
				size_t src_len __unused,
				uint8_t *dst __unused,
				size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
sw_crypto_acipher_rsassa_sign(uint32_t algo __unused,
			      struct rsa_keypair *key __unused,
			      int salt_len __unused,
			      const uint8_t *msg __unused,
			      size_t msg_len __unused,
			      uint8_t *sig __unused,
			      size_t *sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
sw_crypto_acipher_rsassa_verify(uint32_t algo __unused,
				struct rsa_public_key *key __unused,
				int salt_len __unused,
				const uint8_t *msg __unused,
				size_t msg_len __unused,
				const uint8_t *sig __unused,
				size_t sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
