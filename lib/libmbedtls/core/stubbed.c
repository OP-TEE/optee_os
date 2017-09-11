// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <stdlib.h>

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/


#if defined(CFG_CRYPTO_DSA)
TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *s __unused,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *s __unused,
				    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key __unused,
				      size_t key_size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_dsa_sign(uint32_t algo __unused,
				   struct dsa_keypair *key __unused,
				   const uint8_t *msg __unused,
				   size_t msg_len __unused,
				   uint8_t *sig __unused,
				   size_t *sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_dsa_verify(uint32_t algo __unused,
				     struct dsa_public_key *key __unused,
				     const uint8_t *msg __unused,
				     size_t msg_len __unused,
				     const uint8_t *sig __unused,
				     size_t sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_CRYPTO_DSA */


/* Stubs for the crypto alloc ctx functions matching crypto_impl.h */
#undef CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED

#define CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(name, type) \
	TEE_Result \
	crypto_##name##_alloc_ctx(struct crypto_##type##_ctx **ctx __unused) \
	{ return TEE_ERROR_NOT_IMPLEMENTED; }

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_XTS)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_xts, cipher)
#endif

#if defined(CFG_CRYPTO_CCM)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_ccm, authenc)
#endif
