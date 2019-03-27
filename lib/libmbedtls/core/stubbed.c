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

#if defined(CFG_CRYPTO_RSA) || defined(CFG_CRYPTO_DSA) || \
    defined(CFG_CRYPTO_DH) || defined(CFG_CRYPTO_ECC)
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

void crypto_bignum_bn2bin(const struct bignum *from __unused,
			  uint8_t *to __unused)
{
}

void crypto_bignum_copy(struct bignum *to __unused,
			const struct bignum *from __unused)
{
}

void crypto_bignum_free(struct bignum *a)
{
	if (a)
		panic();
}

void crypto_bignum_clear(struct bignum *a __unused)
{
}

/* return -1 if a<b, 0 if a==b, +1 if a>b */
int32_t crypto_bignum_compare(struct bignum *a __unused,
			      struct bignum *b __unused)
{
	return -1;
}
#endif


#if defined(CFG_CRYPTO_RSA)
TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s __unused,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s __unused,
				    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_acipher_free_rsa_public_key(struct rsa_public_key *s __unused)
{
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key __unused,
				      size_t key_size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key __unused,
					   const uint8_t *src __unused,
					   size_t src_len __unused,
					   uint8_t *dst __unused,
					   size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key __unused,
					   const uint8_t *src __unused,
					   size_t src_len __unused,
					   uint8_t *dst __unused,
					   size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo __unused,
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

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo __unused,
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

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo __unused,
				      struct rsa_keypair *key __unused,
				      int salt_len __unused,
				      const uint8_t *msg __unused,
				      size_t msg_len __unused,
				      uint8_t *sig __unused,
				      size_t *sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo __unused,
					struct rsa_public_key *key __unused,
					int salt_len __unused,
					const uint8_t *msg __unused,
					size_t msg_len __unused,
					const uint8_t *sig __unused,
					size_t sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_CRYPTO_RSA */

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

#if defined(CFG_CRYPTO_DH)
TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s __unused,
					   size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key __unused,
				     struct bignum *q __unused,
				     size_t xbits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_dh_shared_secret(struct dh_keypair *private_key __unused,
				struct bignum *public_key __unused,
				struct bignum *secret __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_CRYPTO_DH */

#if defined(CFG_CRYPTO_ECC)
TEE_Result
crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s __unused,
				    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s __unused,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_acipher_free_ecc_public_key(struct ecc_public_key *s __unused)
{
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo __unused,
				   struct ecc_keypair *key __unused,
				   const uint8_t *msg __unused,
				   size_t msg_len __unused,
				   uint8_t *sig __unused,
				   size_t *sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo __unused,
				     struct ecc_public_key *key __unused,
				     const uint8_t *msg __unused,
				     size_t msg_len __unused,
				     const uint8_t *sig __unused,
				     size_t sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key __unused,
				 struct ecc_public_key *public_key __unused,
				 void *secret __unused,
				 unsigned long *secret_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_CRYPTO_ECC */

#if defined(CFG_CRYPTO_SHA256)
TEE_Result hash_sha256_check(const uint8_t *hash  __unused,
		const uint8_t *data __unused,
		size_t data_size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif

TEE_Result crypto_aes_expand_enc_key(const void *key __unused,
				     size_t key_len __unused,
				     void *enc_key __unused,
				     size_t enc_keylen __unused,
				     unsigned int *rounds __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_enc_block(const void *enc_key __unused,
			  size_t enc_keylen __unused,
			  unsigned int rounds __unused,
			  const void *src __unused, void *dst __unused)
{
}

/* Stubs for the crypto alloc ctx functions matching crypto_impl.h */
#undef CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED

#define CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(name, type) \
	TEE_Result \
	crypto_##name##_alloc_ctx(struct crypto_##type##_ctx **ctx __unused) \
	{ return TEE_ERROR_NOT_IMPLEMENTED; }

#if defined(CFG_CRYPTO_MD5)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(md5, hash)
#endif

#if defined(CFG_CRYPTO_SHA1)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha1, hash)
#endif

#if defined(CFG_CRYPTO_SHA224)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha224, hash)
#endif

#if defined(CFG_CRYPTO_SHA256)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha256, hash)
#endif

#if defined(CFG_CRYPTO_SHA384)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha384, hash)
#endif

#if defined(CFG_CRYPTO_SHA512)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha512, hash)
#endif

#if defined(CFG_CRYPTO_HMAC)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_md5, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha1, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha224, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha256, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha384, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha512, mac)
#endif

#if defined(CFG_CRYPTO_CMAC)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_cmac, mac)
#endif

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_ECB)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_ecb, cipher)
#endif

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_CBC)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_cbc, cipher)
#endif

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_CTR)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_ctr, cipher)
#endif

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_XTS)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_xts, cipher)
#endif

#if defined(CFG_CRYPTO_DES) && defined(CFG_CRYPTO_ECB)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des_ecb, cipher)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des3_ecb, cipher)
#endif

#if defined(CFG_CRYPTO_DES) && defined(CFG_CRYPTO_CBC)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des_cbc, cipher)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des3_cbc, cipher)
#endif

#if defined(CFG_CRYPTO_CCM)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_ccm, authenc)
#endif
