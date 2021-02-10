// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 * Copyright 2020 NXP
 * Copyright 2021, SumUp Service GmbH
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <stdlib.h>
#include <string.h>
#include <utee_defines.h>

TEE_Result crypto_hash_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result res = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_hash_ctx *c = NULL;

	/*
	 * Use default cryptographic implementation if no matching
	 * drvcrypt device.
	 */
	res = drvcrypt_hash_alloc_ctx(&c, algo);

	if (res == TEE_ERROR_NOT_IMPLEMENTED) {
		switch (algo) {
		case TEE_ALG_MD5:
			res = crypto_md5_alloc_ctx(&c);
			break;
		case TEE_ALG_SHA1:
			res = crypto_sha1_alloc_ctx(&c);
			break;
		case TEE_ALG_SHA224:
			res = crypto_sha224_alloc_ctx(&c);
			break;
		case TEE_ALG_SHA256:
			res = crypto_sha256_alloc_ctx(&c);
			break;
		case TEE_ALG_SHA384:
			res = crypto_sha384_alloc_ctx(&c);
			break;
		case TEE_ALG_SHA512:
			res = crypto_sha512_alloc_ctx(&c);
			break;
		case TEE_ALG_SM3:
			res = crypto_sm3_alloc_ctx(&c);
			break;
		default:
			break;
		}
	}

	if (!res)
		*ctx = c;

	return res;
}

static const struct crypto_hash_ops *hash_ops(void *ctx)
{
	struct crypto_hash_ctx *c = ctx;

	assert(c && c->ops);

	return c->ops;
}

void crypto_hash_free_ctx(void *ctx)
{
	if (ctx)
		hash_ops(ctx)->free_ctx(ctx);
}

void crypto_hash_copy_state(void *dst_ctx, void *src_ctx)
{
	hash_ops(dst_ctx)->copy_state(dst_ctx, src_ctx);
}

TEE_Result crypto_hash_init(void *ctx)
{
	return hash_ops(ctx)->init(ctx);
}

TEE_Result crypto_hash_update(void *ctx, const uint8_t *data, size_t len)
{
	return hash_ops(ctx)->update(ctx, data, len);
}

TEE_Result crypto_hash_final(void *ctx, uint8_t *digest, size_t len)
{
	return hash_ops(ctx)->final(ctx, digest, len);
}

TEE_Result crypto_cipher_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result res = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_cipher_ctx *c = NULL;

	/*
	 * Use default cryptographic implementation if no matching
	 * drvcrypt device.
	 */
	res = drvcrypt_cipher_alloc_ctx(&c, algo);

	if (res == TEE_ERROR_NOT_IMPLEMENTED) {
		switch (algo) {
		case TEE_ALG_AES_ECB_NOPAD:
			res = crypto_aes_ecb_alloc_ctx(&c);
			break;
		case TEE_ALG_AES_CBC_NOPAD:
			res = crypto_aes_cbc_alloc_ctx(&c);
			break;
		case TEE_ALG_AES_CTR:
			res = crypto_aes_ctr_alloc_ctx(&c);
			break;
		case TEE_ALG_AES_CTS:
			res = crypto_aes_cts_alloc_ctx(&c);
			break;
		case TEE_ALG_AES_XTS:
			res = crypto_aes_xts_alloc_ctx(&c);
			break;
		case TEE_ALG_DES_ECB_NOPAD:
			res = crypto_des_ecb_alloc_ctx(&c);
			break;
		case TEE_ALG_DES3_ECB_NOPAD:
			res = crypto_des3_ecb_alloc_ctx(&c);
			break;
		case TEE_ALG_DES_CBC_NOPAD:
			res = crypto_des_cbc_alloc_ctx(&c);
			break;
		case TEE_ALG_DES3_CBC_NOPAD:
			res = crypto_des3_cbc_alloc_ctx(&c);
			break;
		case TEE_ALG_SM4_ECB_NOPAD:
			res = crypto_sm4_ecb_alloc_ctx(&c);
			break;
		case TEE_ALG_SM4_CBC_NOPAD:
			res = crypto_sm4_cbc_alloc_ctx(&c);
			break;
		case TEE_ALG_SM4_CTR:
			res = crypto_sm4_ctr_alloc_ctx(&c);
			break;
		default:
			return TEE_ERROR_NOT_IMPLEMENTED;
		}
	}

	if (!res)
		*ctx = c;

	return res;
}

static const struct crypto_cipher_ops *cipher_ops(void *ctx)
{
	struct crypto_cipher_ctx *c = ctx;

	assert(c && c->ops);

	return c->ops;
}

void crypto_cipher_free_ctx(void *ctx)
{
	if (ctx)
		cipher_ops(ctx)->free_ctx(ctx);
}

void crypto_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	cipher_ops(dst_ctx)->copy_state(dst_ctx, src_ctx);
}

TEE_Result crypto_cipher_init(void *ctx, TEE_OperationMode mode,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2, size_t key2_len,
			      const uint8_t *iv, size_t iv_len)
{
	if (mode != TEE_MODE_DECRYPT && mode != TEE_MODE_ENCRYPT)
		return TEE_ERROR_BAD_PARAMETERS;

	return cipher_ops(ctx)->init(ctx, mode, key1, key1_len, key2, key2_len,
				     iv, iv_len);
}

TEE_Result crypto_cipher_update(void *ctx, TEE_OperationMode mode __unused,
				bool last_block, const uint8_t *data,
				size_t len, uint8_t *dst)
{
	return cipher_ops(ctx)->update(ctx, last_block, data, len, dst);
}

void crypto_cipher_final(void *ctx)
{
	cipher_ops(ctx)->final(ctx);
}

TEE_Result crypto_cipher_get_block_size(uint32_t algo, size_t *size)
{
	uint32_t class = TEE_ALG_GET_CLASS(algo);

	if (class != TEE_OPERATION_CIPHER && class != TEE_OPERATION_MAC &&
	    class != TEE_OPERATION_AE)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (TEE_ALG_GET_MAIN_ALG(algo)) {
	case TEE_MAIN_ALGO_AES:
		*size = TEE_AES_BLOCK_SIZE;
		return TEE_SUCCESS;
	case TEE_MAIN_ALGO_DES:
	case TEE_MAIN_ALGO_DES3:
		*size = TEE_DES_BLOCK_SIZE;
		return TEE_SUCCESS;
	case TEE_MAIN_ALGO_SM4:
		*size = TEE_SM4_BLOCK_SIZE;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result crypto_mac_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result res = TEE_SUCCESS;
	struct crypto_mac_ctx *c = NULL;

	/*
	 * Use default cryptographic implementation if no matching
	 * drvcrypt device.
	 */
	res = drvcrypt_mac_alloc_ctx(&c, algo);

	if (res == TEE_ERROR_NOT_IMPLEMENTED) {
		switch (algo) {
		case TEE_ALG_HMAC_MD5:
			res = crypto_hmac_md5_alloc_ctx(&c);
			break;
		case TEE_ALG_HMAC_SHA1:
			res = crypto_hmac_sha1_alloc_ctx(&c);
			break;
		case TEE_ALG_HMAC_SHA224:
			res = crypto_hmac_sha224_alloc_ctx(&c);
			break;
		case TEE_ALG_HMAC_SHA256:
			res = crypto_hmac_sha256_alloc_ctx(&c);
			break;
		case TEE_ALG_HMAC_SHA384:
			res = crypto_hmac_sha384_alloc_ctx(&c);
			break;
		case TEE_ALG_HMAC_SHA512:
			res = crypto_hmac_sha512_alloc_ctx(&c);
			break;
		case TEE_ALG_HMAC_SM3:
			res = crypto_hmac_sm3_alloc_ctx(&c);
			break;
		case TEE_ALG_AES_CBC_MAC_NOPAD:
			res = crypto_aes_cbc_mac_nopad_alloc_ctx(&c);
			break;
		case TEE_ALG_AES_CBC_MAC_PKCS5:
			res = crypto_aes_cbc_mac_pkcs5_alloc_ctx(&c);
			break;
		case TEE_ALG_DES_CBC_MAC_NOPAD:
			res = crypto_des_cbc_mac_nopad_alloc_ctx(&c);
			break;
		case TEE_ALG_DES_CBC_MAC_PKCS5:
			res = crypto_des_cbc_mac_pkcs5_alloc_ctx(&c);
			break;
		case TEE_ALG_DES3_CBC_MAC_NOPAD:
			res = crypto_des3_cbc_mac_nopad_alloc_ctx(&c);
			break;
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			res = crypto_des3_cbc_mac_pkcs5_alloc_ctx(&c);
			break;
		case TEE_ALG_DES3_CMAC:
			res = crypto_des3_cmac_alloc_ctx(&c);
			break;
		case TEE_ALG_AES_CMAC:
			res = crypto_aes_cmac_alloc_ctx(&c);
			break;
		default:
			return TEE_ERROR_NOT_SUPPORTED;
		}
	}

	if (!res)
		*ctx = c;

	return res;
}

static const struct crypto_mac_ops *mac_ops(void *ctx)
{
	struct crypto_mac_ctx *c = ctx;

	assert(c && c->ops);

	return c->ops;
}

void crypto_mac_free_ctx(void *ctx)
{
	if (ctx)
		mac_ops(ctx)->free_ctx(ctx);
}

void crypto_mac_copy_state(void *dst_ctx, void *src_ctx)
{
	mac_ops(dst_ctx)->copy_state(dst_ctx, src_ctx);
}

TEE_Result crypto_mac_init(void *ctx, const uint8_t *key, size_t len)
{
	return mac_ops(ctx)->init(ctx, key, len);
}

TEE_Result crypto_mac_update(void *ctx, const uint8_t *data, size_t len)
{
	if (!len)
		return TEE_SUCCESS;

	return mac_ops(ctx)->update(ctx, data, len);
}

TEE_Result crypto_mac_final(void *ctx, uint8_t *digest, size_t digest_len)
{
	return mac_ops(ctx)->final(ctx, digest, digest_len);
}

TEE_Result crypto_authenc_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result res = TEE_SUCCESS;
	struct crypto_authenc_ctx *c = NULL;

	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		res = crypto_aes_ccm_alloc_ctx(&c);
		break;
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		res = crypto_aes_gcm_alloc_ctx(&c);
		break;
#endif
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (!res)
		*ctx = c;

	return res;
}

static const struct crypto_authenc_ops *ae_ops(void *ctx)
{
	struct crypto_authenc_ctx *c = ctx;

	assert(c && c->ops);

	return c->ops;
}

TEE_Result crypto_authenc_init(void *ctx, TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len)
{
	return ae_ops(ctx)->init(ctx, mode, key, key_len, nonce, nonce_len,
				 tag_len, aad_len, payload_len);
}

TEE_Result crypto_authenc_update_aad(void *ctx, TEE_OperationMode mode __unused,
				     const uint8_t *data, size_t len)
{
	return ae_ops(ctx)->update_aad(ctx, data, len);
}


TEE_Result crypto_authenc_update_payload(void *ctx, TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t src_len, uint8_t *dst_data,
					 size_t *dst_len)
{
	if (*dst_len < src_len)
		return TEE_ERROR_SHORT_BUFFER;
	*dst_len = src_len;

	return ae_ops(ctx)->update_payload(ctx, mode, src_data, src_len,
					   dst_data);
}

TEE_Result crypto_authenc_enc_final(void *ctx, const uint8_t *src_data,
				    size_t src_len, uint8_t *dst_data,
				    size_t *dst_len, uint8_t *dst_tag,
				    size_t *dst_tag_len)
{
	if (*dst_len < src_len)
		return TEE_ERROR_SHORT_BUFFER;
	*dst_len = src_len;

	return ae_ops(ctx)->enc_final(ctx, src_data, src_len, dst_data,
				      dst_tag, dst_tag_len);
}

TEE_Result crypto_authenc_dec_final(void *ctx, const uint8_t *src_data,
				    size_t src_len, uint8_t *dst_data,
				    size_t *dst_len, const uint8_t *tag,
				    size_t tag_len)
{
	if (*dst_len < src_len)
		return TEE_ERROR_SHORT_BUFFER;
	*dst_len = src_len;

	return ae_ops(ctx)->dec_final(ctx, src_data, src_len, dst_data, tag,
				      tag_len);
}

void crypto_authenc_final(void *ctx)
{
	ae_ops(ctx)->final(ctx);
}

void crypto_authenc_free_ctx(void *ctx)
{
	if (ctx)
		ae_ops(ctx)->free_ctx(ctx);
}

void crypto_authenc_copy_state(void *dst_ctx, void *src_ctx)
{
	ae_ops(dst_ctx)->copy_state(dst_ctx, src_ctx);
}

#if !defined(CFG_CRYPTO_RSA) && !defined(CFG_CRYPTO_DSA) && \
    !defined(CFG_CRYPTO_DH) && !defined(CFG_CRYPTO_ECC)
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
#endif

#if !defined(CFG_CRYPTO_RSA)
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

void crypto_acipher_free_rsa_keypair(struct rsa_keypair *s __unused)
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
#endif /*!CFG_CRYPTO_RSA*/

#if !defined(CFG_CRYPTO_DSA)
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
#endif /*!CFG_CRYPTO_DSA*/

#if !defined(CFG_CRYPTO_DH)
TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s __unused,
					   size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key __unused,
				     struct bignum *q __unused,
				     size_t xbits __unused,
				     size_t key_size __unused)
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
#endif /*!CFG_CRYPTO_DH*/

TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *key,
					       uint32_t key_type,
					       size_t key_size_bits)
{
	TEE_Result res = TEE_ERROR_NOT_IMPLEMENTED;

	/*
	 * Use default cryptographic implementation if no matching
	 * drvcrypt device.
	 */
	res = drvcrypt_asym_alloc_ecc_public_key(key, key_type, key_size_bits);
	if (res == TEE_ERROR_NOT_IMPLEMENTED)
		res = crypto_asym_alloc_ecc_public_key(key, key_type,
						       key_size_bits);

	return res;
}

TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *key,
					    uint32_t key_type,
					    size_t key_size_bits)
{
	TEE_Result res = TEE_ERROR_NOT_IMPLEMENTED;

	/*
	 * Use default cryptographic implementation if no matching
	 * drvcrypt device.
	 */
	res = drvcrypt_asym_alloc_ecc_keypair(key, key_type, key_size_bits);
	if (res == TEE_ERROR_NOT_IMPLEMENTED)
		res = crypto_asym_alloc_ecc_keypair(key, key_type,
						    key_size_bits);

	return res;
}

void crypto_acipher_free_ecc_public_key(struct ecc_public_key *key)
{
	assert(key->ops && key->ops->free);

	key->ops->free(key);
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key,
				      size_t key_size_bits)
{
	assert(key->ops && key->ops->generate);

	return key->ops->generate(key, key_size_bits);
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	assert(key->ops);

	if (!key->ops->sign)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return key->ops->sign(algo, key, msg, msg_len, sig, sig_len);
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	assert(key->ops);

	if (!key->ops->verify)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return key->ops->verify(algo, key, msg, msg_len, sig, sig_len);
}

TEE_Result crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
					    struct ecc_public_key *public_key,
					    void *secret,
					    unsigned long *secret_len)
{
	assert(private_key->ops);

	if (!private_key->ops->shared_secret)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return private_key->ops->shared_secret(private_key, public_key, secret,
					       secret_len);
}

TEE_Result crypto_acipher_sm2_pke_decrypt(struct ecc_keypair *key,
					  const uint8_t *src, size_t src_len,
					  uint8_t *dst, size_t *dst_len)
{
	assert(key->ops);

	if (!key->ops->decrypt)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return key->ops->decrypt(key, src, src_len, dst, dst_len);
}

TEE_Result crypto_acipher_sm2_pke_encrypt(struct ecc_public_key *key,
					  const uint8_t *src, size_t src_len,
					  uint8_t *dst, size_t *dst_len)
{
	assert(key->ops);

	if (!key->ops->encrypt)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return key->ops->encrypt(key, src, src_len, dst, dst_len);
}

#if !defined(CFG_CRYPTO_SM2_KEP)
TEE_Result crypto_acipher_sm2_kep_derive(struct ecc_keypair *my_key __unused,
					 struct ecc_keypair *my_eph_key
								__unused,
					 struct ecc_public_key *peer_key
								__unused,
					 struct ecc_public_key *peer_eph_key
								__unused,
					 struct sm2_kep_parms *p __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif

__weak void crypto_storage_obj_del(uint8_t *data __unused, size_t len __unused)
{
}
