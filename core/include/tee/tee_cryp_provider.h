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

/*
 * This is the Cryptographic Provider API (CP API).
 *
 * This defines how most crypto syscalls that implement the Cryptographic
 * Operations API can invoke the actual providers of cryptographic algorithms
 * (such as LibTomCrypt).
 *
 * To add a new provider, you need to provide an implementation of this
 * interface.
 *
 * The following parameters are commonly used.
 *
 * @ctx: context allocated by the syscall, for later use by the algorithm
 * @algo: algorithm identifier (TEE_ALG_*)
 */


#ifndef TEE_CRYP_PROVIDER_H
#define TEE_CRYP_PROVIDER_H

#include <tee_api_types.h>

/* Message digest functions */
struct hash_ops {
	TEE_Result (*get_digest_size)(uint32_t algo, size_t *size);
	TEE_Result (*get_ctx_size)(uint32_t algo, size_t *size);
	TEE_Result (*init)(void *ctx, uint32_t algo);
	TEE_Result (*update)(void *ctx, uint32_t algo,
			     const uint8_t *data, size_t len);
	TEE_Result (*final)(void *ctx, uint32_t algo, uint8_t *digest,
			    size_t len);
	TEE_Result (*createdigest)(uint32_t algo, const uint8_t *data,
				   size_t datalen, uint8_t *digest,
				   size_t digestlen);
	TEE_Result (*check)(uint32_t algo, const uint8_t *hash,
			    size_t hash_size, const uint8_t *data,
			    size_t data_size);
};

/* Symmetric ciphers */
struct cipher_ops {
	TEE_Result (*get_ctx_size)(uint32_t algo, size_t *size);
	TEE_Result (*init)(void *ctx, uint32_t algo,
			    TEE_OperationMode mode,
			    const uint8_t *key1, size_t key1_len,
			    const uint8_t *key2, size_t key2_len,
			    const uint8_t *iv, size_t iv_len);
	TEE_Result (*update)(void *ctx, uint32_t algo,
			     TEE_OperationMode mode,
			     bool last_block, const uint8_t *data,
			     size_t len, uint8_t *dst);
	void       (*final)(void *ctx, uint32_t algo);
	TEE_Result (*get_block_size)(uint32_t algo, size_t *size);
};

/* Message Authentication Code functions */
struct mac_ops {
	TEE_Result (*get_digest_size)(uint32_t algo, size_t *size);
	TEE_Result (*get_ctx_size)(uint32_t algo, size_t *size);
	TEE_Result (*init)(void *ctx, uint32_t algo,
			   const uint8_t *key, size_t len);

	TEE_Result (*update)(void *ctx, uint32_t algo,
			     const uint8_t *data, size_t len);
	TEE_Result (*final)(void *ctx, uint32_t algo,
			    const uint8_t *data, size_t data_len,
			    uint8_t *digest, size_t digest_len);
};

/* Authenticated encryption */
struct authenc_ops {
	TEE_Result (*get_ctx_size)(uint32_t algo, size_t *size);
	TEE_Result (*init)(void *ctx, uint32_t algo,
			   const uint8_t *key, size_t key_len,
			   const uint8_t *nonce, size_t nonce_len,
			   size_t tag_len, size_t aad_len,
			   size_t payload_len);
	TEE_Result (*update_aad)(void *ctx, uint32_t algo,
				 const uint8_t *data, size_t len);
	TEE_Result (*update_payload)(void *ctx, uint32_t algo,
				     TEE_OperationMode mode,
				     const uint8_t *src_data,
				     size_t src_len,
				     uint8_t *dst_data);
	TEE_Result (*enc_final)(void *ctx, uint32_t algo,
				const uint8_t *src_data,
				size_t src_len, uint8_t *dst_data,
				uint8_t *dst_tag,
				size_t *dst_tag_len);
	TEE_Result (*dec_final)(void *ctx, uint32_t algo,
				const uint8_t *src_data,
				size_t src_len, uint8_t *dst_data,
				const uint8_t *tag, size_t tag_len);

	void       (*final)(void *ctx, uint32_t algo);
};

/* Implementation-defined big numbers */
typedef struct bignum bignum;
struct bignum_ops {
	/* Allocate a bignum of sufficient capacity for any key element */
	bignum *(*allocate)(void);
	TEE_Result (*bin2bn)(const uint8_t *from, size_t fromsize, bignum *to);
	size_t (*bin_size_for)(bignum *a);
	void (*bn2bin)(bignum *from, uint8_t *to);
	void (*copy)(bignum *to, const bignum *from);
	void (*free)(bignum *a);
	/*
	 * Pre-allocate a bignum of sufficient capacity for any key structure
	 * member. Supply this function if key generation can be implemented
	 * without dynamic allocations. Otherwise, it may be left NULL.
	 */
	bignum *(*preallocate)(void);
};

/* Asymmetric algorithms */

struct rsa_keypair_s {
	bignum *e;	/* Public exponent */
	bignum *d;	/* Private exponent */
	bignum *N;	/* Modulus */

	/* Optional CRT parameters (all NULL if unused) */
	bignum *p;	/* N = pq */
	bignum *q;
	bignum *qP;	/* 1/q mod p */
	bignum *dP;	/* d mod (p-1) */
	bignum *dQ;	/* d mod (q-1) */
};

struct rsa_public_key_s {
	bignum *e;	/* Public exponent */
	bignum *N;	/* Modulus */
};

struct dsa_keypair_s {
	bignum *g;	/* Generator of subgroup (public) */
	bignum *p;	/* Prime number (public) */
	bignum *q;	/* Order of subgroup (public) */
	bignum *y;	/* Public key */
	bignum *x;	/* Private key */
};

struct dsa_public_key_s {
	bignum *g;	/* Generator of subgroup (public) */
	bignum *p;	/* Prime number (public) */
	bignum *q;	/* Order of subgroup (public) */
	bignum *y;	/* Public key */
};

struct dh_keypair_s {
	bignum *g;	/* Generator of Z_p (shared) */
	bignum *p;	/* Prime modulus (shared) */
	bignum *x;	/* Private key */
	bignum *y;	/* Public key y = g^x */

	/*
	 * Optional parameters used by key generation.
	 * When not used, q == NULL and xbits == 0
	 */
	bignum *q;	/* x must be in the range [2, q-2] */
	uint32_t xbits;	/* Number of bits in the private key */
};

struct acipher_ops {

	/*
	 * Key generation functions
	 * Called by TEE after setting each member of @key to the return
	 * value of bignum_ops.preallocate() if preallocate != NULL.
	 * If possible, you should allocate memory only in preallocate() and
	 * not during key generation, because allocation failures in gen_*_key
	 * will make the TA panic.
	 */
	TEE_Result (*gen_rsa_key)(struct rsa_keypair_s *key, size_t key_size);
	TEE_Result (*gen_dsa_key)(struct dsa_keypair_s *key, size_t key_size);
	TEE_Result (*gen_dh_key)(struct dh_keypair_s *key, bignum *q, size_t xbits);

	TEE_Result (*rsanopad_decrypt)(struct rsa_keypair_s *key,
				       const uint8_t *src, size_t src_len,
				       uint8_t *dst, size_t *dst_len);
	TEE_Result (*rsanopad_encrypt)(struct rsa_public_key_s *key,
				       const uint8_t *src, size_t src_len,
				       uint8_t *dst, size_t *dst_len);
	TEE_Result (*rsaes_decrypt)(uint32_t algo, struct rsa_keypair_s *key,
					const uint8_t *label,
					size_t label_len,
					const uint8_t *src,
					size_t src_len, uint8_t *dst,
					size_t *dst_len);
	TEE_Result (*rsaes_encrypt)(uint32_t algo, struct rsa_public_key_s *key,
					const uint8_t *label,
					size_t label_len,
					const uint8_t *src,
					size_t src_len, uint8_t *dst,
					size_t *dst_len);
	/* RSA SSA sign/verify: if salt_len == -1, use default value */
	TEE_Result (*rsassa_sign)(uint32_t algo, struct rsa_keypair_s *key,
				      int salt_len, const uint8_t *msg,
				      size_t msg_len, uint8_t *sig,
				      size_t *sig_len);
	TEE_Result (*rsassa_verify)(uint32_t algo, struct rsa_public_key_s *key,
					int salt_len, const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len);
	TEE_Result (*dsa_sign)(uint32_t algo, struct dsa_keypair_s *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len);
	TEE_Result (*dsa_verify)(uint32_t algo, struct dsa_public_key_s *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len);
};

/* Key derivation */
struct derive_ops {
	TEE_Result (*dh_shared_secret)(struct dh_keypair_s *private_key,
					   bignum *public_key,
					   bignum *secret);
	size_t (*dh_size)(bignum *private_key);
};

/* Random data generation */
struct rng_ops {
	TEE_Result (*get_rng_array)(void *buffer, int len);
};

/* Cryptographic Provider API */
struct crypto_ops {
	/* Human-readable provider name */
	const char *name;
	TEE_Result (*init)(void);

	struct hash_ops hash;
	struct cipher_ops cipher;
	struct mac_ops mac;
	struct authenc_ops authenc;
	struct acipher_ops acipher;
	struct derive_ops derive;
	struct rng_ops rng;
	struct bignum_ops bignum;
};

extern struct crypto_ops crypto_ops;

TEE_Result tee_cryp_init(void);

#endif /* TEE_CRYP_PROVIDER_H */
