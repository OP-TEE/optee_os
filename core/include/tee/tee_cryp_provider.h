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
	TEE_Result (*get_ctx_size)(uint32_t algo, size_t *size);
	TEE_Result (*init)(void *ctx, uint32_t algo);
	TEE_Result (*update)(void *ctx, uint32_t algo,
			     const uint8_t *data, size_t len);
	TEE_Result (*final)(void *ctx, uint32_t algo, uint8_t *digest,
			    size_t len);
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
	TEE_Result (*get_ctx_size)(uint32_t algo, size_t *size);
	TEE_Result (*init)(void *ctx, uint32_t algo,
			   const uint8_t *key, size_t len);
	TEE_Result (*update)(void *ctx, uint32_t algo,
			     const uint8_t *data, size_t len);
	TEE_Result (*final)(void *ctx, uint32_t algo,
			    uint8_t *digest, size_t digest_len);
};

/* Authenticated encryption */
struct authenc_ops {
	TEE_Result (*get_ctx_size)(uint32_t algo, size_t *size);
	TEE_Result (*init)(void *ctx, uint32_t algo,
			   TEE_OperationMode mode,
			   const uint8_t *key, size_t key_len,
			   const uint8_t *nonce, size_t nonce_len,
			   size_t tag_len, size_t aad_len,
			   size_t payload_len);
	TEE_Result (*update_aad)(void *ctx, uint32_t algo,
				 TEE_OperationMode mode,
				 const uint8_t *data, size_t len);
	TEE_Result (*update_payload)(void *ctx, uint32_t algo,
				     TEE_OperationMode mode,
				     const uint8_t *src_data,
				     size_t src_len,
				     uint8_t *dst_data,
				     size_t *dst_len);
	TEE_Result (*enc_final)(void *ctx, uint32_t algo,
				const uint8_t *src_data,
				size_t src_len, uint8_t *dst_data,
				size_t *dst_len, uint8_t *dst_tag,
				size_t *dst_tag_len);
	TEE_Result (*dec_final)(void *ctx, uint32_t algo,
				const uint8_t *src_data,
				size_t src_len, uint8_t *dst_data,
				size_t *dst_len, const uint8_t *tag,
				size_t tag_len);

	void       (*final)(void *ctx, uint32_t algo);
};

/* Implementation-defined big numbers */
struct bignum_ops {
	/*
	 * Allocate a bignum capable of holding an unsigned integer value of
	 * up to bitsize bits
	 */
	struct bignum *(*allocate)(size_t size_bits);
	TEE_Result (*bin2bn)(const uint8_t *from, size_t fromsize,
			     struct bignum *to);
	size_t (*num_bytes)(struct bignum *a);
	void (*bn2bin)(const struct bignum *from, uint8_t *to);
	void (*copy)(struct bignum *to, const struct bignum *from);
	void (*free)(struct bignum *a);
	void (*clear)(struct bignum *a);
};

/* Asymmetric algorithms */

struct rsa_keypair {
	struct bignum *e;	/* Public exponent */
	struct bignum *d;	/* Private exponent */
	struct bignum *n;	/* Modulus */

	/* Optional CRT parameters (all NULL if unused) */
	struct bignum *p;	/* N = pq */
	struct bignum *q;
	struct bignum *qp;	/* 1/q mod p */
	struct bignum *dp;	/* d mod (p-1) */
	struct bignum *dq;	/* d mod (q-1) */
};

struct rsa_public_key {
	struct bignum *e;	/* Public exponent */
	struct bignum *n;	/* Modulus */
};

struct dsa_keypair {
	struct bignum *g;	/* Generator of subgroup (public) */
	struct bignum *p;	/* Prime number (public) */
	struct bignum *q;	/* Order of subgroup (public) */
	struct bignum *y;	/* Public key */
	struct bignum *x;	/* Private key */
};

struct dsa_public_key {
	struct bignum *g;	/* Generator of subgroup (public) */
	struct bignum *p;	/* Prime number (public) */
	struct bignum *q;	/* Order of subgroup (public) */
	struct bignum *y;	/* Public key */
};

struct dh_keypair {
	struct bignum *g;	/* Generator of Z_p (shared) */
	struct bignum *p;	/* Prime modulus (shared) */
	struct bignum *x;	/* Private key */
	struct bignum *y;	/* Public key y = g^x */

	/*
	 * Optional parameters used by key generation.
	 * When not used, q == NULL and xbits == 0
	 */
	struct bignum *q;	/* x must be in the range [2, q-2] */
	uint32_t xbits;		/* Number of bits in the private key */
};

struct acipher_ops {

	/*
	 * Key allocation functions
	 * Allocate the bignum's inside a key structure.
	 * TEE core will later use bignum.free().
	 */
	TEE_Result (*alloc_rsa_keypair)(struct rsa_keypair *s,
					size_t key_size_bits);
	TEE_Result (*alloc_rsa_public_key)(struct rsa_public_key *s,
					   size_t key_size_bits);
	TEE_Result (*alloc_dsa_keypair)(struct dsa_keypair *s,
					size_t key_size_bits);
	TEE_Result (*alloc_dsa_public_key)(struct dsa_public_key *s,
					   size_t key_size_bits);
	TEE_Result (*alloc_dh_keypair)(struct dh_keypair *s,
				       size_t key_size_bits);

	/*
	 * Key generation functions
	 */
	TEE_Result (*gen_rsa_key)(struct rsa_keypair *key, size_t key_size);
	TEE_Result (*gen_dsa_key)(struct dsa_keypair *key, size_t key_size);
	TEE_Result (*gen_dh_key)(struct dh_keypair *key, struct bignum *q,
				 size_t xbits);
	TEE_Result (*dh_shared_secret)(struct dh_keypair *private_key,
				       struct bignum *public_key,
				       struct bignum *secret);

	TEE_Result (*rsanopad_decrypt)(struct rsa_keypair *key,
				       const uint8_t *src, size_t src_len,
				       uint8_t *dst, size_t *dst_len);
	TEE_Result (*rsanopad_encrypt)(struct rsa_public_key *key,
				       const uint8_t *src, size_t src_len,
				       uint8_t *dst, size_t *dst_len);
	TEE_Result (*rsaes_decrypt)(uint32_t algo, struct rsa_keypair *key,
				    const uint8_t *label, size_t label_len,
				    const uint8_t *src, size_t src_len,
				    uint8_t *dst, size_t *dst_len);
	TEE_Result (*rsaes_encrypt)(uint32_t algo,
				    struct rsa_public_key *key,
				    const uint8_t *label, size_t label_len,
				    const uint8_t *src, size_t src_len,
				    uint8_t *dst, size_t *dst_len);
	/* RSA SSA sign/verify: if salt_len == -1, use default value */
	TEE_Result (*rsassa_sign)(uint32_t algo, struct rsa_keypair *key,
				  int salt_len, const uint8_t *msg,
				  size_t msg_len, uint8_t *sig,
				  size_t *sig_len);
	TEE_Result (*rsassa_verify)(uint32_t algo,
				    struct rsa_public_key *key,
				    int salt_len, const uint8_t *msg,
				    size_t msg_len, const uint8_t *sig,
				    size_t sig_len);
	TEE_Result (*dsa_sign)(uint32_t algo, struct dsa_keypair *key,
			       const uint8_t *msg, size_t msg_len,
			       uint8_t *sig, size_t *sig_len);
	TEE_Result (*dsa_verify)(uint32_t algo, struct dsa_public_key *key,
				 const uint8_t *msg, size_t msg_len,
				 const uint8_t *sig, size_t sig_len);
};

/* Encode/Decode operations */

struct codec_ops {
	TEE_Result (*base64_encode)(const uint8_t *in, uint32_t inlen,
				 uint8_t *out, uint32_t *outlen);
	TEE_Result (*base64_decode)(const uint8_t *in,  uint32_t inlen,
				 uint8_t *out, uint32_t *outlen);
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
	struct codec_ops codec;
	struct bignum_ops bignum;
};

extern struct crypto_ops crypto_ops;

TEE_Result tee_cryp_init(void);

/*
 * Verifies a SHA-256 hash, doesn't require tee_cryp_init() to be called in
 * advance and has as few dependencies as possible.
 *
 * This function is primarily used by pager and early initialization code
 * where the complete crypto library isn't available.
 */
TEE_Result hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size);

#endif /* TEE_CRYP_PROVIDER_H */
