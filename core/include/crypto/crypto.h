/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2017, Linaro Limited
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

#ifndef __CRYPTO_CRYPTO_H
#define __CRYPTO_CRYPTO_H

#include <tee/tee_obj.h>
#include <tee_api_types.h>

TEE_Result crypto_init(void);

/* Message digest functions */
TEE_Result crypto_hash_alloc_ctx(void **ctx, uint32_t algo);
TEE_Result crypto_hash_init(void *ctx);
TEE_Result crypto_hash_update(void *ctx, const uint8_t *data, size_t len);
TEE_Result crypto_hash_final(void *ctx, uint8_t *digest, size_t len);
void crypto_hash_free_ctx(void *ctx);
void crypto_hash_copy_state(void *dst_ctx, void *src_ctx);

/* Symmetric ciphers */
TEE_Result crypto_cipher_alloc_ctx(void **ctx, uint32_t algo);
TEE_Result crypto_cipher_init(void *ctx, TEE_OperationMode mode,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2, size_t key2_len,
			      const uint8_t *iv, size_t iv_len);
TEE_Result crypto_cipher_update(void *ctx, TEE_OperationMode mode,
				bool last_block, const uint8_t *data,
				size_t len, uint8_t *dst);
void crypto_cipher_final(void *ctx);
TEE_Result crypto_cipher_get_block_size(uint32_t algo, size_t *size);
void crypto_cipher_free_ctx(void *ctx);
void crypto_cipher_copy_state(void *dst_ctx, void *src_ctx);

/* Message Authentication Code functions */
TEE_Result crypto_mac_alloc_ctx(void **ctx, uint32_t algo);
TEE_Result crypto_mac_init(void *ctx, const uint8_t *key, size_t len);
TEE_Result crypto_mac_update(void *ctx, const uint8_t *data, size_t len);
TEE_Result crypto_mac_final(void *ctx, uint8_t *digest, size_t digest_len);
void crypto_mac_free_ctx(void *ctx);
void crypto_mac_copy_state(void *dst_ctx, void *src_ctx);

/* Authenticated encryption */
TEE_Result crypto_authenc_alloc_ctx(void **ctx, uint32_t algo);
TEE_Result crypto_authenc_init(void *ctx, TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len);
TEE_Result crypto_authenc_update_aad(void *ctx, TEE_OperationMode mode,
				     const uint8_t *data, size_t len);
TEE_Result crypto_authenc_update_payload(void *ctx, TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t src_len, uint8_t *dst_data,
					 size_t *dst_len);
TEE_Result crypto_authenc_enc_final(void *ctx, const uint8_t *src_data,
				    size_t src_len, uint8_t *dst_data,
				    size_t *dst_len, uint8_t *dst_tag,
				    size_t *dst_tag_len);
TEE_Result crypto_authenc_dec_final(void *ctx, const uint8_t *src_data,
				    size_t src_len, uint8_t *dst_data,
				    size_t *dst_len, const uint8_t *tag,
				    size_t tag_len);
void crypto_authenc_final(void *ctx);
void crypto_authenc_free_ctx(void *ctx);
void crypto_authenc_copy_state(void *dst_ctx, void *src_ctx);

/* Informs crypto that the data in the buffer will be removed from storage */
TEE_Result crypto_storage_obj_del(struct tee_obj *obj);

/* Implementation-defined big numbers */

/*
 * Allocate a bignum capable of holding an unsigned integer value of
 * up to bitsize bits
 */
struct bignum *crypto_bignum_allocate(size_t size_bits);
TEE_Result crypto_bignum_bin2bn(const uint8_t *from, size_t fromsize,
				struct bignum *to);
size_t crypto_bignum_num_bytes(struct bignum *a);
size_t crypto_bignum_num_bits(struct bignum *a);
void crypto_bignum_bn2bin(const struct bignum *from, uint8_t *to);
void crypto_bignum_copy(struct bignum *to, const struct bignum *from);
void crypto_bignum_free(struct bignum *a);
void crypto_bignum_clear(struct bignum *a);

/* return -1 if a<b, 0 if a==b, +1 if a>b */
int32_t crypto_bignum_compare(struct bignum *a, struct bignum *b);

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

struct ecc_public_key {
	struct bignum *x;	/* Public value x */
	struct bignum *y;	/* Public value y */
	uint32_t curve;	        /* Curve type */
	const struct crypto_ecc_public_ops *ops; /* Key Operations */
};

struct ecc_keypair {
	struct bignum *d;	/* Private value */
	struct bignum *x;	/* Public value x */
	struct bignum *y;	/* Public value y */
	uint32_t curve;	        /* Curve type */
	const struct crypto_ecc_keypair_ops *ops; /* Key Operations */
};

struct x25519_keypair {
	uint8_t *priv;	/* Private value */
	uint8_t *pub;	/* Public value */
};

struct ed25519_keypair {
	uint8_t *priv;
	uint8_t *pub;
	uint32_t curve;
};

/*
 * Key allocation functions
 * Allocate the bignum's inside a key structure.
 * TEE core will later use crypto_bignum_free().
 */
TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s,
				size_t key_size_bits);
TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s,
				   size_t key_size_bits);
void crypto_acipher_free_rsa_public_key(struct rsa_public_key *s);
void crypto_acipher_free_rsa_keypair(struct rsa_keypair *s);
TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *s,
				size_t key_size_bits);
TEE_Result crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *s,
				   size_t key_size_bits);
TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s,
			       size_t key_size_bits);
TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s,
					       uint32_t key_type,
					       size_t key_size_bits);
TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s,
					    uint32_t key_type,
					    size_t key_size_bits);
void crypto_acipher_free_ecc_public_key(struct ecc_public_key *s);
TEE_Result crypto_acipher_alloc_x25519_keypair(struct x25519_keypair *s,
					       size_t key_size_bits);
TEE_Result crypto_acipher_alloc_ed25519_keypair(struct ed25519_keypair *s,
						size_t key_size_bits);

/*
 * Key generation functions
 */
TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t key_size);
TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key, size_t key_size);
TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key, struct bignum *q,
				     size_t xbits, size_t key_size);
TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key, size_t key_size);
TEE_Result crypto_acipher_gen_x25519_key(struct x25519_keypair *key,
					 size_t key_size);
TEE_Result crypto_acipher_gen_ed25519_key(struct ed25519_keypair *key,
					  size_t key_size);
TEE_Result crypto_acipher_ed25519_sign(struct ed25519_keypair *key,
				       const uint8_t *msg, size_t msg_len,
				       uint8_t *sig, size_t *sig_len);
TEE_Result crypto_acipher_ed25519ctx_sign(struct ed25519_keypair *key,
					  const uint8_t *msg, size_t msg_len,
					  uint8_t *sig, size_t *sig_len,
					  bool ph_flag,
					  const uint8_t *ctx, size_t ctxlen);
TEE_Result crypto_acipher_ed25519_verify(struct ed25519_keypair *key,
					 const uint8_t *msg, size_t msg_len,
					 const uint8_t *sig, size_t sig_len);
TEE_Result crypto_acipher_ed25519ctx_verify(struct ed25519_keypair *key,
					    const uint8_t *msg, size_t msg_len,
					    const uint8_t *sig, size_t sig_len,
					    bool ph_flag,
					    const uint8_t *ctx, size_t ctxlen);

TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *public_key,
					   struct bignum *secret);

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len);
TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len);
TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len);
TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len);
/* RSA SSA sign/verify: if salt_len == -1, use default value */
TEE_Result crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
				      int salt_len, const uint8_t *msg,
				      size_t msg_len, uint8_t *sig,
				      size_t *sig_len);
TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len, const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len);
TEE_Result crypto_acipher_dsa_sign(uint32_t algo, struct dsa_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len);
TEE_Result crypto_acipher_dsa_verify(uint32_t algo, struct dsa_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len);
TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len);
TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len);
TEE_Result crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
					    struct ecc_public_key *public_key,
					    void *secret,
					    unsigned long *secret_len);
TEE_Result crypto_acipher_sm2_pke_decrypt(struct ecc_keypair *key,
					  const uint8_t *src, size_t src_len,
					  uint8_t *dst, size_t *dst_len);
TEE_Result crypto_acipher_sm2_pke_encrypt(struct ecc_public_key *key,
					  const uint8_t *src, size_t src_len,
					  uint8_t *dst, size_t *dst_len);
TEE_Result crypto_acipher_x25519_shared_secret(struct x25519_keypair
					       *private_key,
					       void *public_key, void *secret,
					       unsigned long *secret_len);

struct sm2_kep_parms {
	uint8_t *out;
	size_t out_len;
	bool is_initiator;
	const uint8_t *initiator_id;
	size_t initiator_id_len;
	const uint8_t *responder_id;
	size_t responder_id_len;
	const uint8_t *conf_in;
	size_t conf_in_len;
	uint8_t *conf_out;
	size_t conf_out_len;
};

TEE_Result crypto_acipher_sm2_kep_derive(struct ecc_keypair *my_key,
					 struct ecc_keypair *my_eph_key,
					 struct ecc_public_key *peer_key,
					 struct ecc_public_key *peer_eph_key,
					 struct sm2_kep_parms *p);

/*
 * Verifies a SHA-256 hash, doesn't require crypto_init() to be called in
 * advance and has as few dependencies as possible.
 *
 * This function is primarily used by pager and early initialization code
 * where the complete crypto library isn't available.
 */
TEE_Result hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size);

/*
 * Computes a SHA-512/256 hash, vetted conditioner as per NIST.SP.800-90B.
 * It doesn't require crypto_init() to be called in advance and has as few
 * dependencies as possible.
 *
 * This function could be used inside interrupt context where the crypto
 * library can't be used due to mutex handling.
 */
TEE_Result hash_sha512_256_compute(uint8_t *digest, const uint8_t *data,
		size_t data_size);

#define CRYPTO_RNG_SRC_IS_QUICK(sid) (!!((sid) & 1))

/*
 * enum crypto_rng_src - RNG entropy source
 *
 * Identifiers for different RNG entropy sources. The lowest bit indicates
 * if the source is to be merely queued (bit is 1) or if it's delivered
 * directly to the pool. The difference is that in the latter case RPC to
 * normal world can be performed and in the former it must not.
 */
enum crypto_rng_src {
	CRYPTO_RNG_SRC_JITTER_SESSION	= (0 << 1 | 0),
	CRYPTO_RNG_SRC_JITTER_RPC	= (1 << 1 | 1),
	CRYPTO_RNG_SRC_NONSECURE	= (1 << 1 | 0),
};

/*
 * crypto_rng_init() - initialize the RNG
 * @data:	buffer with initial seed
 * @dlen:	length of @data
 */
TEE_Result crypto_rng_init(const void *data, size_t dlen);

/*
 * crypto_rng_add_event() - supply entropy to RNG from a source
 * @sid:	Source identifier, should be unique for a specific source
 * @pnum:	Pool number, acquired using crypto_rng_get_next_pool_num()
 * @data:	Data associated with the event
 * @dlen:	Length of @data
 *
 * @sid controls whether the event is merly queued in a ring buffer or if
 * it's added to one of the pools directly. If CRYPTO_RNG_SRC_IS_QUICK() is
 * true (lowest bit set) events are queue otherwise added to corresponding
 * pool. If CRYPTO_RNG_SRC_IS_QUICK() is false, eventual queued events are
 * added to their queues too.
 */
void crypto_rng_add_event(enum crypto_rng_src sid, unsigned int *pnum,
			  const void *data, size_t dlen);

/*
 * crypto_rng_read() - read cryptograhically secure RNG
 * @buf:	Buffer to hold the data
 * @len:	Length of buffer.
 *
 * Eventual queued events are also added to their pools during this
 * function call.
 */
TEE_Result crypto_rng_read(void *buf, size_t len);

/*
 * crypto_aes_expand_enc_key() - Expand an AES key
 * @key:	AES key buffer
 * @key_len:	Size of the @key buffer in bytes
 * @enc_key:	Expanded AES encryption key buffer
 * @enc_keylen: Size of the @enc_key buffer in bytes
 * @rounds:	Number of rounds to be used during encryption
 */
TEE_Result crypto_aes_expand_enc_key(const void *key, size_t key_len,
				     void *enc_key, size_t enc_keylen,
				     unsigned int *rounds);

/*
 * crypto_aes_enc_block() - Encrypt an AES block
 * @enc_key:	Expanded AES encryption key
 * @enc_keylen:	Size of @enc_key in bytes
 * @rounds:	Number of rounds
 * @src:	Source buffer of one AES block (16 bytes)
 * @dst:	Destination buffer of one AES block (16 bytes)
 */
void crypto_aes_enc_block(const void *enc_key, size_t enc_keylen,
			  unsigned int rounds, const void *src, void *dst);

#endif /* __CRYPTO_CRYPTO_H */
