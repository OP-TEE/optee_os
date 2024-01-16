/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 *
 * Brief   Asymmetric Cipher interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_ACIPHER_H__
#define __DRVCRYPT_ACIPHER_H__

#include <crypto/crypto.h>
#include <tee_api_types.h>

/*
 * Assymetric Cipher RSA Algorithm enumerate
 */
enum drvcrypt_rsa_id {
	DRVCRYPT_RSA_NOPAD = 0,	   /* RSA Algo mode NO PAD */
	DRVCRYPT_RSA_OAEP,	   /* RSA Algo mode OAEP */
	DRVCRYPT_RSA_PKCS_V1_5,	   /* RSA Algo mode PKCSv1.5 */
	DRVCRYPT_RSASSA_PKCS_V1_5, /* RSA Signature Algo mode PKCSv1.5 */
	DRVCRYPT_RSASSA_PSS,	   /* RSA Signature Algo mode PSS */
};

/*
 * RSA Key object
 */
struct drvcrypt_rsakey {
	void *key;	/* Public or Private key */
	size_t n_size;	/* Size in bytes of the Modulus N */
	bool isprivate; /* True if private key */
};

/*
 * RSA Mask Generation data
 */
struct drvcrypt_rsa_mgf {
	uint32_t hash_algo;	  /* HASH Algorithm */
	size_t digest_size;	  /* Hash Digest Size */
	struct drvcrypt_buf seed; /* Seed to generate mask */
	struct drvcrypt_buf mask; /* Mask generated */
};

/*
 * RSA Encoded Signature data
 */
struct drvcrypt_rsa_ssa {
	uint32_t algo;		       /* Operation algorithm */
	uint32_t hash_algo;	       /* HASH Algorithm */
	size_t digest_size;	       /* Hash Digest Size */
	struct drvcrypt_rsakey key;    /* Public or Private Key */
	struct drvcrypt_buf message;   /* Message to sign or signed */
	struct drvcrypt_buf signature; /* Signature of the message */
	size_t salt_len;	       /* Signature Salt length */

	/* RSA Mask Generation function */
	TEE_Result (*mgf)(struct drvcrypt_rsa_mgf *mgf_data);
};

/*
 * RSA Encrypt/Decrypt data
 */
struct drvcrypt_rsa_ed {
	uint32_t algo;		     /* Operation algorithm */
	enum drvcrypt_rsa_id rsa_id; /* RSA Algorithm Id */
	uint32_t hash_algo;	     /* HASH Algorithm */
	size_t digest_size;	     /* Hash Digest Size */
	struct drvcrypt_rsakey key;  /* Public or Private key */
	struct drvcrypt_buf message; /* Message to encrypt or decrypted */
	struct drvcrypt_buf cipher;  /* Cipher encrypted or to decrypt */
	struct drvcrypt_buf label;   /* Additional Label (RSAES) */

	/* RSA Mask Generation function */
	TEE_Result (*mgf)(struct drvcrypt_rsa_mgf *mgf_data);
};

/*
 * Crypto Library RSA driver operations
 */
struct drvcrypt_rsa {
	/* Allocates the RSA keypair */
	TEE_Result (*alloc_keypair)(struct rsa_keypair *key, size_t size_bits);
	/* Allocates the RSA public key */
	TEE_Result (*alloc_publickey)(struct rsa_public_key *key,
				      size_t size_bits);
	/* Free RSA public key */
	void (*free_publickey)(struct rsa_public_key *key);
	/* Free RSA keypair */
	void (*free_keypair)(struct rsa_keypair *key);
	/* Generates the RSA keypair */
	TEE_Result (*gen_keypair)(struct rsa_keypair *key, size_t size_bits);

	/* RSA Encryption */
	TEE_Result (*encrypt)(struct drvcrypt_rsa_ed *rsa_data);
	/* RSA Decryption */
	TEE_Result (*decrypt)(struct drvcrypt_rsa_ed *rsa_data);

	struct {
		/* RSA Sign a message and encode the signature */
		TEE_Result (*ssa_sign)(struct drvcrypt_rsa_ssa *ssa_data);
		/* RSA Encoded Signature Verification */
		TEE_Result (*ssa_verify)(struct drvcrypt_rsa_ssa *ssa_data);
	} optional;
};

/*
 * Register a RSA processing driver in the crypto API
 *
 * @ops - Driver operations in the HW layer
 */
static inline TEE_Result drvcrypt_register_rsa(const struct drvcrypt_rsa *ops)
{
	return drvcrypt_register(CRYPTO_RSA, (void *)ops);
}

/*
 * Signature data
 */
struct drvcrypt_sign_data {
	uint32_t algo;               /* Operation algorithm */
	void *key;                   /* Public or Private Key */
	size_t size_sec;             /* Security size in bytes */
	struct drvcrypt_buf message;    /* Message to sign or signed */
	struct drvcrypt_buf signature;  /* Signature of the message */
};

/*
 * Shared Secret data
 */
struct drvcrypt_secret_data {
	void *key_priv;		    /* Private Key */
	void *key_pub;		    /* Public Key */
	size_t size_sec;	    /* Security size in bytes */
	struct drvcrypt_buf secret; /* Shared secret */
};

/*
 * Encrypt/Decrypt data
 */
struct drvcrypt_ecc_ed {
	uint32_t algo;                  /* Operation algorithm */
	void *key;                      /* Public or Private Key */
	size_t size_sec;                /* Security size in bytes */
	struct drvcrypt_buf plaintext;  /* Clear text message */
	struct drvcrypt_buf ciphertext; /* Encrypted message */
};

/*
 * Crypto ECC driver operations
 */
struct drvcrypt_ecc {
	/* Allocates the ECC keypair */
	TEE_Result (*alloc_keypair)(struct ecc_keypair *key, uint32_t type,
				    size_t size_bits);
	/* Allocates the ECC public key */
	TEE_Result (*alloc_publickey)(struct ecc_public_key *key, uint32_t type,
				      size_t size_bits);
	/* Free ECC public key */
	void (*free_publickey)(struct ecc_public_key *key);
	/* Generates the ECC keypair */
	TEE_Result (*gen_keypair)(struct ecc_keypair *key, size_t size_bits);
	/* ECC Sign a message and returns the signature */
	TEE_Result (*sign)(struct drvcrypt_sign_data *sdata);
	/* ECC Verify a message's signature */
	TEE_Result (*verify)(struct drvcrypt_sign_data *sdata);
	/* ECC Shared Secret */
	TEE_Result (*shared_secret)(struct drvcrypt_secret_data *sdata);
	/* ECC Encrypt */
	TEE_Result (*encrypt)(struct drvcrypt_ecc_ed *cdata);
	/* ECC Decrypt */
	TEE_Result (*decrypt)(struct drvcrypt_ecc_ed *cdata);
};

/*
 * Register an ECC processing driver in the crypto API
 *
 * @ops - Driver operations in the HW layer
 */
static inline TEE_Result drvcrypt_register_ecc(struct drvcrypt_ecc *ops)
{
	return drvcrypt_register(CRYPTO_ECC, (void *)ops);
}

/*
 * Crypto Library DH driver operations
 */
struct drvcrypt_dh {
	/* Allocates the DH keypair */
	TEE_Result (*alloc_keypair)(struct dh_keypair *key, size_t size_bits);
	/* Generates the DH keypair */
	TEE_Result (*gen_keypair)(struct dh_keypair *key, struct bignum *q,
				  size_t size_bits);
	/* DH Shared Secret */
	TEE_Result (*shared_secret)(struct drvcrypt_secret_data *sdata);
};

/*
 * Register a DH processing driver in the crypto API
 *
 * @ops - Driver operations in the HW layer
 */
static inline TEE_Result drvcrypt_register_dh(struct drvcrypt_dh *ops)
{
	return drvcrypt_register(CRYPTO_DH, (void *)ops);
}

/*
 * Crypto Library DSA driver operations
 */
struct drvcrypt_dsa {
	/* Allocates the DSA keypair */
	TEE_Result (*alloc_keypair)(struct dsa_keypair *key, size_t l_bits,
				    size_t n_bits);
	/* Allocates the DSA public key */
	TEE_Result (*alloc_publickey)(struct dsa_public_key *key, size_t l_bits,
				      size_t n_bits);
	/* Generates the DSA keypair */
	TEE_Result (*gen_keypair)(struct dsa_keypair *key, size_t l_bits,
				  size_t n_bits);
	/* DSA Sign a message and returns the signature */
	TEE_Result (*sign)(struct drvcrypt_sign_data *sdata, size_t l_bytes,
			   size_t n_bytes);
	/* DSA Verify a message's signature */
	TEE_Result (*verify)(struct drvcrypt_sign_data *sdata, size_t l_bytes,
			     size_t n_bytes);
};

/*
 * Register a DSA processing driver in the crypto API
 *
 * @ops - Driver operations in the HW layer
 */
static inline TEE_Result drvcrypt_register_dsa(struct drvcrypt_dsa *ops)
{
	return drvcrypt_register(CRYPTO_DSA, (void *)ops);
}

/*
 * Crypto Library Montgomery driver operations
 */

struct drvcrypt_montgomery {
	/* Allocates the Montgomery key pair */
	TEE_Result (*alloc_keypair)(struct montgomery_keypair *key,
				    size_t size_bits);
	/* Generates the Montgomery key pair */
	TEE_Result (*gen_keypair)(struct montgomery_keypair *key,
				  size_t key_size);
	/* Montgomery Shared Secret */
	TEE_Result (*shared_secret)(struct drvcrypt_secret_data *sdata);
};

/*
 * Register a X25519 processing driver in the crypto API
 *
 * @ops - Driver operations in the HW layer
 */
static inline TEE_Result drvcrypt_register_x25519(struct drvcrypt_montgomery
						  *ops)
{
	return drvcrypt_register(CRYPTO_X25519, (void *)ops);
}

/*
 * Register a X448 processing driver in the crypto API
 *
 * @ops - Driver operations in the HW layer
 */
static inline TEE_Result drvcrypt_register_x448(struct drvcrypt_montgomery *ops)
{
	return drvcrypt_register(CRYPTO_X448, (void *)ops);
}

#endif /* __DRVCRYPT_ACIPHER_H__ */
