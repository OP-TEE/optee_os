/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
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
 * RSA Encrypt/Decript data
 */
struct drvcrypt_rsa_ed {
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

#endif /* __DRVCRYPT_ACIPHER_H__ */
