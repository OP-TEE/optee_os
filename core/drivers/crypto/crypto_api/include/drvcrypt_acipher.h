/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    drvcrypt_acipher.h
 *
 * @brief   Assymetric Cipher interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_ACIPHER_H__
#define __DRVCRYPT_ACIPHER_H__

/* Global includes */
#include <crypto/crypto.h>
#include <tee_api_types.h>

/**
 * @brief   Signature data
 */
struct drvcrypt_sign_data {
	uint32_t            algo;       ///< Operation algorithm
	void                *key;       ///< Public or Private Key
	size_t              size_sec;   ///< Security size in bytes
	struct drvcrypt_buf message;    ///< Message to sign or signed
	struct drvcrypt_buf signature;  ///< Signature of the message
};

/**
 * @brief   Shared Secret data
 */
struct drvcrypt_secret_data {
	void                *key_priv;  ///< Private Key
	void                *key_pub;   ///< Public Key
	size_t              size_sec;   ///< Security size in bytes
	struct drvcrypt_buf secret;     ///< Share secret
};

/**
 * @brief   Crypto ECC driver operations
 *
 */
struct drvcrypt_ecc {
	///< Allocates the ECC keypair
	TEE_Result (*alloc_keypair)(struct ecc_keypair *key, size_t size_bits);
	///< Allocates the ECC public key
	TEE_Result (*alloc_publickey)(struct ecc_public_key *key,
					size_t size_bits);
	///< Free ECC public key
	void (*free_publickey)(struct ecc_public_key *key);
	///< Generates the ECC keypair
	TEE_Result (*gen_keypair)(struct ecc_keypair *key, size_t size_bits);
	///< ECC Sign a message and returns the signature
	TEE_Result (*sign)(struct drvcrypt_sign_data *sdata);
	///< ECC Verify a message's signature
	TEE_Result (*verify)(struct drvcrypt_sign_data *sdata);
	///< ECC Shared Secret
	TEE_Result (*shared_secret)(struct drvcrypt_secret_data *sdata);
};

/**
 * @brief   Assymetric Cipher RSA Algorithm enumerate
 */
enum drvcrypt_rsa_id {
	RSA_NOPAD = 0,   ///< RSA Algo mode NO PAD
	RSA_OAEP,        ///< RSA Algo mode OAEP
	RSA_PKCS_V1_5,   ///< RSA Algo mode PKCSv1.5
};

/**
 * @brief   RSA Key object
 */
struct rsakey {
	void   *key;      ///< Public or Private key
	size_t n_size;    ///< Size in bytes of the Modulus N
	bool   isprivate; ///< True if private key
};

/**
 * @brief   RSA Mask Generation data
 */
struct drvcrypt_rsa_mgf {
	uint32_t              hash_algo;   ///< HASH Algorithm
	size_t                digest_size; ///< Hash Digest Size
	struct drvcrypt_buf   seed;        ///< Seed to generate mask
	struct drvcrypt_buf   mask;        ///< Mask generated

};

/**
 * @brief   RSA Encoded Signature data
 */
struct drvcrypt_rsa_ssa {
	uint32_t              algo;        ///< Operation algorithm
	uint32_t              hash_algo;   ///< HASH Algorithm
	size_t                digest_size; ///< Hash Digest Size
	struct rsakey         key;         ///< Public or Private Key
	struct drvcrypt_buf   message;     ///< Message to sign or signed
	struct drvcrypt_buf   signature;   ///< Signature of the message
	size_t                salt_len;    ///< Signature Salt length

	///< RSA Mask Generation function
	TEE_Result (*mgf)(struct drvcrypt_rsa_mgf *mgf_data);
};

/**
 * @brief   RSA Encrypt/Decript data
 */
struct drvcrypt_rsa_ed {
	enum drvcrypt_rsa_id  rsa_id;      ///< RSA Algorithm Id
	uint32_t              hash_algo;   ///< HASH Algorithm
	size_t                digest_size; ///< Hash Digest Size
	struct rsakey         key;         ///< Public or Private key
	struct drvcrypt_buf   message;     ///< Message to encrypt or decrypted
	struct drvcrypt_buf   cipher;      ///< Cipher encrypted or to decrypt
	struct drvcrypt_buf   label;       ///< Additional Label (RSAES)

	///< RSA Mask Generation function
	TEE_Result (*mgf)(struct drvcrypt_rsa_mgf *mgf_data);
};

/**
 * @brief   NXP Crypto Library RSA driver operations
 *
 */
struct drvcrypt_rsa {
	///< Allocates the RSA keypair
	TEE_Result (*alloc_keypair)(struct rsa_keypair *key, size_t size_bits);
	///< Allocates the RSA public key
	TEE_Result (*alloc_publickey)(struct rsa_public_key *key,
					size_t size_bits);
	///< Free RSA public key
	void (*free_publickey)(struct rsa_public_key *key);
	///< Generates the RSA keypair
	TEE_Result (*gen_keypair)(struct rsa_keypair *key, size_t size_bits);

	///< RSA Encryption
	TEE_Result (*encrypt)(struct drvcrypt_rsa_ed *rsa_data);
	///< RSA Decryption
	TEE_Result (*decrypt)(struct drvcrypt_rsa_ed *rsa_data);

	///< RSA Sign a message and encode the signature
	TEE_Result (*ssa_sign)(struct drvcrypt_rsa_ssa *ssa_data);
	///< RSA Encoded Signature Verification
	TEE_Result (*ssa_verify)(struct drvcrypt_rsa_ssa *ssa_data);

};

#endif /* __DRVCRYPT_ACIPHER_H__ */
