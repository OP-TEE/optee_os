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

#endif /* __DRVCRYPT_ACIPHER_H__ */
