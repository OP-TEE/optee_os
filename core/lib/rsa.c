// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    rsa.c
 *
 */
/* Global includes */
#include <crypto/crypto.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

/**
 * @brief   Allocate a RSA keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *key,
						size_t size_bits)
{
	/* Initialize all input key fields to 0 */
	memset(key, 0, sizeof(*key));

	/* Allocate the Public Exponent to maximum size */
	key->e = crypto_bignum_allocate(256);
	if (!key->e)
		goto err_alloc_keypair;

	/* Allocate the Private Exponent [d = 1/e mod LCM(p-1, q-1)] */
	key->d = crypto_bignum_allocate(size_bits + (RSEC_OVERHEAD * 8));
	if (!key->d)
		goto err_alloc_keypair;

	/* Allocate the Modulus (size_bits) [n = p * q] */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_keypair;

	/* Allocate the prime number p of size (size_bits / 2) */
	key->p = crypto_bignum_allocate(size_bits + (RSEC_OVERHEAD * 8));
	if (!key->p)
		goto err_alloc_keypair;

	/* Allocate the prime number q of size (size_bits / 2) */
	key->q = crypto_bignum_allocate(size_bits + (RSEC_OVERHEAD * 8));
	if (!key->q)
		goto err_alloc_keypair;

	/* Allocate dp (size_bits / 2) [d mod (p-1)] */
	key->dp = crypto_bignum_allocate(size_bits + (RSEC_OVERHEAD * 8));
	if (!key->dp)
		goto err_alloc_keypair;

	/* Allocate dq (size_bits / 2) [d mod (q-1)] */
	key->dq = crypto_bignum_allocate(size_bits + (RSEC_OVERHEAD * 8));
	if (!key->dq)
		goto err_alloc_keypair;

	/* Allocate qp (size_bits / 2) [1/q mod p] */
	key->qp = crypto_bignum_allocate(size_bits + (RSEC_OVERHEAD * 8));
	if (!key->qp)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	crypto_bignum_free(key->e);
	crypto_bignum_free(key->d);
	crypto_bignum_free(key->n);
	crypto_bignum_free(key->p);
	crypto_bignum_free(key->q);
	crypto_bignum_free(key->dp);
	crypto_bignum_free(key->dq);
	crypto_bignum_free(key->qp);

	return TEE_ERROR_OUT_OF_MEMORY;
}
TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *key,
						size_t size_bits)
{
}

void crypto_acipher_free_rsa_public_key(struct rsa_public_key *key)
{
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t size_bits)
{
	/* This will generate the Simple RSA Keys either from Hardware/Software Library
	  * NXP CAAM generates key components in Binary format, so will be converting them
	  * to bignums before saving to the rsa_keypair *key */
}

/**
	This new crypto API will be added for generating Runtime Secure Keys from hardware.
*/
TEE_Result crypto_acipher_gen_rsa_key_rsec(struct rsa_keypair *key,
						size_t size_bits)
{
	/* This will be offloaded to Hardware Crypto Driver for generating Runtime Secure Keys.
	  * NXP CAAM generates key components in Binary format, so will be converting them
	  * to bignums before saving to the rsa_keypair *key except the private key components,
	  * because they can be understandable only by hardware now and moreover we are not
	  * going to export the private components to the user.
	  * But because we kept the rsa_keypair all components to be bignum, we will just copy
	  * the private parts to the bignums as it is.
	  * For this we will need an API crypto_bignum_bin_copy which will copy the binary key
	  * component to the bignum memory.*/
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
				const uint8_t *cipher, size_t cipher_len,
				uint8_t *msg, size_t *msg_len)
{
}

TEE_Result crypto_acipher_rsanopad_decrypt_rsec(struct rsa_keypair *key,
				const uint8_t *cipher, size_t cipher_len,
				uint8_t *msg, size_t *msg_len)
{
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					const uint8_t *msg, size_t msg_len,
					uint8_t *cipher, size_t *cipher_len)
{
}

TEE_Result crypto_acipher_rsanopad_encrypt_rsec(struct rsa_public_key *key,
					const uint8_t *msg, size_t msg_len,
					uint8_t *cipher, size_t *cipher_len)
{
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo,
				struct rsa_keypair *key,
				const uint8_t *label, size_t label_len,
				const uint8_t *cipher, size_t cipher_len,
				uint8_t *msg, size_t *msg_len)
{
}

TEE_Result crypto_acipher_rsaes_decrypt_rsec(uint32_t algo,
				struct rsa_keypair *key,
				const uint8_t *label, size_t label_len,
				const uint8_t *cipher, size_t cipher_len,
				uint8_t *msg, size_t *msg_len)
{
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *msg,	size_t msg_len,
					uint8_t *cipher, size_t *cipher_len)
{
}

TEE_Result crypto_acipher_rsaes_encrypt_rsec(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *msg,	size_t msg_len,
					uint8_t *cipher, size_t *cipher_len)
{
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo,
					struct rsa_keypair *key, int salt_len,
					const uint8_t *msg, size_t msg_len,
					uint8_t *sig, size_t *sig_len)
{
}

TEE_Result crypto_acipher_rsassa_sign_rsec(uint32_t algo,
					struct rsa_keypair *key, int salt_len,
					const uint8_t *msg, size_t msg_len,
					uint8_t *sig, size_t *sig_len)
{
}


TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
				struct rsa_public_key *key, int salt_len,
				const uint8_t *msg, size_t msg_len,
				const uint8_t *sig, size_t sig_len)
{
}
