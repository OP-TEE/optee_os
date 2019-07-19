// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    rsa.c
 *
 * @brief   Crypto RSA interface implementation to enable HW driver.
 */
/* Global includes */
#include <crypto/crypto.h>
#include <tee_api_defines_extensions.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>

/* Local includes */
#include "local.h"

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
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_rsa *rsa = NULL;

	if ((!key) || (size_bits == 0)) {
		CRYPTO_TRACE("Parameters error (key @0x%"PRIxPTR")\n"
				"(size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa)
		ret = rsa->alloc_keypair(key, size_bits);

	CRYPTO_TRACE("RSA Keypair (%d bits) alloc ret = 0x%"PRIx32"",
						size_bits, ret);
	return ret;
}

/**
 * @brief   Allocate a RSA public key
 *
 * @param[in]  key        Public Key
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *key,
						size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_rsa *rsa = NULL;

	if ((!key) || (size_bits == 0)) {
		CRYPTO_TRACE("Parameters error (key @0x%"PRIxPTR")\n"
				"(size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa)
		ret = rsa->alloc_publickey(key, size_bits);

	CRYPTO_TRACE("RSA Public Key (%d bits) alloc ret = 0x%"PRIx32"",
						size_bits, ret);
	return ret;
}

/**
 * @brief   Free a RSA public key
 *
 * @param[in]  key        Public Key
 */
void crypto_acipher_free_rsa_public_key(struct rsa_public_key *key)
{
	struct drvcrypt_rsa *rsa = NULL;

	if (key) {
		rsa = drvcrypt_getmod(CRYPTO_RSA);
		if (rsa) {
			CRYPTO_TRACE("RSA Public Key free");
			rsa->free_publickey(key);
		}
	}
}

/**
 * @brief   Generates a RSA keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_rsa *rsa = NULL;

	/* Check input parameters */
	if ((!key) || (size_bits == 0)) {
		CRYPTO_TRACE("Parameters error (key @0x%"PRIxPTR")\n"
				"(size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa)
		ret = rsa->gen_keypair(key, size_bits);

	CRYPTO_TRACE("RSA Keypair (%d bits) generate ret = 0x%"PRIx32"",
						size_bits, ret);

	return ret;
}

/**
 * @brief   RSA No Pad decrypts the message \a msg encrypted with the
 *          RSA keypair \a key.
 *
 * @param[in]     key        RSA Keypair
 * @param[in]     cipher     Cipher data to decrypt
 * @param[in]     cipher_len Cipher length in bytes
 * @param[out]    msg        Decrypted message
 * @param[in/out] msg_len    Length of the buffer / Decrypted message in bytes
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
				const uint8_t *cipher, size_t cipher_len,
				uint8_t *msg, size_t *msg_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_rsa    *rsa = NULL;
	struct drvcrypt_rsa_ed rsa_data;

	/* Check input parameters */
	if ((!key) || (!msg) || (!cipher) || (!msg_len)) {
		CRYPTO_TRACE("Parameters error (key @0x%"PRIxPTR")\n"
				"(msg @0x%"PRIxPTR" size %d bytes)\n"
				"(cipher @0x%"PRIxPTR" size %d bytes)",
				(uintptr_t)key, (uintptr_t)msg, *msg_len,
				(uintptr_t)cipher, cipher_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa_data.key.key       = key;
	rsa_data.key.isprivate = true;
	rsa_data.key.n_size    = crypto_bignum_num_bytes(key->n);

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the decryption data parameters */
		rsa_data.rsa_id         = RSA_NOPAD;
		rsa_data.message.data   = msg;
		rsa_data.message.length = *msg_len;
		rsa_data.cipher.data    = (uint8_t *)cipher;
		rsa_data.cipher.length  = cipher_len;

		ret = rsa->decrypt(&rsa_data);

		/* Set the message decrypted size */
		*msg_len = rsa_data.message.length;
	}

	CRYPTO_TRACE("RSA Decrypt NO PAD ret = 0x%"PRIx32"", ret);

	return ret;
}

/**
 * @brief   RSA No Pad encrypts the message \a msg with the RSA public
 *          key \a key.
 *
 * @param[in]     key        RSA Public
 * @param[in]     msg        Message to encrypt
 * @param[in]     msg_len    Size of message in bytes
 * @param[out]    cipher     Cipher data
 * @param[in/out] cipher_len Length of the buffer / Cipher in bytes
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					const uint8_t *msg, size_t msg_len,
					uint8_t *cipher, size_t *cipher_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_rsa    *rsa = NULL;
	struct drvcrypt_rsa_ed rsa_data;

	/* Check input parameters */
	if ((!key) || (!msg) || (!cipher) || (!cipher_len)) {
		CRYPTO_TRACE("Parameters error (key @0x%"PRIxPTR")\n"
				"(msg @0x%"PRIxPTR" size %d bytes)\n"
				"(cipher @0x%"PRIxPTR" size %d bytes)",
				(uintptr_t)key, (uintptr_t)msg, msg_len,
				(uintptr_t)cipher, *cipher_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa_data.key.key       = key;
	rsa_data.key.isprivate = false;
	rsa_data.key.n_size    = crypto_bignum_num_bytes(key->n);

	if (rsa_data.key.n_size > *cipher_len) {
		CRYPTO_TRACE("Cipher length (%d) too short expected %d bytes",
					*cipher_len, rsa_data.key.n_size);
		*cipher_len = rsa_data.key.n_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the encryption data parameters */
		rsa_data.rsa_id         = RSA_NOPAD;
		rsa_data.message.data   = (uint8_t *)msg;
		rsa_data.message.length = msg_len;
		rsa_data.cipher.data    = cipher;
		rsa_data.cipher.length  = *cipher_len;

		ret = rsa->encrypt(&rsa_data);

		/* Set the cipher size */
		*cipher_len = rsa_data.cipher.length;
	}

	CRYPTO_TRACE("RSA Encrypt NO PAD ret = 0x%"PRIx32"", ret);

	return ret;
}

/**
 * @brief   RSAES (encryption scheme) decrypts the message \a msg encrypted
 *          with the RSA keypair \a key.
 *
 * @param[in]     algo       Algorithm id
 * @param[in]     key        RSA Keypair
 * @param[in]     label      Additional Encryption Label
 * @param[in]     label_len  Length in bytes of the Label
 * @param[in]     cipher     Cipher data to decrypt
 * @param[in]     cipher_len Cipher length in bytes
 * @param[out]    msg        Decrypted message
 * @param[in/out] msg_len    Length of the buffer / Decrypted message in bytes
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo,
				struct rsa_keypair *key,
				const uint8_t *label, size_t label_len,
				const uint8_t *cipher, size_t cipher_len,
				uint8_t *msg, size_t *msg_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_rsa    *rsa = NULL;
	struct drvcrypt_rsa_ed rsa_data;

	/* Check input parameters */
	if ((!key) || (!msg) || (!cipher) || (!msg_len) ||
			((!label) && (label_len != 0))) {
		CRYPTO_TRACE("Parameters error (key @0x%"PRIxPTR")\n"
				"(msg @0x%"PRIxPTR" size %d bytes)\n"
				"(cipher @0x%"PRIxPTR" size %d bytes)\n"
				"(label @0x%"PRIxPTR" size %d bytes)",
				(uintptr_t)key, (uintptr_t)msg, *msg_len,
				(uintptr_t)cipher, cipher_len,
				(uintptr_t)label, label_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the encryption data parameters */
		if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
			rsa_data.rsa_id   = RSA_PKCS_V1_5;
		} else {
			rsa_data.rsa_id    = RSA_OAEP;
			rsa_data.hash_algo = TEE_INTERNAL_HASH_TO_ALGO(algo);

			ret = tee_hash_get_digest_size(
					TEE_INTERNAL_HASH_TO_ALGO(algo),
					&rsa_data.digest_size);
			if (ret != TEE_SUCCESS)
				return ret;

			rsa_data.mgf = &rsa_mgf1;
		}

		rsa_data.key.key       = key;
		rsa_data.key.isprivate = true;
		rsa_data.key.n_size    = crypto_bignum_num_bytes(key->n);

		rsa_data.message.data   = msg;
		rsa_data.message.length = *msg_len;
		rsa_data.cipher.data    = (uint8_t *)cipher;
		rsa_data.cipher.length  = cipher_len;
		rsa_data.label.data     = ((label_len > 0) ?
						(uint8_t *)label : NULL);
		rsa_data.label.length   = label_len;

		ret = rsa->decrypt(&rsa_data);

		/* Set the message size */
		*msg_len = rsa_data.message.length;
	}

	CRYPTO_TRACE("RSAES Decrypt ret = 0x%"PRIx32"", ret);

	return ret;
}

/**
 * @brief   RSAES (encryption schemes) encrypts the message \a msg with the
 *          RSA public key \a key.
 *
 * @param[in]     algo       Algorithm id
 * @param[in]     key        RSA Public
 * @param[in]     label      Additional Encryption Label
 * @param[in]     label_len  Length in bytes of the Label
 * @param[in]     msg        Message to encrypt
 * @param[in]     msg_len    Size of message in bytes
 * @param[out]    cipher     Cipher data
 * @param[in/out] cipher_len Length of the buffer / Cipher in bytes
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *msg,	size_t msg_len,
					uint8_t *cipher, size_t *cipher_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_rsa    *rsa = NULL;
	struct drvcrypt_rsa_ed rsa_data;

	/* Check input parameters */
	if ((!key) || (!msg) || (!cipher) || (!cipher_len) ||
		   ((!label) && (label_len != 0))) {
		CRYPTO_TRACE("Parameters error (key @0x%"PRIxPTR")\n"
				"(msg @0x%"PRIxPTR" size %d bytes)\n"
				"(cipher @0x%"PRIxPTR" size %d bytes)\n"
				"(label @0x%"PRIxPTR" size %d bytes)",
				(uintptr_t)key, (uintptr_t)msg, msg_len,
				(uintptr_t)cipher, *cipher_len,
				(uintptr_t)label, label_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa_data.key.key       = key;
	rsa_data.key.isprivate = false;
	rsa_data.key.n_size    = crypto_bignum_num_bytes(key->n);

	if (rsa_data.key.n_size > *cipher_len) {
		CRYPTO_TRACE("Cipher length (%d) too short expected %d bytes",
					*cipher_len, rsa_data.key.n_size);
		*cipher_len = rsa_data.key.n_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the encryption data parameters */
		if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
			rsa_data.rsa_id   = RSA_PKCS_V1_5;

			/* Message length <= (modulus_size - 11) */
			if (msg_len > (rsa_data.key.n_size - 11))
				return TEE_ERROR_BAD_PARAMETERS;

		} else {
			rsa_data.rsa_id    = RSA_OAEP;
			rsa_data.hash_algo = TEE_INTERNAL_HASH_TO_ALGO(algo);

			/* Message length <= (modulus_size - 2 * hLength - 2) */
			ret = tee_hash_get_digest_size(
					TEE_INTERNAL_HASH_TO_ALGO(algo),
					&rsa_data.digest_size);
			if (ret != TEE_SUCCESS)
				return ret;

			if (msg_len > (rsa_data.key.n_size -
						(2 * rsa_data.digest_size) - 2))
				return TEE_ERROR_BAD_PARAMETERS;

			rsa_data.mgf = &rsa_mgf1;
		}

		rsa_data.message.data   = (uint8_t *)msg;
		rsa_data.message.length = msg_len;
		rsa_data.cipher.data    = cipher;
		rsa_data.cipher.length  = rsa_data.key.n_size;
		rsa_data.label.data     = ((label_len > 0) ?
						(uint8_t *)label : NULL);
		rsa_data.label.length   = label_len;

		ret = rsa->encrypt(&rsa_data);

		/* Set the cipher size */
		*cipher_len = rsa_data.cipher.length;
	}

	CRYPTO_TRACE("RSAES Encrypt ret = 0x%"PRIx32"", ret);

	return ret;
}

/**
 * @brief   PKCS#1 - Sign the message \a msg and encodes the signature.
 *          Message is signed with the RSA Key given by the Private Key \a key
 *
 * @param[in]     algo       RSA PKCS1 algorithm
 * @param[in]     key        RSA Private key
 * @param[in]     salt_len   Signature Salt Length (bytes)
 * @param[in]     msg        Message to sign
 * @param[in]     msg_len    Length of the message (bytes)
 * @param[out]    sig        Signature
 * @param[in/out] sig_len    Length of the signature (bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_acipher_rsassa_sign(uint32_t algo,
					struct rsa_keypair *key, int salt_len,
					const uint8_t *msg, size_t msg_len,
					uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct drvcrypt_rsa     *rsa = NULL;
	struct drvcrypt_rsa_ssa rsa_ssa;

	/* Verify first if the input parameters */
	if ((!key) || (!msg) || (!sig) || (!sig_len)) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		/* Prepare the Digest */
		rsa_ssa.hash_algo = TEE_DIGEST_HASH_TO_ALGO(algo);

		/* Check if the message length is digest hash size */
		ret = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
					&rsa_ssa.digest_size);
		if (ret != TEE_SUCCESS)
			return ret;

		if (msg_len != rsa_ssa.digest_size) {
			CRYPTO_TRACE("Wrong input msg length (%d expected %d)",
					msg_len, rsa_ssa.digest_size);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	} else {
		rsa_ssa.hash_algo   = 0;
		rsa_ssa.digest_size = 0;
	}

	/* Prepare the Key */
	rsa_ssa.key.key       = key;
	rsa_ssa.key.isprivate = true;
	rsa_ssa.key.n_size    = crypto_bignum_num_bytes(key->n);

	if (rsa_ssa.key.n_size > *sig_len) {
		CRYPTO_TRACE("Signature length (%d) too short must be %d bytes",
				*sig_len, rsa_ssa.key.n_size);
		*sig_len = rsa_ssa.key.n_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa) {
		/*
		 * Prepare the Encoded Signature structure data
		 */
		rsa_ssa.algo             = algo;
		rsa_ssa.message.data     = (uint8_t *)msg;
		rsa_ssa.message.length   = msg_len;
		rsa_ssa.signature.data   = (uint8_t *)sig;
		rsa_ssa.signature.length = rsa_ssa.key.n_size;
		rsa_ssa.salt_len         = salt_len;
		rsa_ssa.mgf              = &rsa_mgf1;

		if (rsa->ssa_sign)
			ret = rsa->ssa_sign(&rsa_ssa);
		else
			ret = rsassa_sign(&rsa_ssa);

		/* Set the signature length */
		*sig_len = rsa_ssa.signature.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Encode signature algo (0x%"PRIx32") returned 0x%"PRIx32"",
		algo, ret);
	return ret;
}

/**
 * @brief   PKCS#1 - Verification the encoded signature of the message \a msg.
 *          Message is signed with the RSA Key given by the Public Key \a key
 *
 * @param[in]  algo       RSA PKCS1 algorithm
 * @param[in]  key        RSA Public key
 * @param[in]  salt_len   Signature Salt Length (bytes)
 * @param[in]  msg        Message signed
 * @param[in]  msg_len    Length of the message (bytes)
 * @param[in]  sig        Signature to be verified
 * @param[in]  sig_len    Length of the signature (bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature invalid
 */
TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
				struct rsa_public_key *key, int salt_len,
				const uint8_t *msg, size_t msg_len,
				const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct drvcrypt_rsa     *rsa = NULL;
	struct drvcrypt_rsa_ssa rsa_ssa;

	/* Verify first if the input parameters */
	if ((!key) || (!msg) || (!sig)) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		/* Prepare the Digest */
		rsa_ssa.hash_algo = TEE_DIGEST_HASH_TO_ALGO(algo);

		/* Check if the message length is digest hash size */
		ret = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
					&rsa_ssa.digest_size);
		if (ret != TEE_SUCCESS)
			return ret;

		if (msg_len != rsa_ssa.digest_size) {
			CRYPTO_TRACE("Wrong input msg length (%d expected %d)",
					msg_len, rsa_ssa.digest_size);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	} else {
		rsa_ssa.hash_algo   = 0;
		rsa_ssa.digest_size = 0;
	}

	/* Prepare the Key */
	rsa_ssa.key.key       = key;
	rsa_ssa.key.isprivate = false;
	rsa_ssa.key.n_size    = crypto_bignum_num_bytes(key->n);

	if (rsa_ssa.key.n_size > sig_len) {
		CRYPTO_TRACE("Signature length expected %d",
				rsa_ssa.key.n_size);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	rsa = drvcrypt_getmod(CRYPTO_RSA);
	if (rsa) {
		/*
		 * Prepare the Encoded Signature structure data
		 */
		rsa_ssa.algo             = algo;
		rsa_ssa.message.data     = (uint8_t *)msg;
		rsa_ssa.message.length   = msg_len;
		rsa_ssa.signature.data   = (uint8_t *)sig;
		rsa_ssa.signature.length = sig_len;
		rsa_ssa.salt_len         = salt_len;
		rsa_ssa.mgf              = &rsa_mgf1;

		if (rsa->ssa_verify)
			ret = rsa->ssa_verify(&rsa_ssa);
		else
			ret = rsassa_verify(&rsa_ssa);

	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Signature verif algo (0x%"PRIx32") returned 0x%"PRIx32"",
		algo, ret);

	return ret;
}
