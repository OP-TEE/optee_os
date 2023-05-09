// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Crypto RSA interface implementation to enable HW driver.
 */
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <fault_mitigation.h>
#include <tee_api_defines_extensions.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

#include "local.h"

TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *key,
					    size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_rsa *rsa = NULL;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Parameters error (key @%p) (size %zu bits)", key,
			     size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa)
		ret = rsa->alloc_keypair(key, size_bits);

	CRYPTO_TRACE("RSA Keypair (%zu bits) alloc ret = 0x%" PRIx32, size_bits,
		     ret);
	return ret;
}

TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *key,
					       size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_rsa *rsa = NULL;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Parameters error (key @%p) (size %zu bits)", key,
			     size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa)
		ret = rsa->alloc_publickey(key, size_bits);

	CRYPTO_TRACE("RSA Public Key (%zu bits) alloc ret = 0x%" PRIx32,
		     size_bits, ret);
	return ret;
}

void crypto_acipher_free_rsa_public_key(struct rsa_public_key *key)
{
	struct drvcrypt_rsa *rsa = NULL;

	if (key) {
		rsa = drvcrypt_get_ops(CRYPTO_RSA);
		if (rsa) {
			CRYPTO_TRACE("RSA Public Key free");
			rsa->free_publickey(key);
		}
	}
}

void crypto_acipher_free_rsa_keypair(struct rsa_keypair *key)
{
	struct drvcrypt_rsa *rsa = NULL;

	if (key) {
		rsa = drvcrypt_get_ops(CRYPTO_RSA);
		if (rsa) {
			CRYPTO_TRACE("RSA Keypair free");
			rsa->free_keypair(key);
		}
	}
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_rsa *rsa = NULL;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Parameters error (key @%p) (size %zu bits) ",
			     key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa)
		ret = rsa->gen_keypair(key, size_bits);

	CRYPTO_TRACE("RSA Keypair (%zu bits) generate ret = 0x%" PRIx32,
		     size_bits, ret);

	return ret;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					   const uint8_t *cipher,
					   size_t cipher_len, uint8_t *msg,
					   size_t *msg_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_rsa *rsa = NULL;
	struct drvcrypt_rsa_ed rsa_data = { };

	if (!key || !msg || !cipher || !msg_len) {
		CRYPTO_TRACE("Parameters error (key @%p)\n"
			     "(msg @%p size %zu bytes)\n"
			     "(cipher @0%p size %zu bytes)",
			     key, msg, msg_len ? *msg_len : 0,
			     cipher, cipher_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa_data.key.key = key;
	rsa_data.key.isprivate = true;
	rsa_data.key.n_size = crypto_bignum_num_bytes(key->n);

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa) {
		rsa_data.rsa_id = DRVCRYPT_RSA_NOPAD;
		rsa_data.message.data = msg;
		rsa_data.message.length = *msg_len;
		rsa_data.cipher.data = (uint8_t *)cipher;
		rsa_data.cipher.length = cipher_len;

		ret = rsa->decrypt(&rsa_data);

		*msg_len = rsa_data.message.length;
	}

	CRYPTO_TRACE("RSA Decrypt NO PAD ret = 0x%" PRIx32, ret);

	return ret;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *msg, size_t msg_len,
					   uint8_t *cipher, size_t *cipher_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_rsa *rsa = NULL;
	struct drvcrypt_rsa_ed rsa_data = { };

	if (!key || !msg || !cipher_len) {
		CRYPTO_TRACE("Parameters error (key @%p)\n"
			     "(msg @%p size %zu bytes)\n"
			     "(cipher @%p size %zu bytes)",
			     key, msg, msg_len,
			     cipher, cipher_len ? *cipher_len : 0);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa_data.key.key = key;
	rsa_data.key.isprivate = false;
	rsa_data.key.n_size = crypto_bignum_num_bytes(key->n);

	if (rsa_data.key.n_size > *cipher_len) {
		CRYPTO_TRACE("Cipher length (%zu) too short expected %zu bytes",
			     *cipher_len, rsa_data.key.n_size);
		*cipher_len = rsa_data.key.n_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (!cipher) {
		CRYPTO_TRACE("Parameter \"cipher\" reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the encryption data parameters */
		rsa_data.rsa_id = DRVCRYPT_RSA_NOPAD;
		rsa_data.message.data = (uint8_t *)msg;
		rsa_data.message.length = msg_len;
		rsa_data.cipher.data = cipher;
		rsa_data.cipher.length = *cipher_len;

		ret = rsa->encrypt(&rsa_data);

		/* Set the cipher size */
		*cipher_len = rsa_data.cipher.length;
	}

	CRYPTO_TRACE("RSA Encrypt NO PAD ret = 0x%" PRIx32, ret);

	return ret;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *cipher,
					size_t cipher_len, uint8_t *msg,
					size_t *msg_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_rsa *rsa = NULL;
	struct drvcrypt_rsa_ed rsa_data = { };

	if (!key || !msg || !cipher || !msg_len || (!label && label_len)) {
		CRYPTO_TRACE("Parameters error (key @%p)\n"
			     "(msg @%p size %zu bytes)\n"
			     "(cipher @%p size %zu bytes)\n"
			     "(label @%p size %zu bytes)",
			     key, msg, msg_len ? *msg_len : 0,
			     cipher, cipher_len, label, label_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the encryption data parameters */
		if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
			rsa_data.rsa_id = DRVCRYPT_RSA_PKCS_V1_5;
		} else {
			rsa_data.rsa_id = DRVCRYPT_RSA_OAEP;
			rsa_data.hash_algo = TEE_INTERNAL_HASH_TO_ALGO(algo);

			ret = tee_alg_get_digest_size(rsa_data.hash_algo,
						      &rsa_data.digest_size);
			if (ret != TEE_SUCCESS)
				return ret;

			rsa_data.mgf = &drvcrypt_rsa_mgf1;
		}

		rsa_data.key.key = key;
		rsa_data.key.isprivate = true;
		rsa_data.key.n_size = crypto_bignum_num_bytes(key->n);

		rsa_data.message.data = msg;
		rsa_data.message.length = *msg_len;
		rsa_data.cipher.data = (uint8_t *)cipher;
		rsa_data.cipher.length = cipher_len;
		rsa_data.label.data =
			((label_len > 0) ? (uint8_t *)label : NULL);
		rsa_data.label.length = label_len;
		rsa_data.algo = algo;

		ret = rsa->decrypt(&rsa_data);

		/* Set the message size */
		*msg_len = rsa_data.message.length;
	}

	CRYPTO_TRACE("RSAES Decrypt ret = 0x%" PRIx32, ret);

	return ret;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *msg, size_t msg_len,
					uint8_t *cipher, size_t *cipher_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_rsa *rsa = NULL;
	struct drvcrypt_rsa_ed rsa_data = { };

	if (!key || !msg || !cipher_len || (!label && label_len)) {
		CRYPTO_TRACE("Parameters error (key @%p\n"
			     "(msg @%p size %zu bytes)\n"
			     "(cipher @%p size %zu bytes)\n"
			     "(label @%p size %zu bytes)",
			     key, msg, msg_len,
			     cipher, cipher_len ? *cipher_len : 0,
			     label, label_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa_data.key.key = key;
	rsa_data.key.isprivate = false;
	rsa_data.key.n_size = crypto_bignum_num_bytes(key->n);

	if (rsa_data.key.n_size > *cipher_len) {
		CRYPTO_TRACE("Cipher length (%zu) too short expected %zu bytes",
			     *cipher_len, rsa_data.key.n_size);
		*cipher_len = rsa_data.key.n_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (!cipher) {
		CRYPTO_TRACE("Parameter \"cipher\" reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the encryption data parameters */
		if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
			rsa_data.rsa_id = DRVCRYPT_RSA_PKCS_V1_5;

			/* Message length <= (modulus_size - 11) */
			if (msg_len > rsa_data.key.n_size - 11)
				return TEE_ERROR_BAD_PARAMETERS;

		} else {
			rsa_data.rsa_id = DRVCRYPT_RSA_OAEP;
			rsa_data.hash_algo = TEE_INTERNAL_HASH_TO_ALGO(algo);

			/* Message length <= (modulus_size - 2 * hLength - 2) */
			ret = tee_alg_get_digest_size(rsa_data.hash_algo,
						      &rsa_data.digest_size);
			if (ret != TEE_SUCCESS)
				return ret;

			if (2 * rsa_data.digest_size >= rsa_data.key.n_size - 2)
				return TEE_ERROR_BAD_PARAMETERS;

			if (msg_len >
			    rsa_data.key.n_size - 2 * rsa_data.digest_size - 2)
				return TEE_ERROR_BAD_PARAMETERS;

			rsa_data.mgf = &drvcrypt_rsa_mgf1;
		}

		rsa_data.message.data = (uint8_t *)msg;
		rsa_data.message.length = msg_len;
		rsa_data.cipher.data = cipher;
		rsa_data.cipher.length = rsa_data.key.n_size;
		rsa_data.label.data = (label_len > 0) ? (uint8_t *)label : NULL;
		rsa_data.label.length = label_len;
		rsa_data.algo = algo;

		ret = rsa->encrypt(&rsa_data);

		/* Set the cipher size */
		*cipher_len = rsa_data.cipher.length;
	}

	CRYPTO_TRACE("RSAES Encrypt ret = 0x%" PRIx32, ret);

	return ret;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
				      int salt_len, const uint8_t *msg,
				      size_t msg_len, uint8_t *sig,
				      size_t *sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_rsa *rsa = NULL;
	struct drvcrypt_rsa_ssa rsa_ssa = { };

	if (!key || !msg || !sig_len) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		/* Prepare the Digest */
		rsa_ssa.hash_algo = TEE_DIGEST_HASH_TO_ALGO(algo);

		/* Check if the message length is digest hash size */
		ret = tee_alg_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
					      &rsa_ssa.digest_size);
		if (ret != TEE_SUCCESS)
			return ret;

		if (msg_len != rsa_ssa.digest_size) {
			CRYPTO_TRACE("Msg length (%zu expected %zu)", msg_len,
				     rsa_ssa.digest_size);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	} else {
		rsa_ssa.hash_algo = 0;
		rsa_ssa.digest_size = 0;
	}

	/* Prepare the Key */
	rsa_ssa.key.key = key;
	rsa_ssa.key.isprivate = true;
	rsa_ssa.key.n_size = crypto_bignum_num_bytes(key->n);

	if (rsa_ssa.key.n_size > *sig_len) {
		CRYPTO_TRACE("Sign length (%zu) too short must be %zu bytes",
			     *sig_len, rsa_ssa.key.n_size);
		*sig_len = rsa_ssa.key.n_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (!sig) {
		CRYPTO_TRACE("Parameter \"sig\" reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the Encoded Signature structure data */
		rsa_ssa.algo = algo;
		rsa_ssa.message.data = (uint8_t *)msg;
		rsa_ssa.message.length = msg_len;
		rsa_ssa.signature.data = (uint8_t *)sig;
		rsa_ssa.signature.length = rsa_ssa.key.n_size;
		rsa_ssa.salt_len = salt_len;
		rsa_ssa.mgf = &drvcrypt_rsa_mgf1;

		ret = TEE_ERROR_NOT_IMPLEMENTED;
		if (rsa->optional.ssa_sign)
			ret = rsa->optional.ssa_sign(&rsa_ssa);

		if (ret == TEE_ERROR_NOT_IMPLEMENTED)
			ret = drvcrypt_rsassa_sign(&rsa_ssa);

		/* Set the signature length */
		*sig_len = rsa_ssa.signature.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Encode signature algo (0x%" PRIx32
		     ") returned 0x%" PRIx32,
		     algo, ret);
	return ret;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len, const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_rsa *rsa = NULL;
	struct drvcrypt_rsa_ssa rsa_ssa = { };

	if (!key || !msg || !sig) {
		CRYPTO_TRACE("Input parameters reference error");
		goto out;
	}

	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		/* Prepare the Digest */
		rsa_ssa.hash_algo = TEE_DIGEST_HASH_TO_ALGO(algo);

		/* Check if the message length is digest hash size */
		ret = tee_alg_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
					      &rsa_ssa.digest_size);
		if (ret != TEE_SUCCESS)
			goto out;

		if (msg_len != rsa_ssa.digest_size) {
			CRYPTO_TRACE("Input msg length (%zu expected %zu)",
				     msg_len, rsa_ssa.digest_size);
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
	} else {
		rsa_ssa.hash_algo = 0;
		rsa_ssa.digest_size = 0;
	}

	/* Prepare the Key */
	rsa_ssa.key.key = key;
	rsa_ssa.key.isprivate = false;
	rsa_ssa.key.n_size = crypto_bignum_num_bytes(key->n);

	if (rsa_ssa.key.n_size > sig_len) {
		CRYPTO_TRACE("Signature length expected %zu",
			     rsa_ssa.key.n_size);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	rsa = drvcrypt_get_ops(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the Encoded Signature structure data */
		rsa_ssa.algo = algo;
		rsa_ssa.message.data = (uint8_t *)msg;
		rsa_ssa.message.length = msg_len;
		rsa_ssa.signature.data = (uint8_t *)sig;
		rsa_ssa.signature.length = sig_len;
		rsa_ssa.salt_len = salt_len;
		rsa_ssa.mgf = &drvcrypt_rsa_mgf1;

		ret = TEE_ERROR_NOT_IMPLEMENTED;
		if (rsa->optional.ssa_verify)
			ret = rsa->optional.ssa_verify(&rsa_ssa);

		if (ret == TEE_ERROR_NOT_IMPLEMENTED)
			ret = drvcrypt_rsassa_verify(&rsa_ssa);

	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Signature verif algo (0x%" PRIx32 ") returned 0x%" PRIx32,
		     algo, ret);

out:
	FTMN_CALLEE_DONE(ret);
	return ret;
}
