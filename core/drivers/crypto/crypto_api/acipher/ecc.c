// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Crypto ECC interface implementation to enable HW driver.
 */
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

/*
 * Returns the key size in bytes for the given ECC curve
 *
 * @curve   ECC Curve ID
 */
static size_t get_ecc_key_size_bytes(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		return 24;

	case TEE_ECC_CURVE_NIST_P224:
		return 28;

	case TEE_ECC_CURVE_NIST_P256:
		return 32;

	case TEE_ECC_CURVE_NIST_P384:
		return 48;

	case TEE_ECC_CURVE_NIST_P521:
		return 66;

	default:
		return 0;
	}
}

/*
 * Verify if the cryptographic algorithm @algo is valid for
 * the ECC curve
 *
 * @curve   ECC curve
 * @algo    Cryptographic algorithm
 */
static bool algo_is_valid(uint32_t curve, uint32_t algo)
{
	unsigned int algo_op = TEE_ALG_GET_CLASS(algo);
	unsigned int algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int algo_curve = TEE_ALG_GET_DIGEST_HASH(algo);

	/* Check first the algo operation and id */
	if ((algo_op == TEE_OPERATION_ASYMMETRIC_SIGNATURE &&
	     algo_id == TEE_MAIN_ALGO_ECDSA) ||
	    (algo_op == TEE_OPERATION_KEY_DERIVATION &&
	     algo_id == TEE_MAIN_ALGO_ECDH)) {
		if (curve == algo_curve) {
			CRYPTO_TRACE("Algo 0x%" PRIx32 " curve 0x%" PRIx32
				     " is valid", algo, curve);
			return true;
		}
	}

	CRYPTO_TRACE("Algo 0x%" PRIx32 " curve 0x%" PRIx32 " is not valid",
		     algo, curve);

	return false;
}

/*
 * Free an ECC public key
 *
 * @key   Public Key
 */
static void ecc_free_public_key(struct ecc_public_key *key)
{
	struct drvcrypt_ecc *ecc = NULL;

	if (key) {
		ecc = drvcrypt_get_ops(CRYPTO_ECC);
		if (ecc) {
			CRYPTO_TRACE("ECC Public Key free");
			ecc->free_publickey(key);
		}
	}
}

/*
 * Generates an ECC keypair
 *
 * @key        Keypair
 * @size_bits  Key size in bits
 */
static TEE_Result ecc_generate_keypair(struct ecc_keypair *key,
				       size_t size_bits __maybe_unused)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_ecc *ecc = NULL;
	size_t key_size_bits = 0;

	/* Check input parameters */
	if (!key) {
		CRYPTO_TRACE("Parameters error key is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key_size_bits = get_ecc_key_size_bytes(key->curve) * 8;

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc)
		ret = ecc->gen_keypair(key, key_size_bits);

	CRYPTO_TRACE("ECC Keypair (%zu bits) generate ret = 0x%" PRIx32,
		     key_size_bits, ret);

	return ret;
}

/*
 * Sign the message with the ECC Key given by the Keypair
 *
 * @algo       ECC algorithm
 * @key        ECC Keypair
 * @msg        Message to sign
 * @msg_len    Length of the message (bytes)
 * @sig        Signature
 * @sig_len    [in/out] Length of the signature (bytes)
 */
static TEE_Result ecc_sign(uint32_t algo, struct ecc_keypair *key,
			   const uint8_t *msg, size_t msg_len, uint8_t *sig,
			   size_t *sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_ecc *ecc = NULL;
	struct drvcrypt_sign_data sdata = { };
	size_t size_bytes = 0;

	/* Verify first the input parameters */
	if (!key || !msg || !sig || !sig_len) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (!algo_is_valid(key->curve, algo))
		return ret;

	size_bytes = get_ecc_key_size_bytes(key->curve);
	if (!size_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Verify the signature length function of the key size */
	if (*sig_len < 2 * size_bytes) {
		CRYPTO_TRACE("Length (%zu) too short expected %zu bytes",
			     *sig_len, 2 * size_bytes);
		*sig_len = 2 * size_bytes;
		return TEE_ERROR_SHORT_BUFFER;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc) {
		/*
		 * Prepare the Signature structure data
		 */
		sdata.algo = algo;
		sdata.key = key;
		sdata.size_sec = size_bytes;
		sdata.message.data = (uint8_t *)msg;
		sdata.message.length = msg_len;
		sdata.signature.data = (uint8_t *)sig;
		sdata.signature.length = *sig_len;

		ret = ecc->sign(&sdata);

		/* Set the signature length */
		*sig_len = sdata.signature.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Sign algo (0x%" PRIx32 ") returned 0x%" PRIx32, algo,
		     ret);

	return ret;
}

/*
 * Verify if signature is signed with the given public key.
 *
 * @algo       ECC algorithm
 * @key        ECC Public key
 * @msg        Message to sign
 * @msg_len    Length of the message (bytes)
 * @sig        Signature
 * @sig_len    Length of the signature (bytes)
 */
static TEE_Result ecc_verify(uint32_t algo, struct ecc_public_key *key,
			     const uint8_t *msg, size_t msg_len,
			     const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_ecc *ecc = NULL;
	struct drvcrypt_sign_data sdata = { };
	size_t size_bytes = 0;

	/* Verify first the input parameters */
	if (!key || !msg || !sig) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (!algo_is_valid(key->curve, algo))
		return ret;

	size_bytes = get_ecc_key_size_bytes(key->curve);
	if (!size_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Verify the signature length against key size */
	if (sig_len != 2 * size_bytes) {
		CRYPTO_TRACE("Length (%zu) is invalid expected %zu bytes",
			     sig_len, 2 * size_bytes);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc) {
		sdata.algo = algo;
		sdata.key = key;
		sdata.size_sec = size_bytes;
		sdata.message.data = (uint8_t *)msg;
		sdata.message.length = msg_len;
		sdata.signature.data = (uint8_t *)sig;
		sdata.signature.length = sig_len;

		ret = ecc->verify(&sdata);
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Verify algo (0x%" PRIx32 ") returned 0x%" PRIx32, algo,
		     ret);

	return ret;
}

/*
 * Compute the shared secret data from ECC Private key and Public Key
 *
 * @private_key  ECC Private key
 * @public_key   ECC Public key
 * @secret       Secret
 * @secret_len   Length of the secret (bytes)
 */
static TEE_Result ecc_shared_secret(struct ecc_keypair *private_key,
				    struct ecc_public_key *public_key,
				    void *secret, unsigned long *secret_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_ecc *ecc = NULL;
	struct drvcrypt_secret_data sdata = { };
	size_t size_bytes = 0;

	/* Verify first the input parameters */
	if (!private_key || !public_key || !secret || !secret_len) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (private_key->curve != public_key->curve) {
		CRYPTO_TRACE("Private Key curve (%d) != Public Key curve (%d)",
			     private_key->curve, public_key->curve);
		return ret;
	}

	size_bytes = get_ecc_key_size_bytes(public_key->curve);
	if (!size_bytes)
		return ret;

	if (*secret_len < size_bytes) {
		*secret_len = size_bytes;
		return TEE_ERROR_SHORT_BUFFER;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc) {
		/*
		 * Prepare the Secret structure data
		 */
		sdata.key_priv = private_key;
		sdata.key_pub = public_key;
		sdata.size_sec = size_bytes;
		sdata.secret.data = secret;
		sdata.secret.length = *secret_len;

		ret = ecc->shared_secret(&sdata);

		/* Set the secret length */
		*secret_len = sdata.secret.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Shared Secret returned 0x%" PRIx32, ret);

	return ret;
}

static const struct crypto_ecc_keypair_ops ecc_keypair_ops = {
	.generate = ecc_generate_keypair,
	.sign = ecc_sign,
	.shared_secret = ecc_shared_secret,
};

TEE_Result drvcrypt_asym_alloc_ecc_keypair(struct ecc_keypair *key,
					   uint32_t type, size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_ecc *ecc = NULL;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Bad parameters (key @%p)(size %zu bits)", key,
			     size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (type) {
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
		ecc = drvcrypt_get_ops(CRYPTO_ECC);
		break;
	default:
		break;
	}

	if (ecc)
		ret = ecc->alloc_keypair(key, size_bits);

	if (!ret)
		key->ops = &ecc_keypair_ops;

	CRYPTO_TRACE("ECC Keypair (%zu bits) alloc ret = 0x%" PRIx32, size_bits,
		     ret);
	return ret;
}

static const struct crypto_ecc_public_ops ecc_public_key_ops = {
	.free = ecc_free_public_key,
	.verify = ecc_verify,
};

TEE_Result drvcrypt_asym_alloc_ecc_public_key(struct ecc_public_key *key,
					      uint32_t type, size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_ecc *ecc = NULL;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Bad parameters (key @%p)(size %zu bits)", key,
			     size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (type) {
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
		ecc = drvcrypt_get_ops(CRYPTO_ECC);
		break;
	default:
		break;
	}

	if (ecc)
		ret = ecc->alloc_publickey(key, size_bits);

	if (!ret)
		key->ops = &ecc_public_key_ops;

	CRYPTO_TRACE("ECC Public Key (%zu bits) alloc ret = 0x%" PRIx32,
		     size_bits, ret);
	return ret;
}
