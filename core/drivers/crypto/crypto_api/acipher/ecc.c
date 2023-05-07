// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Crypto ECC interface implementation to enable HW driver.
 */
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
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
	case TEE_ECC_CURVE_SM2:
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
 * Returns the key size in bits for the given ECC curve
 *
 * @curve   ECC Curve ID
 */

static size_t get_ecc_key_size_bits(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
	case TEE_ECC_CURVE_NIST_P224:
	case TEE_ECC_CURVE_NIST_P256:
	case TEE_ECC_CURVE_NIST_P384:
	case TEE_ECC_CURVE_SM2:
		return get_ecc_key_size_bytes(curve) * 8;

	case TEE_ECC_CURVE_NIST_P521:
		return 521;

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

	if (algo_op == TEE_OPERATION_ASYMMETRIC_SIGNATURE &&
	    algo_id == TEE_MAIN_ALGO_SM2_DSA_SM3) {
		if (curve == TEE_ECC_CURVE_SM2)
			return true;
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

	key_size_bits = get_ecc_key_size_bits(key->curve);

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
	if (!key || !msg || !sig_len) {
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

	if (!sig) {
		CRYPTO_TRACE("Parameter \"sig\" reference error");
		return TEE_ERROR_BAD_PARAMETERS;
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
	if (!private_key || !public_key || !secret_len) {
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

	if (!secret) {
		CRYPTO_TRACE("Parameter \"secret\" reference error");
		return ret;
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

static TEE_Result ecc_sm2_encrypt(struct ecc_public_key *key,
				  const uint8_t *src, size_t src_len,
				  uint8_t *dst, size_t *dst_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_ecc_ed cdata = { };
	struct drvcrypt_ecc *ecc = NULL;
	size_t ciphertext_len = 0;
	size_t size_bytes = 0;

	ecc = drvcrypt_get_ops(CRYPTO_ECC);

	size_bytes = get_ecc_key_size_bytes(key->curve);
	if (!size_bytes) {
		CRYPTO_TRACE("Curve 0x%08"PRIx32" not supported", key->curve);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Uncompressed form indicator */
	dst[0] = 0x04;

	ciphertext_len = 2 * size_bytes + src_len + TEE_SM3_HASH_SIZE;

	cdata.key = key;
	cdata.size_sec = size_bytes;
	cdata.plaintext.data = (uint8_t *)src;
	cdata.plaintext.length = src_len;
	cdata.ciphertext.data = dst + 1;
	cdata.ciphertext.length = ciphertext_len;

	ret = ecc->encrypt(&cdata);

	if (!ret || ret == TEE_ERROR_SHORT_BUFFER)
		*dst_len = cdata.ciphertext.length + 1;

	return ret;
}

static TEE_Result ecc_encrypt(struct ecc_public_key *key,
			      const uint8_t *src, size_t src_len,
			      uint8_t *dst, size_t *dst_len)
{
	struct drvcrypt_ecc *ecc = NULL;

	if (!key || !src || !dst) {
		CRYPTO_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (!ecc || !ecc->encrypt)
		return TEE_ERROR_NOT_IMPLEMENTED;

	switch (key->curve) {
	case TEE_ECC_CURVE_SM2:
		return ecc_sm2_encrypt(key, src, src_len, dst, dst_len);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static TEE_Result ecc_sm2_decrypt(struct ecc_keypair *key,
				  const uint8_t *src, size_t src_len,
				  uint8_t *dst, size_t *dst_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_ecc_ed cdata = { };
	struct drvcrypt_ecc *ecc = NULL;
	uint8_t *ciphertext = NULL;
	size_t ciphertext_len = 0;
	size_t size_bytes = 0;
	size_t plaintext_len = 0;
	/* Point Compression */
	uint8_t pc = 0;

	ecc = drvcrypt_get_ops(CRYPTO_ECC);

	size_bytes = get_ecc_key_size_bytes(key->curve);
	if (!size_bytes) {
		CRYPTO_TRACE("Curve 0x%08"PRIx32" not supported", key->curve);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	pc = src[0];
	switch (pc) {
	case 0x02:
	case 0x03:
		/* Compressed form */
		return TEE_ERROR_NOT_SUPPORTED;
	case 0x04:
		/* Uncompressed form */
		ciphertext = (uint8_t *)src + 1;
		ciphertext_len = src_len - 1;
		break;
	case 0x06:
	case 0x07:
		/* Hybrid form */
		return TEE_ERROR_NOT_SUPPORTED;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (SUB_OVERFLOW(ciphertext_len, 2 * size_bytes + TEE_SM3_HASH_SIZE,
			 &plaintext_len))
		return TEE_ERROR_BAD_PARAMETERS;

	cdata.key = key;
	cdata.size_sec = size_bytes;
	cdata.ciphertext.data = ciphertext;
	cdata.ciphertext.length = ciphertext_len;
	cdata.plaintext.data = dst;
	cdata.plaintext.length = plaintext_len;

	ret = ecc->decrypt(&cdata);

	/* Set the plaintext length */
	if (!ret || ret == TEE_ERROR_SHORT_BUFFER)
		*dst_len = cdata.plaintext.length;

	return ret;
}

static TEE_Result ecc_decrypt(struct ecc_keypair *key,
			      const uint8_t *src, size_t src_len,
			      uint8_t *dst, size_t *dst_len)
{
	struct drvcrypt_ecc *ecc = NULL;

	if (!key || !src || !dst) {
		CRYPTO_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (!ecc || !ecc->decrypt)
		return TEE_ERROR_NOT_IMPLEMENTED;

	switch (key->curve) {
	case TEE_ECC_CURVE_SM2:
		return ecc_sm2_decrypt(key, src, src_len, dst, dst_len);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static const struct crypto_ecc_keypair_ops ecc_keypair_ops = {
	.generate = ecc_generate_keypair,
	.sign = ecc_sign,
	.shared_secret = ecc_shared_secret,
	.decrypt = ecc_decrypt,
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
	case TEE_TYPE_SM2_PKE_KEYPAIR:
	case TEE_TYPE_SM2_DSA_KEYPAIR:
		ecc = drvcrypt_get_ops(CRYPTO_ECC);
		break;
	default:
		break;
	}

	if (ecc)
		ret = ecc->alloc_keypair(key, type, size_bits);

	if (!ret) {
		key->ops = &ecc_keypair_ops;

		/* ecc->alloc_keypair() can not get type to set curve */
		switch (type) {
		case TEE_TYPE_SM2_PKE_KEYPAIR:
		case TEE_TYPE_SM2_DSA_KEYPAIR:
			key->curve = TEE_ECC_CURVE_SM2;
			break;
		default:
			break;
		}
	}

	CRYPTO_TRACE("ECC Keypair (%zu bits) alloc ret = 0x%" PRIx32, size_bits,
		     ret);
	return ret;
}

static const struct crypto_ecc_public_ops ecc_public_key_ops = {
	.free = ecc_free_public_key,
	.verify = ecc_verify,
	.encrypt = ecc_encrypt,
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
	case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
	case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
		ecc = drvcrypt_get_ops(CRYPTO_ECC);
		break;
	default:
		break;
	}

	if (ecc)
		ret = ecc->alloc_publickey(key, type, size_bits);

	if (!ret) {
		key->ops = &ecc_public_key_ops;

		/* ecc->alloc_publickey() can not get type to set curve */
		switch (type) {
		case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
		case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
			key->curve = TEE_ECC_CURVE_SM2;
			break;
		default:
			break;
		}
	}

	CRYPTO_TRACE("ECC Public Key (%zu bits) alloc ret = 0x%" PRIx32,
		     size_bits, ret);
	return ret;
}
