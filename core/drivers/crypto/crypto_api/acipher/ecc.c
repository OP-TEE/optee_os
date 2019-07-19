// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    ecc.c
 *
 * @brief   Crypto ECC interface implementation to enable HW driver.
 */
/* Global includes */
#include <crypto/crypto.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>

/**
 * @brief   Returns the key size in bits for the given
 *          ECC curve \a curve
 *
 * @param[in]  curve      ECC Curve ID
 *
 * @retval  0 if not supported
 * @retval  size in bits of the key
 */
static size_t get_ecc_keysize(uint32_t curve)
{
	size_t size_sec = 0;

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		size_sec = 192;
		break;

	case TEE_ECC_CURVE_NIST_P224:
		size_sec = 224;
		break;

	case TEE_ECC_CURVE_NIST_P256:
		size_sec = 256;
		break;

	case TEE_ECC_CURVE_NIST_P384:
		size_sec = 384;
		break;

	case TEE_ECC_CURVE_NIST_P521:
		/* Key size is 528 bits to be byte aligned */
		size_sec = 528;
		break;

	default:
		break;
	}

	return size_sec;
}

/**
 * @brief   Verify if the cryptographic algorithm \a aglo is valid for
 *          the ECC curve \a curve
 *
 * @param[in]  curve   ECC curve
 * @param[in]  algo    Cryptographic algorithm
 *
 * @retval 0    if valid
 * @retval (-1) if not valid
 */
static int algo_isvalid(uint32_t curve, uint32_t algo)
{
	int ret = (-1);
	uint8_t algo_op;
	uint8_t algo_id;
	uint8_t algo_curve;

	algo_op    = TEE_ALG_GET_CLASS(algo);
	algo_id    = TEE_ALG_GET_MAIN_ALG(algo);
	algo_curve = TEE_ALG_GET_DIGEST_HASH(algo);

	/* Check first if the aglo operation and the algo id are correct */
	if (((algo_op == TEE_OPERATION_ASYMMETRIC_SIGNATURE) &&
		 (algo_id == TEE_MAIN_ALGO_ECDSA)) ||
		((algo_op == TEE_OPERATION_KEY_DERIVATION) &&
		 (algo_id == TEE_MAIN_ALGO_ECDH))) {
		if (curve == algo_curve)
			ret = 0;
	}

	CRYPTO_TRACE("Validate algo 0x%"PRIx32" with curve %d return %d",
			algo, curve, ret);

	return ret;
}

/**
 * @brief   Allocate an ECC keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *key,
						size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_ecc *ecc = NULL;

	if ((!key) || (size_bits == 0)) {
		CRYPTO_TRACE("Bad parameters (key @0x%"PRIxPTR")(size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc = drvcrypt_getmod(CRYPTO_ECC);
	if (ecc)
		ret = ecc->alloc_keypair(key, size_bits);

	CRYPTO_TRACE("ECC Keypair (%d bits) alloc ret = 0x%"PRIx32"",
						size_bits, ret);
	return ret;
}

/**
 * @brief   Allocate an ECC public key
 *
 * @param[in]  key        Public Key
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *key,
						size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_ecc *ecc = NULL;

	if ((!key) || (size_bits == 0)) {
		CRYPTO_TRACE("Bad parameters (key @0x%"PRIxPTR")(size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc = drvcrypt_getmod(CRYPTO_ECC);
	if (ecc)
		ret = ecc->alloc_publickey(key, size_bits);

	CRYPTO_TRACE("ECC Public Key (%d bits) alloc ret = 0x%"PRIx32"",
						size_bits, ret);
	return ret;
}

/**
 * @brief   Free an ECC public key
 *
 * @param[in]  key        Public Key
 */
void crypto_acipher_free_ecc_public_key(struct ecc_public_key *key)
{
	struct drvcrypt_ecc *ecc = NULL;

	if (key) {
		ecc = drvcrypt_getmod(CRYPTO_ECC);
		if (ecc) {
			CRYPTO_TRACE("ECC Public Key free");
			ecc->free_publickey(key);
		}
	}
}

/**
 * @brief   Generates an ECC keypair
 *
 * @param[in]  key        Keypair
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct drvcrypt_ecc *ecc = NULL;
	size_t size_bits;

	/* Check input parameters */
	if (!key) {
		CRYPTO_TRACE("Parameters error key is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size_bits = get_ecc_keysize(key->curve);
	if (size_bits == 0)
		return TEE_ERROR_NOT_IMPLEMENTED;

	ecc = drvcrypt_getmod(CRYPTO_ECC);
	if (ecc)
		ret = ecc->gen_keypair(key, size_bits);

	CRYPTO_TRACE("ECC Keypair (%d bits) generate ret = 0x%"PRIx32"",
						size_bits, ret);

	return ret;
}

/**
 * @brief   Sign the message \a msg.
 *          Message is signed with the ECC Key given by the Keypair \a key
 *
 * @param[in]     algo       ECC algorithm
 * @param[in]     key        ECC Keypair
 * @param[in]     msg        Message to sign
 * @param[in]     msg_len    Length of the message (bytes)
 * @param[out]    sig        Signature
 * @param[in/out] sig_len    Length of the signature (bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 * @retval TEE_ERROR_SECURITY          Invalid message
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_ecc_sign(uint32_t algo,
					struct ecc_keypair *key,
					const uint8_t *msg, size_t msg_len,
					uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct drvcrypt_ecc       *ecc = NULL;
	struct drvcrypt_sign_data sdata;
	size_t                    size_bits;
	size_t                    size_bytes;

	/* Verify first if the input parameters */
	if ((!key) || (!msg) || (!sig) || (!sig_len)) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (algo_isvalid(key->curve, algo) != 0)
		return ret;

	size_bits = get_ecc_keysize(key->curve);
	if (size_bits == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Verify the signature length function of the key size */
	size_bytes = size_bits / 8;
	if (*sig_len < (2 * size_bytes)) {
		CRYPTO_TRACE("Signature len (%d) too short expected %d bytes",
					*sig_len, (2 * size_bytes));
		*sig_len = 2 * size_bytes;
		return TEE_ERROR_SHORT_BUFFER;
	}

	ecc = drvcrypt_getmod(CRYPTO_ECC);
	if (ecc) {
		/*
		 * Prepare the Signature structure data
		 */
		sdata.algo             = algo;
		sdata.key              = key;
		sdata.size_sec         = size_bytes;
		sdata.message.data     = (uint8_t *)msg;
		sdata.message.length   = msg_len;
		sdata.signature.data   = (uint8_t *)sig;
		sdata.signature.length = *sig_len;

		ret = ecc->sign(&sdata);

		/* Set the signature length */
		*sig_len = sdata.signature.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Sign algo (0x%"PRIx32") returned 0x%"PRIx32"",
		algo, ret);

	return ret;
}

/**
 * @brief   Verify the signature of the message \a msg.
 *          Message is signed with the ECC Key given by the Public Key \a key
 *
 * @param[in]  algo       ECC algorithm
 * @param[in]  key        ECC Public key
 * @param[in]  msg        Message to sign
 * @param[in]  msg_len    Length of the message (bytes)
 * @param[in]  sig        Signature
 * @param[in]  sig_len    Length of the signature (bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature is not valid
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_ecc_verify(uint32_t algo,
					struct ecc_public_key *key,
					const uint8_t *msg, size_t msg_len,
					const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct drvcrypt_ecc       *ecc = NULL;
	struct drvcrypt_sign_data sdata;
	size_t                    size_bits;
	size_t                    size_bytes;

	/* Verify first if the input parameters */
	if ((!key) || (!msg) || (!sig)) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (algo_isvalid(key->curve, algo) != 0)
		return ret;

	size_bits = get_ecc_keysize(key->curve);
	if (size_bits == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Verify the signature length function of the key size */
	size_bytes = size_bits / 8;
	if (sig_len != (2 * size_bytes)) {
		CRYPTO_TRACE("Signature len (%d) is invalid expected %d bytes",
					sig_len, (2 * size_bytes));
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	ecc = drvcrypt_getmod(CRYPTO_ECC);
	if (ecc) {
		/*
		 * Prepare the Signature structure data
		 */
		sdata.algo             = algo;
		sdata.key              = key;
		sdata.size_sec         = size_bytes;
		sdata.message.data     = (uint8_t *)msg;
		sdata.message.length   = msg_len;
		sdata.signature.data   = (uint8_t *)sig;
		sdata.signature.length = sig_len;

		ret = ecc->verify(&sdata);
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Verify algo (0x%"PRIx32") returned 0x%"PRIx32"",
		algo, ret);

	return ret;
}

/**
 * @brief   Compute the shared secret data from ECC Private key \a private_key
 *          and Public Key \a public_key
 *
 * @param[in]  private_key  ECC Private key
 * @param[in]  public_key   ECC Public key
 * @param[in]  secret       Secret
 * @param[in]  secret_len   Length of the secret (bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 */
TEE_Result crypto_acipher_ecc_shared_secret(
					struct ecc_keypair *private_key,
					struct ecc_public_key *public_key,
					void *secret, unsigned long *secret_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct drvcrypt_ecc         *ecc = NULL;
	struct drvcrypt_secret_data sdata;
	size_t                      size_bits;

	/* Verify first if the input parameters */
	if ((!private_key) || (!public_key) || (!secret) || (!secret_len)) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (private_key->curve != public_key->curve) {
		CRYPTO_TRACE("Private Key curve (%d) != Public Key curve (%d)",
				private_key->curve, public_key->curve);
		return ret;
	}

	size_bits = get_ecc_keysize(public_key->curve);
	if (size_bits == 0)
		return ret;

	if (*secret_len < (size_bits / 8))
		return TEE_ERROR_SHORT_BUFFER;

	ecc = drvcrypt_getmod(CRYPTO_ECC);
	if (ecc) {
		/*
		 * Prepare the Secret structure data
		 */
		sdata.key_priv      = private_key;
		sdata.key_pub       = public_key;
		sdata.size_sec      = size_bits / 8;
		sdata.secret.data   = secret;
		sdata.secret.length = *secret_len;

		ret = ecc->shared_secret(&sdata);

		/* Set the secret length */
		*secret_len = sdata.secret.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Shared Secret returned 0x%"PRIx32"", ret);

	return ret;
}

