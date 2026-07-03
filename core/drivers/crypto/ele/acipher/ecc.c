// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 NXP
 */
#include <config.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <ecc.h>
#include <initcall.h>
#include <key_mgmt.h>
#include <sign_verify.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <utee_defines.h>
#include <util.h>

/*
 * Software fallback ops retrieved once at init time.  Used for curves and
 * algorithms that ELE does not support (SM2, ECDH, …).
 */
static const struct crypto_ecc_keypair_ops *pair_ops;
static const struct crypto_ecc_public_ops *pub_ops;

/* Map a TEE curve identifier to the key size in bits. */
static TEE_Result curve_to_bits(uint32_t curve, size_t *key_size_bits)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P224:
		*key_size_bits = 224;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*key_size_bits = 256;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*key_size_bits = 384;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*key_size_bits = 521;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return TEE_SUCCESS;
}

/*
 * Derive the ELE algorithm identifier from the TEE algorithm and validate
 * that the curve size matches the digest size.
 *
 * Returns TEE_SUCCESS and sets *key_size_bits / *ele_algo on success, or
 * TEE_ERROR_NOT_IMPLEMENTED for unsupported combinations.
 */
static TEE_Result get_key_size_and_algo(uint32_t curve, uint32_t tee_algo,
					size_t digest_size,
					size_t *key_size_bits,
					uint32_t *ele_algo)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t bits = 0;

	res = curve_to_bits(curve, &bits);
	if (res)
		return res;

	switch (tee_algo) {
	case TEE_ALG_ECDSA_SHA224:
		if (bits != 224 || digest_size != TEE_SHA224_HASH_SIZE)
			goto err;
		*ele_algo = ELE_ALGO_ECDSA_SHA224;
		break;
	case TEE_ALG_ECDSA_SHA256:
		if (bits != 256 || digest_size != TEE_SHA256_HASH_SIZE)
			goto err;
		*ele_algo = ELE_ALGO_ECDSA_SHA256;
		break;
	case TEE_ALG_ECDSA_SHA384:
		if (bits != 384 || digest_size != TEE_SHA384_HASH_SIZE)
			goto err;
		*ele_algo = ELE_ALGO_ECDSA_SHA384;
		break;
	case TEE_ALG_ECDSA_SHA512:
		if (bits != 521 || digest_size != TEE_SHA512_HASH_SIZE)
			goto err;
		*ele_algo = ELE_ALGO_ECDSA_SHA512;
		break;
	default:
		DMSG("Unsupported algorithm %#" PRIx32, tee_algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	*key_size_bits = bits;

	return TEE_SUCCESS;

err:
	DMSG("Curve size / digest size mismatch for algo %#" PRIx32, tee_algo);
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result do_allocate_keypair(struct ecc_keypair *key, uint32_t type,
				      size_t size_bits)
{
	switch (type) {
	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_SM2_PKE_KEYPAIR:
	case TEE_TYPE_SM2_DSA_KEYPAIR:
		/* Not supported by ELE — let the framework use software */
		return TEE_ERROR_NOT_IMPLEMENTED;
	default:
		break;
	}

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(key, 0, sizeof(*key));

	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto err;

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err;

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err;

	return TEE_SUCCESS;

err:
	crypto_bignum_free(&key->d);
	crypto_bignum_free(&key->x);
	crypto_bignum_free(&key->y);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result do_allocate_publickey(struct ecc_public_key *key,
					uint32_t type, size_t size_bits)
{
	switch (type) {
	case TEE_TYPE_ECDH_PUBLIC_KEY:
	case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
	case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
		/* Not supported by ELE — let the framework use software */
		return TEE_ERROR_NOT_IMPLEMENTED;
	default:
		break;
	}

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(key, 0, sizeof(*key));

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err;

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err;

	return TEE_SUCCESS;

err:
	crypto_bignum_free(&key->x);
	crypto_bignum_free(&key->y);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static void do_free_publickey(struct ecc_public_key *key)
{
	if (!key)
		return;

	crypto_bignum_free(&key->x);
	crypto_bignum_free(&key->y);
}

static TEE_Result do_gen_keypair(struct ecc_keypair *key, size_t size_bits)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t key_size_bits = 0;
	size_t key_size = 0;
	uint8_t *pub_buf = NULL;
	uint8_t *priv_buf = NULL;

	if (!key || !size_bits)
		return TEE_ERROR_BAD_PARAMETERS;

	res = curve_to_bits(key->curve, &key_size_bits);
	if (res) {
		if (!IS_ENABLED(CFG_IMX_ELE_ECC_DRV_FALLBACK))
			return TEE_ERROR_NOT_IMPLEMENTED;
		DMSG("ELE ECC keygen fallback to software");
		return pair_ops->generate(key, size_bits);
	}

	key_size = ROUNDUP_DIV(key_size_bits, 8);

	pub_buf = calloc(1, key_size * 2);
	if (!pub_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	priv_buf = calloc(1, key_size);
	if (!priv_buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = imx_ele_generate_keypair(priv_buf, key_size,
				       pub_buf, key_size * 2,
				       ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
				       key_size_bits);
	if (res) {
		EMSG("ELE key generation failed");
		goto out;
	}

	crypto_bignum_bin2bn(pub_buf, key_size, key->x);
	crypto_bignum_bin2bn(pub_buf + key_size, key_size, key->y);
	crypto_bignum_bin2bn(priv_buf, key_size, key->d);

out:
	free(pub_buf);
	free(priv_buf);

	return res;
}

static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ecc_keypair *key = NULL;
	size_t key_size_bits = 0;
	size_t key_size = 0;
	uint32_t ele_algo = 0;
	uint8_t *priv_buf = NULL;
	size_t d_size = 0;
	size_t sig_len = 0;

	if (!sdata || !sdata->key || !sdata->message.data ||
	    !sdata->signature.data || !sdata->message.length)
		return TEE_ERROR_BAD_PARAMETERS;

	key = sdata->key;

	res = get_key_size_and_algo(key->curve, sdata->algo,
				    sdata->message.length,
				    &key_size_bits, &ele_algo);
	if (res) {
		if (!IS_ENABLED(CFG_IMX_ELE_ECC_DRV_FALLBACK))
			return TEE_ERROR_NOT_IMPLEMENTED;
		DMSG("ELE ECC sign fallback to software");
		return pair_ops->sign(sdata->algo, sdata->key,
				      sdata->message.data,
				      sdata->message.length,
				      sdata->signature.data,
				      &sdata->signature.length);
	}

	key_size = ROUNDUP_DIV(key_size_bits, 8);
	sig_len = key_size * 2;

	priv_buf = calloc(1, key_size);
	if (!priv_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * The bignum representation may be shorter than the key size when
	 * leading zeros are stripped; right-align the scalar in the buffer.
	 */
	d_size = crypto_bignum_num_bytes(key->d);
	crypto_bignum_bn2bin(key->d, priv_buf + key_size - d_size);

	res = imx_ele_signature_generate(priv_buf, key_size,
					 sdata->message.data,
					 sdata->message.length,
					 sdata->signature.data,
					 sig_len,
					 ele_algo,
					 ELE_SIG_GEN_MSG_TYPE_DIGEST,
					 ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
					 key_size_bits);
	if (res) {
		EMSG("ELE signature generation failed");
		goto out;
	}

	sdata->signature.length = sig_len;

out:
	free(priv_buf);

	return res;
}

static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ecc_public_key *key = NULL;
	size_t key_size_bits = 0;
	size_t key_size = 0;
	uint32_t ele_algo = 0;
	uint8_t *pub_buf = NULL;
	size_t x_size = 0;
	size_t y_size = 0;

	if (!sdata || !sdata->key || !sdata->message.data ||
	    !sdata->signature.data || !sdata->message.length ||
	    !sdata->signature.length)
		return TEE_ERROR_BAD_PARAMETERS;

	key = sdata->key;

	res = get_key_size_and_algo(key->curve, sdata->algo,
				    sdata->message.length,
				    &key_size_bits, &ele_algo);
	if (res) {
		if (!IS_ENABLED(CFG_IMX_ELE_ECC_DRV_FALLBACK))
			return TEE_ERROR_NOT_IMPLEMENTED;
		DMSG("ELE ECC verify fallback to software");
		return pub_ops->verify(sdata->algo, sdata->key,
				       sdata->message.data,
				       sdata->message.length,
				       sdata->signature.data,
				       sdata->signature.length);
	}

	key_size = ROUNDUP_DIV(key_size_bits, 8);

	pub_buf = calloc(1, key_size * 2);
	if (!pub_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Right-align each coordinate in its half of the buffer to handle
	 * bignums with stripped leading zeros.
	 */
	x_size = crypto_bignum_num_bytes(key->x);
	crypto_bignum_bn2bin(key->x, pub_buf + key_size - x_size);

	y_size = crypto_bignum_num_bytes(key->y);
	crypto_bignum_bn2bin(key->y, pub_buf + key_size + (key_size - y_size));

	res = imx_ele_signature_verify(pub_buf, key_size * 2,
				       sdata->message.data,
				       sdata->message.length,
				       sdata->signature.data,
				       sdata->signature.length,
				       key_size_bits,
				       ELE_KEY_TYPE_ECC_PUB_KEY_SECP_R1,
				       ele_algo,
				       ELE_SIG_GEN_MSG_TYPE_DIGEST);
	if (res)
		EMSG("ELE signature verification failed: res=0x%x", res);

	free(pub_buf);

	return res;
}

static struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair   = do_allocate_keypair,
	.alloc_publickey = do_allocate_publickey,
	.free_publickey  = do_free_publickey,
	.gen_keypair     = do_gen_keypair,
	.sign            = do_sign,
	.verify          = do_verify,
};

TEE_Result imx_ele_ecc_init(void)
{
	pub_ops = crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDSA_PUBLIC_KEY);
	if (!pub_ops)
		return TEE_ERROR_GENERIC;

	pair_ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDSA_KEYPAIR);
	if (!pair_ops)
		return TEE_ERROR_GENERIC;

	if (drvcrypt_register_ecc(&driver_ecc))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
