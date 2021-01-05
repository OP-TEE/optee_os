// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <der.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <drvcrypt_math.h>
#include <initcall.h>
#include <se050.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <tee_api_defines_extensions.h>
#include <utee_defines.h>
#include <util.h>

static uint32_t algo_tee2se050(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_ECDSA_P192:
		return kAlgorithm_SSS_ECDSA_SHA1;
	case TEE_ALG_ECDSA_P224:
		return kAlgorithm_SSS_ECDSA_SHA224;
	case TEE_ALG_ECDSA_P256:
		return kAlgorithm_SSS_ECDSA_SHA256;
	case TEE_ALG_ECDSA_P384:
		return kAlgorithm_SSS_ECDSA_SHA384;
	case TEE_ALG_ECDSA_P521:
		return kAlgorithm_SSS_ECDSA_SHA512;
	default:
		EMSG("algorithm %#"PRIx32" not enabled", algo);
		return kAlgorithm_None;
	}
}

static uint32_t cipher_tee2se050(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
	case TEE_ECC_CURVE_NIST_P224:
	case TEE_ECC_CURVE_NIST_P256:
	case TEE_ECC_CURVE_NIST_P384:
	case TEE_ECC_CURVE_NIST_P521:
		return kSSS_CipherType_EC_NIST_P;
	default:
		EMSG("cipher %#"PRIx32" not enabled", curve);
		return kSSS_CipherType_NONE;
	}
}

static uint32_t curve_tee2se050(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		return kSE05x_ECCurve_NIST_P192;
	case TEE_ECC_CURVE_NIST_P224:
		return kSE05x_ECCurve_NIST_P224;
	case TEE_ECC_CURVE_NIST_P256:
		return kSE05x_ECCurve_NIST_P256;
	case TEE_ECC_CURVE_NIST_P384:
		return kSE05x_ECCurve_NIST_P384;
	case TEE_ECC_CURVE_NIST_P521:
		return kSE05x_ECCurve_NIST_P521;
	default:
		EMSG("curve %#"PRIx32" not enabled", curve);
		return kSE05x_ECCurve_NA;
	}
}

static uint32_t curve_se0502tee(uint32_t curve)
{
	switch (curve) {
	case kSE05x_ECCurve_NIST_P192:
		return TEE_ECC_CURVE_NIST_P192;
	case kSE05x_ECCurve_NIST_P224:
		return TEE_ECC_CURVE_NIST_P224;
	case kSE05x_ECCurve_NIST_P256:
		return TEE_ECC_CURVE_NIST_P256;
	case kSE05x_ECCurve_NIST_P384:
		return TEE_ECC_CURVE_NIST_P384;
	case kSE05x_ECCurve_NIST_P521:
		return TEE_ECC_CURVE_NIST_P521;
	default:
		EMSG("curve %#"PRIx32" not enabled", curve);
		return TEE_CRYPTO_ELEMENT_NONE;
	}
}

static bool bn_alloc_max(struct bignum **s)
{
	*s = crypto_bignum_allocate(4096);

	return *s;
}

static TEE_Result ecc_get_key_size(uint32_t curve, uint32_t algo,
				   size_t *bytes, size_t *bits)
{
	/*
	 * Note GPv1.1 indicates TEE_ALG_ECDH_NIST_P192_DERIVE_SHARED_SECRET
	 * but defines TEE_ALG_ECDH_P192
	 */
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*bits = 192;
		*bytes = 24;
		if (algo && algo != TEE_ALG_ECDSA_P192 &&
		    algo != TEE_ALG_ECDH_P192)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*bits = 224;
		*bytes = 28;
		if (algo && algo != TEE_ALG_ECDSA_P224 &&
		    algo != TEE_ALG_ECDH_P224)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*bits = 256;
		*bytes = 32;
		if (algo && algo != TEE_ALG_ECDSA_P256 &&
		    algo != TEE_ALG_ECDH_P256)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*bits = 384;
		*bytes = 48;
		if (algo && algo != TEE_ALG_ECDSA_P384 &&
		    algo != TEE_ALG_ECDH_P384)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*bits = 521;
		*bytes = 66;
		if (algo && algo != TEE_ALG_ECDSA_P521 &&
		    algo != TEE_ALG_ECDH_P521)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result ecc_get_msg_size(uint32_t algo, size_t *len)
{
	switch (algo) {
	case kAlgorithm_SSS_ECDSA_SHA1:
		*len = MIN((size_t)TEE_SHA1_HASH_SIZE, *len);
		break;
	case kAlgorithm_SSS_ECDSA_SHA224:
		*len = MIN((size_t)TEE_SHA224_HASH_SIZE, *len);
		break;
	case kAlgorithm_SSS_ECDSA_SHA256:
		*len = MIN((size_t)TEE_SHA256_HASH_SIZE, *len);
		break;
	case kAlgorithm_SSS_ECDSA_SHA384:
		*len = MIN((size_t)TEE_SHA384_HASH_SIZE, *len);
		break;
	case kAlgorithm_SSS_ECDSA_SHA512:
		*len = MIN((size_t)TEE_SHA512_HASH_SIZE, *len);
		break;
	default:
		EMSG("invalid se050 %#"PRIx32" algorithm", algo);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result set_binary_data(struct bignum *b, size_t key_len, uint8_t **p,
				  size_t *len)
{
	size_t a = crypto_bignum_num_bytes(b);
	uint8_t leading_zeros = 0;
	uint8_t *q = NULL;

	if (!a)
		return TEE_ERROR_GENERIC;

	if (a != key_len) {
		leading_zeros = key_len - a;
		a = key_len;
	}

	q = calloc(1, a);
	if (!q)
		return TEE_ERROR_OUT_OF_MEMORY;

	crypto_bignum_bn2bin(b, q + leading_zeros);
	*len = a;
	*p = q;

	return TEE_SUCCESS;
}

static TEE_Result se050_inject_public_key(sss_se05x_object_t *k_object,
					  struct ecc_public_key *key,
					  size_t key_len)
{
	struct se050_ecc_keypub key_bin = { };
	TEE_Result ret = TEE_ERROR_GENERIC;
	sss_status_t st = kStatus_SSS_Fail;
	uint32_t oid = 0;

	st = sss_se05x_key_object_init(k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(k_object, oid,
						  kSSS_KeyPart_Public,
						  cipher_tee2se050(key->curve),
						  0,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = set_binary_data(key->x, key_len, &key_bin.x, &key_bin.x_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = set_binary_data(key->y, key_len, &key_bin.y, &key_bin.y_len);
	if (ret != TEE_SUCCESS) {
		free(key_bin.x);
		return ret;
	}

	key_bin.curve = curve_tee2se050(key->curve);
	st = se050_key_store_set_ecc_key_bin(se050_kstore, k_object, NULL,
					     &key_bin);
	free(key_bin.x);
	free(key_bin.y);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static TEE_Result se050_inject_keypair(sss_se05x_object_t *k_object,
				       struct ecc_keypair *key,
				       size_t key_len)
{
	struct se050_ecc_keypair key_bin = { };
	sss_status_t st = kStatus_SSS_Fail;
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t key_id = 0;
	uint32_t oid = 0;

	st = sss_se05x_key_object_init(k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	key_id = se050_ecc_keypair_from_nvm(key);
	if (key_id) {
		st = sss_se05x_key_object_get_handle(k_object, key_id);
		if (st != kStatus_SSS_Success)
			return TEE_ERROR_BAD_PARAMETERS;

		return TEE_SUCCESS;
	}

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(k_object, oid,
						  kSSS_KeyPart_Pair,
						  cipher_tee2se050(key->curve),
						  0,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = set_binary_data(key->d, key_len, &key_bin.d, &key_bin.d_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = set_binary_data(key->x, key_len,
			      &key_bin.pub.x, &key_bin.pub.x_len);
	if (ret != TEE_SUCCESS) {
		free(key_bin.d);
		return ret;
	}

	ret = set_binary_data(key->y, key_len,
			      &key_bin.pub.y, &key_bin.pub.y_len);
	if (ret != TEE_SUCCESS) {
		free(key_bin.d);
		free(key_bin.pub.x);
		return ret;
	}

	key_bin.pub.curve = curve_tee2se050(key->curve);
	st = se050_key_store_set_ecc_key_bin(se050_kstore, k_object, &key_bin,
					     NULL);
	free(key_bin.d);
	free(key_bin.pub.x);
	free(key_bin.pub.y);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static TEE_Result shared_secret(struct ecc_keypair *private_key,
				struct ecc_public_key *public_key,
				void *secret, size_t *secret_len)
{
	struct se050_ecc_keypub key = { };
	sss_status_t st = kStatus_SSS_Fail;
	TEE_Result ret = TEE_SUCCESS;
	size_t key_bits = 0;
	size_t key_bytes = 0;
	size_t x1_len = 0;
	size_t y1_len = 0;
	size_t x2_len = 0;
	uint32_t kid = 0;

	if (private_key->curve != public_key->curve)
		return TEE_ERROR_BAD_PARAMETERS;

	kid = se050_ecc_keypair_from_nvm(private_key);
	if (!kid) {
		EMSG("private key must be stored in SE050 flash");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* validate input parameters */
	x1_len = crypto_bignum_num_bytes(private_key->x);
	y1_len = crypto_bignum_num_bytes(private_key->y);
	x2_len = crypto_bignum_num_bytes(public_key->x);

	ret = ecc_get_key_size(public_key->curve, 0, &key_bytes, &key_bits);
	if (ret != TEE_SUCCESS)
		return ret;

	if (x1_len != y1_len || x1_len != key_bytes || x1_len != x2_len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* prepare the public key (must be in raw format) */
	ret = set_binary_data(public_key->x, x1_len, &key.x, &key.x_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = set_binary_data(public_key->y, y1_len, &key.y, &key.y_len);
	if (ret != TEE_SUCCESS) {
		free(key.x);
		return ret;
	}

	st = se050_ecc_gen_shared_secret(&se050_session->s_ctx, kid, &key,
					 secret, secret_len);
	free(key.x);
	free(key.y);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static TEE_Result sign(uint32_t algo, struct ecc_keypair *key,
		       const uint8_t *msg, size_t msg_len,
		       uint8_t *sig, size_t *sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;
	size_t key_bytes = 0;
	size_t key_bits = 0;

	res = ecc_get_key_size(key->curve, algo, &key_bytes, &key_bits);
	if (res != TEE_SUCCESS)
		goto exit;

	/* se050 exports DER format */
	if (*sig_len < (2 * key_bytes + DER_SIGNATURE_SZ)) {
		*sig_len = 2 * key_bytes + DER_SIGNATURE_SZ;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	res = ecc_get_msg_size(algo_tee2se050(algo), &msg_len);
	if (res != TEE_SUCCESS)
		goto exit;

	res = se050_inject_keypair(&kobject, key, key_bytes);
	if (res != TEE_SUCCESS)
		goto exit;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       algo_tee2se050(algo),
					       kMode_SSS_Sign);
	if (st != kStatus_SSS_Success) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	st = sss_se05x_asymmetric_sign_digest(&ctx, (uint8_t *)msg, msg_len,
					      sig, sig_len);
	if (st != kStatus_SSS_Success) {
		EMSG("curve: %#"PRIx32, key->curve);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	sss_se05x_signature_der2bin(sig, sig_len);
exit:
	if (!se050_ecc_keypair_from_nvm(key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

static TEE_Result verify(uint32_t algo, struct ecc_public_key *key,
			 const uint8_t *msg, size_t msg_len,
			 const uint8_t *sig, size_t sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;
	uint8_t signature[128];
	size_t signature_len = sizeof(signature);
	size_t key_bytes = 0;
	size_t key_bits = 0;

	res = ecc_get_key_size(key->curve, algo, &key_bytes, &key_bits);
	if (res != TEE_SUCCESS)
		goto exit;

	res = ecc_get_msg_size(algo_tee2se050(algo), &msg_len);
	if (res != TEE_SUCCESS)
		goto exit;

	res = se050_inject_public_key(&kobject, key, key_bytes);
	if (res != TEE_SUCCESS)
		goto exit;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       algo_tee2se050(algo),
					       kMode_SSS_Verify);
	if (st != kStatus_SSS_Success) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	st = sss_se05x_signature_bin2der(signature, &signature_len,
					 (uint8_t *)sig, sig_len);
	if (st != kStatus_SSS_Success) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	st = sss_se05x_asymmetric_verify_digest(&ctx, (uint8_t *)msg, msg_len,
						(uint8_t *)signature,
						signature_len);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_SIGNATURE_INVALID;
exit:
	sss_se05x_key_store_erase_key(se050_kstore, &kobject);
	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

static TEE_Result gen_keypair(struct ecc_keypair *key, size_t key_size __unused)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_object_t k_object = { };
	TEE_Result ret = TEE_SUCCESS;
	uint8_t kf[512] = { };
	uint32_t oid = 0;
	uint64_t kid = 0;
	size_t bytes = 0;
	size_t bits = 0;

	ret = ecc_get_key_size(key->curve, 0, &bytes, &bits);
	if (ret)
		return ret;

	st = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(kKeyObject_Mode_Persistent, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(&k_object, oid,
						  kSSS_KeyPart_Pair,
						  cipher_tee2se050(key->curve),
						  0,
						  kKeyObject_Mode_Persistent);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_key_store_generate_key(se050_kstore, &k_object, bits,
					      &se050_asym_policy);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	bytes = sizeof(kf);
	st = se050_key_store_get_ecc_key_bin(se050_kstore, &k_object, kf,
					     &bytes);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &k_object);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* skip the DER tag */
	crypto_bignum_bin2bn(kf + 1, bytes / 2, key->x);
	crypto_bignum_bin2bn(kf + 1 + bytes / 2, bytes / 2, key->y);

	kid = se050_generate_private_key(oid);
	crypto_bignum_bin2bn((uint8_t *)&kid, sizeof(kid), key->d);
	key->curve = curve_se0502tee(k_object.curve_id);
	if (key->curve != TEE_CRYPTO_ELEMENT_NONE)
		return TEE_SUCCESS;

	EMSG("ecc key generation failed");
	sss_se05x_key_store_erase_key(se050_kstore, &k_object);

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result do_gen_keypair(struct ecc_keypair *key, size_t size_bytes)
{
	return gen_keypair(key, size_bytes);
}

static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	return shared_secret(sdata->key_priv,
			     sdata->key_pub,
			     sdata->secret.data,
			     &sdata->secret.length);
}

static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	return sign(sdata->algo,
		    sdata->key,
		    sdata->message.data,
		    sdata->message.length,
		    sdata->signature.data,
		    &sdata->signature.length);
}

static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	return verify(sdata->algo,
		      sdata->key,
		      sdata->message.data,
		      sdata->message.length,
		      sdata->signature.data,
		      sdata->signature.length);
}

static TEE_Result do_alloc_keypair(struct ecc_keypair *s,
				   size_t size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->d))
		goto err;
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result do_alloc_publickey(struct ecc_public_key *s,
				     size_t size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static void do_free_publickey(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
}

static struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair = do_alloc_keypair,
	.alloc_publickey = do_alloc_publickey,
	.free_publickey = do_free_publickey,
	.gen_keypair = do_gen_keypair,
	.sign = do_sign,
	.verify = do_verify,
	.shared_secret = do_shared_secret,
};

static TEE_Result ecc_init(void)
{
	return drvcrypt_register_ecc(&driver_ecc);
}

driver_init_late(ecc_init);
