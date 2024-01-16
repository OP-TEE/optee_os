// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto_impl.h>
#include <der.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <drvcrypt_math.h>
#include <initcall.h>
#include <se050.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>
#include <utee_defines.h>
#include <util.h>

static const struct crypto_ecc_keypair_ops *pair_ops;
static const struct crypto_ecc_public_ops *pub_ops;

static bool oefid_key_supported(size_t bits)
{
	switch (se050_get_oefid()) {
	case SE050F_ID:
		return bits >= 224;
	default:
		return true;
	}
}

static bool oefid_algo_supported(uint32_t algo)
{
	switch (se050_get_oefid()) {
	case SE050F_ID:
		switch (algo) {
		case TEE_ALG_ECDSA_SHA224:
		case TEE_ALG_ECDSA_SHA256:
		case TEE_ALG_ECDSA_SHA384:
		case TEE_ALG_ECDSA_SHA512:
			return true;
		default:
			return false;
		}
	default:
		return true;
	}
}

static uint32_t algo_tee2se050(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_ECDSA_SHA1:
		return kAlgorithm_SSS_ECDSA_SHA1;
	case TEE_ALG_ECDSA_SHA224:
		return kAlgorithm_SSS_ECDSA_SHA224;
	case TEE_ALG_ECDSA_SHA256:
		return kAlgorithm_SSS_ECDSA_SHA256;
	case TEE_ALG_ECDSA_SHA384:
		return kAlgorithm_SSS_ECDSA_SHA384;
	case TEE_ALG_ECDSA_SHA512:
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
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*bits = 192;
		*bytes = 24;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*bits = 224;
		*bytes = 28;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*bits = 256;
		*bytes = 32;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*bits = 384;
		*bytes = 48;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*bits = 521;
		*bytes = 66;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (!oefid_key_supported(*bits))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (!oefid_algo_supported(algo))
		return TEE_ERROR_NOT_IMPLEMENTED;

	return TEE_SUCCESS;
}

static TEE_Result ecc_prepare_msg(uint32_t algo, const uint8_t *msg,
				  size_t *msg_len, uint8_t **msg_padded)
{
	struct {
		uint32_t algo;
		size_t len;
	} map[] = {
		{ kAlgorithm_SSS_ECDSA_SHA1, TEE_SHA1_HASH_SIZE },
		{ kAlgorithm_SSS_ECDSA_SHA224, TEE_SHA224_HASH_SIZE },
		{ kAlgorithm_SSS_ECDSA_SHA256, TEE_SHA256_HASH_SIZE },
		{ kAlgorithm_SSS_ECDSA_SHA384, TEE_SHA384_HASH_SIZE },
		{ kAlgorithm_SSS_ECDSA_SHA512, TEE_SHA512_HASH_SIZE },
	};
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(map); i++) {
		if (algo == map[i].algo)
			break;
	}

	if (i >= ARRAY_SIZE(map))
		return TEE_ERROR_BAD_PARAMETERS;

	if (*msg_len >= map[i].len) {
		/* truncate */
		*msg_len = map[i].len;
		return TEE_SUCCESS;
	}

	/* pad */
	*msg_padded = calloc(1, map[i].len);
	if (!*msg_padded)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(*msg_padded, msg, *msg_len);
	*msg_len = map[i].len;

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

	/*
	 * This function might return an error if the curve already
	 * exists in the secure element. An actual error creating the
	 * curve will be caught when attempting to set the key.
	 */
	sss_se05x_key_store_create_curve(&se050_session->s_ctx,
					 curve_tee2se050(key->curve));

	st = se050_get_oid(&oid);
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
	if (st != kStatus_SSS_Success) {
		EMSG("Can't inject transient key, curve: %#"PRIx32, key->curve);
		return TEE_ERROR_BAD_PARAMETERS;
	}

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

	/*
	 * This function might return an error if the curve already
	 * exists in the secure element. An actual error creating the
	 * curve will be caught when attempting to set the key.
	 */
	sss_se05x_key_store_create_curve(&se050_session->s_ctx,
					 curve_tee2se050(key->curve));

	st = se050_get_oid(&oid);
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
	if (st != kStatus_SSS_Success) {
		EMSG("Can't inject transient key, curve: %#"PRIx32, key->curve);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result gen_fallback(struct ecc_keypair *key, size_t len)
{
	if (!IS_ENABLED(CFG_NXP_SE05X_ECC_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("se050: debug: ECC software fallback: KEYGEN");
	return pair_ops->generate(key, len);
}

static TEE_Result shared_secret_fallback(struct ecc_keypair *private_key,
					 struct ecc_public_key *public_key,
					 void *secret, size_t *secret_len)
{
	const struct crypto_ecc_keypair_ops *ops = NULL;

	if (!IS_ENABLED(CFG_NXP_SE05X_ECC_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (se050_ecc_keypair_from_nvm(private_key))
		return TEE_ERROR_NOT_IMPLEMENTED;

	ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDH_KEYPAIR);
	if (!ops)
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("se050: debug: ECC software fallback: ECDH");
	return ops->shared_secret(private_key, public_key,
				  secret, (unsigned long *)secret_len);
}

static TEE_Result verify_fallback(uint32_t algo, struct ecc_public_key *key,
				  const uint8_t *msg, size_t msg_len,
				  const uint8_t *sig, size_t sig_len)
{
	if (!IS_ENABLED(CFG_NXP_SE05X_ECC_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("se050: debug: ECC software fallback: VERIFY");
	return pub_ops->verify(algo, key, msg, msg_len, sig, sig_len);
}

static TEE_Result sign_fallback(uint32_t algo, struct ecc_keypair *key,
				const uint8_t *msg, size_t msg_len,
				uint8_t *sig, size_t *sig_len)
{
	if (!IS_ENABLED(CFG_NXP_SE05X_ECC_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (se050_ecc_keypair_from_nvm(key))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("se050: debug: ECC software fallback: SIGN");
	return pair_ops->sign(algo, key, msg, msg_len, sig, sig_len);
}

static TEE_Result shared_secret(struct ecc_keypair *private_key,
				struct ecc_public_key *public_key,
				void *secret, size_t *secret_len)
{
	struct se050_ecc_keypub key = { };
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_derive_key_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result ret = TEE_SUCCESS;
	size_t key_bits = 0;
	size_t key_bytes = 0;

	if (private_key->curve != public_key->curve)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = ecc_get_key_size(private_key->curve, 0, &key_bytes, &key_bits);
	if (ret) {
		if (ret != TEE_ERROR_NOT_IMPLEMENTED)
			return ret;

		return shared_secret_fallback(private_key, public_key,
					      secret, secret_len);
	}

	ret = se050_inject_keypair(&kobject, private_key, key_bytes);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_derive_key_context_init(&ctx, se050_session, &kobject,
					       kAlgorithm_SSS_ECDH,
					       kMode_SSS_ComputeSharedSecret);
	if (st != kStatus_SSS_Success) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* prepare the public key (must be in raw format) */
	ret = set_binary_data(public_key->x, key_bytes, &key.x, &key.x_len);
	if (ret != TEE_SUCCESS) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	ret = set_binary_data(public_key->y, key_bytes, &key.y, &key.y_len);
	if (ret != TEE_SUCCESS) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	st = se050_ecc_gen_shared_secret(&se050_session->s_ctx,
					 kobject.keyId, &key,
					 secret, secret_len);

	if (st != kStatus_SSS_Success)
		ret = TEE_ERROR_BAD_PARAMETERS;
exit:
	if (!se050_ecc_keypair_from_nvm(private_key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	free(key.x);
	free(key.y);

	return ret;
}

static TEE_Result sign(uint32_t algo, struct ecc_keypair *key,
		       const uint8_t *msg, size_t msg_len,
		       uint8_t *sig, size_t *sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;
	uint8_t *sig_der = NULL;
	size_t sig_der_len = 0;
	size_t key_bytes = 0;
	size_t key_bits = 0;
	uint8_t *p = NULL;

	res = ecc_get_key_size(key->curve, algo, &key_bytes, &key_bits);
	if (res) {
		if (res != TEE_ERROR_NOT_IMPLEMENTED)
			goto exit;

		return sign_fallback(algo, key, msg, msg_len, sig, sig_len);
	}

	/* allocate temporary buffer to retrieve the signature in DER format */
	sig_der_len = 2 * key_bytes + DER_SIGNATURE_SZ;

	sig_der = malloc(sig_der_len);
	if (!sig_der) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	/* truncate or pad the message as needed */
	res = ecc_prepare_msg(algo_tee2se050(algo), msg, &msg_len, &p);
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

	st = sss_se05x_asymmetric_sign_digest(&ctx, p ? p : (uint8_t *)msg,
					      msg_len, sig_der, &sig_der_len);
	if (st != kStatus_SSS_Success) {
		EMSG("curve: %#"PRIx32, key->curve);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	sss_se05x_signature_der2bin(sig_der, &sig_der_len);

	if (sig_der_len > *sig_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	memcpy(sig, sig_der, sig_der_len);
	*sig_len = sig_der_len;
exit:
	if (!se050_ecc_keypair_from_nvm(key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	sss_se05x_asymmetric_context_free(&ctx);

	free(sig_der);
	free(p);

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
	uint8_t *signature = NULL;
	size_t signature_len = sig_len + DER_SIGNATURE_SZ;
	size_t key_bytes = 0;
	size_t key_bits = 0;
	uint8_t *p = NULL;

	res = ecc_get_key_size(key->curve, algo, &key_bytes, &key_bits);
	if (res) {
		if (res != TEE_ERROR_NOT_IMPLEMENTED)
			goto exit;

		return verify_fallback(algo, key, msg, msg_len, sig, sig_len);
	}

	/* truncate or pad the message as needed */
	res = ecc_prepare_msg(algo_tee2se050(algo), msg, &msg_len, &p);
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

	signature = calloc(1, signature_len);
	if (!signature) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	st = sss_se05x_signature_bin2der(signature, &signature_len,
					 (uint8_t *)sig, sig_len);
	if (st != kStatus_SSS_Success) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	st = sss_se05x_asymmetric_verify_digest(&ctx, p ? p : (uint8_t *)msg,
						msg_len, (uint8_t *)signature,
						signature_len);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_SIGNATURE_INVALID;
exit:
	sss_se05x_key_store_erase_key(se050_kstore, &kobject);
	sss_se05x_asymmetric_context_free(&ctx);
	free(p);
	free(signature);

	return res;
}

static TEE_Result gen_keypair(struct ecc_keypair *key, size_t key_size)
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
	if (ret) {
		if (ret != TEE_ERROR_NOT_IMPLEMENTED)
			return ret;

		return gen_fallback(key, key_size);
	}

	st = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(&oid);
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

static TEE_Result do_alloc_keypair(struct ecc_keypair *s, uint32_t type,
				   size_t size_bits __unused)
{
	/* This driver only supports ECDH/ECDSA */
	if (type != TEE_TYPE_ECDSA_KEYPAIR &&
	    type != TEE_TYPE_ECDH_KEYPAIR)
		return TEE_ERROR_NOT_IMPLEMENTED;

	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->d))
		goto err;
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(&s->d);
	crypto_bignum_free(&s->x);
	crypto_bignum_free(&s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result do_alloc_publickey(struct ecc_public_key *s, uint32_t type,
				     size_t size_bits __unused)
{
	/* This driver only supports ECDH/ECDSA */
	if (type != TEE_TYPE_ECDSA_PUBLIC_KEY &&
	    type != TEE_TYPE_ECDH_PUBLIC_KEY)
		return TEE_ERROR_NOT_IMPLEMENTED;

	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(&s->x);
	crypto_bignum_free(&s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static void do_free_publickey(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(&s->x);
	crypto_bignum_free(&s->y);
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
	pub_ops = crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDSA_PUBLIC_KEY);
	if (!pub_ops)
		return TEE_ERROR_GENERIC;

	pair_ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDSA_KEYPAIR);
	if (!pair_ops)
		return TEE_ERROR_GENERIC;

	/* This driver supports both ECDH and ECDSA */
	assert((pub_ops ==
		crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDH_PUBLIC_KEY)) &&
	       (pair_ops ==
		crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDH_KEYPAIR)));

	return drvcrypt_register_ecc(&driver_ecc);
}

driver_init_late(ecc_init);
