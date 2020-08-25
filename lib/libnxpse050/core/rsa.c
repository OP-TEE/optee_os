// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <se050.h>
#include <string.h>

static uint32_t tee2se050(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		return kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		return kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		return kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		return kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		return kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		return kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		return kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		return kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512;
	case TEE_ALG_RSAES_PKCS1_V1_5:
		return kAlgorithm_SSS_RSAES_PKCS1_V1_5_SHA256;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		return kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		return kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA224;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		return kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		return kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA384;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		return kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512;
	case TEE_ALG_RSA_NOPAD:
		return kAlgorithm_SSS_RSASSA_NO_PADDING;
#ifdef CFG_CRYPTO_RSASSA_NA1
	case TEE_ALG_RSASSA_PKCS1_V1_5:
#endif
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5SHA1:
	default:
		EMSG("rsa algorithm 0x%x not supported ", algo);
		panic();
		return kAlgorithm_None;
	}
}

static TEE_Result set_binary_data(struct bignum *b, uint8_t **p, size_t *len)
{
	*len = crypto_bignum_num_bytes(b);
	if (*len) {
		*p = (uint8_t *)calloc(1, *len);
		if (!*p)
			return TEE_ERROR_OUT_OF_MEMORY;
		crypto_bignum_bn2bin(b, *p);
	}
	return TEE_SUCCESS;
}

static TEE_Result se050_inject_public_key(sss_se05x_object_t *k_object,
					  struct rsa_public_key *key)
{
	sss_status_t st = kStatus_SSS_Fail;
	struct rsa_public_key_bin key_bin = { 0 };
	uint32_t oid = 0;

	st = sss_se05x_key_object_init(k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(kKeyObject_Mode_Persistent, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(k_object, oid,
						  kSSS_KeyPart_Public,
						  kSSS_CipherType_RSA, 0,
						  kKeyObject_Mode_Persistent);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	set_binary_data(key->e, &key_bin.e, &key_bin.e_len);
	set_binary_data(key->n, &key_bin.n, &key_bin.n_len);
	st = se050_key_store_set_rsa_key_bin(se050_kstore, k_object, NULL,
					     &key_bin, key_bin.n_len * 8);
	if (key_bin.n)
		free(key_bin.n);

	if (key_bin.e)
		free(key_bin.e);

	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, k_object);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result se050_inject_keypair(sss_se05x_object_t *k_object,
				       struct rsa_keypair *key)
{
	sss_status_t st = kStatus_SSS_Fail;
	struct rsa_keypair_bin key_bin = { 0 };
	uint32_t key_id;
	uint32_t oid;

	st = sss_se05x_key_object_init(k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	key_id = se050_rsa_keypair_from_nvm(key);
	if (key_id) {
		st = sss_se05x_key_object_get_handle(k_object, key_id);
		if (st != kStatus_SSS_Success) {
			EMSG("rsa");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		return TEE_SUCCESS;
	}

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(k_object, oid,
						  kSSS_KeyPart_Pair,
						  kSSS_CipherType_RSA, 0,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	set_binary_data(key->e, &key_bin.e, &key_bin.e_len);
	set_binary_data(key->d, &key_bin.d, &key_bin.d_len);
	set_binary_data(key->n, &key_bin.n, &key_bin.n_len);
	set_binary_data(key->p, &key_bin.p, &key_bin.p_len);
	set_binary_data(key->q, &key_bin.q, &key_bin.q_len);
	set_binary_data(key->qp, &key_bin.qp, &key_bin.qp_len);
	set_binary_data(key->dp, &key_bin.dp, &key_bin.dp_len);
	set_binary_data(key->dq, &key_bin.dq, &key_bin.dq_len);
	st = se050_key_store_set_rsa_key_bin(se050_kstore, k_object,
					     &key_bin, NULL,
					     crypto_bignum_num_bytes(key->n)
					     * 8);
	if (key_bin.e)
		free(key_bin.e);
	if (key_bin.d)
		free(key_bin.d);
	if (key_bin.n)
		free(key_bin.n);
	if (key_bin.p)
		free(key_bin.p);
	if (key_bin.q)
		free(key_bin.q);
	if (key_bin.qp)
		free(key_bin.qp);
	if (key_bin.dp)
		free(key_bin.dp);
	if (key_bin.dq)
		free(key_bin.dq);

	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, k_object);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t kb)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_object_t k_object = { 0 };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t oid = 0;
	uint64_t kid = 0;
	uint8_t k[2048] = { 0 };
	uint8_t *n = NULL;
	uint8_t *e = NULL;
	size_t n_len = 0, e_len = 0, k_len = sizeof(k);

	st = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(kKeyObject_Mode_Persistent, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(&k_object, oid,
						  kSSS_KeyPart_Pair,
						  kSSS_CipherType_RSA, 0,
						  kKeyObject_Mode_Persistent);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_key_store_generate_key(se050_kstore, &k_object, kb,
					      &se050_asym_policy);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &k_object);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	st = sss_se05x_key_store_get_key(se050_kstore, &k_object, k, &k_len,
					 &kb);
	if (st != kStatus_SSS_Success) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	st = sss_util_asn1_rsa_parse_public(k, k_len, &n, &n_len, &e, &e_len);
	if (st != kStatus_SSS_Success) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	crypto_bignum_bin2bn(n, n_len, key->n);
	crypto_bignum_bin2bn(e, e_len, key->e);

	/* the se050 does not provide the private key */
	kid = se050_generate_private_key(oid);
	crypto_bignum_bin2bn((uint8_t *)&kid, sizeof(kid), (key->d));

	/* fill the rest with some data */
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->p);
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->q);
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->qp);
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->dp);
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->dq);

	if (n)
		free(n);
	if (e)
		free(e);

	ret = TEE_SUCCESS;
exit:
	if (ret != TEE_SUCCESS) {
		IMSG("rsa key generation failed");
		sss_se05x_key_store_erase_key(se050_kstore, &k_object);
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { 0 };
	sss_se05x_object_t kobject = { 0 };
	TEE_Result res = TEE_SUCCESS;

	if (*dst_len < crypto_bignum_num_bytes(key->n)) {
		*dst_len = crypto_bignum_num_bytes(key->n);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = se050_inject_public_key(&kobject, key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       tee2se050(algo),
					       kMode_SSS_Encrypt);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	st = sss_se05x_asymmetric_encrypt(&ctx, src, src_len, dst, dst_len);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_BAD_PARAMETERS;

	sss_se05x_key_store_erase_key(se050_kstore, &kobject);
	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { 0 };
	sss_se05x_object_t kobject = { 0 };
	TEE_Result res = TEE_SUCCESS;

	res = se050_inject_keypair(&kobject, key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       tee2se050(algo),
					       kMode_SSS_Decrypt);
	if (st != kStatus_SSS_Success) {
		if (!se050_rsa_keypair_from_nvm(key))
			sss_se05x_key_store_erase_key(se050_kstore, &kobject);

		return TEE_ERROR_BAD_PARAMETERS;
	}

	st = sss_se05x_asymmetric_decrypt(&ctx, src, src_len, dst, dst_len);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_BAD_PARAMETERS;

	if (!se050_rsa_keypair_from_nvm(key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { 0 };
	sss_se05x_object_t kobject = { 0 };
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	size_t offset = 0;
	size_t blen = 0;
	size_t rsa_len = 0;

	res = se050_inject_public_key(&kobject, key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       kAlgorithm_SSS_RSASSA_NO_PADDING,
					       kMode_SSS_Encrypt);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	blen = CFG_CORE_BIGNUM_MAX_BITS / 8;
	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	rsa_len = crypto_bignum_num_bytes(key->n);
	memset(buf, 0, blen);
	memcpy(buf + rsa_len - src_len, src, src_len);

	st = sss_se05x_asymmetric_encrypt(&ctx, buf, src_len, buf, &blen);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_BAD_PARAMETERS;

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < rsa_len - 1) && (buf[offset] == 0))
		offset++;

	if (*dst_len < rsa_len - offset) {
		*dst_len = rsa_len - offset;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	*dst_len = rsa_len - offset;
	memcpy(dst, buf + offset, *dst_len);
out:
	if (buf)
		free(buf);

	sss_se05x_key_store_erase_key(se050_kstore, &kobject);
	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { 0 };
	sss_se05x_object_t kobject = { 0 };
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	size_t offset = 0;
	size_t blen = 0;
	size_t rsa_len = 0;

	res = se050_inject_keypair(&kobject, key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       kAlgorithm_SSS_RSASSA_NO_PADDING,
					       kMode_SSS_Decrypt);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	blen = CFG_CORE_BIGNUM_MAX_BITS / 8;
	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	rsa_len = crypto_bignum_num_bytes(key->n);
	memset(buf, 0, blen);
	memcpy(buf + rsa_len - src_len, src, src_len);

	st = sss_se05x_asymmetric_decrypt(&ctx, buf, src_len, buf, &blen);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_BAD_PARAMETERS;

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < rsa_len - 1) && (buf[offset] == 0))
		offset++;

	if (*dst_len < rsa_len - offset) {
		*dst_len = rsa_len - offset;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*dst_len = rsa_len - offset;
	memcpy(dst, (char *)buf + offset, *dst_len);
out:
	if (buf)
		free(buf);

	if (!se050_rsa_keypair_from_nvm(key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
				      int salt_len __unused, const uint8_t *msg,
				      size_t msg_len, uint8_t *sig,
				      size_t *sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { 0 };
	sss_se05x_object_t kobject = { 0 };
	TEE_Result res = TEE_SUCCESS;

	if (*sig_len < crypto_bignum_num_bytes(key->n)) {
		*sig_len = crypto_bignum_num_bytes(key->n);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = se050_inject_keypair(&kobject, key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       tee2se050(algo), kMode_SSS_Sign);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	st = sss_se05x_asymmetric_sign_digest(&ctx, (uint8_t *)msg, msg_len,
					      sig, sig_len);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_BAD_PARAMETERS;

	if (!se050_rsa_keypair_from_nvm(key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len __unused,
					const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { 0 };
	sss_se05x_object_t kobject = { 0 };
	TEE_Result res = TEE_SUCCESS;

	res = se050_inject_public_key(&kobject, key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       tee2se050(algo),
					       kMode_SSS_Verify);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	st = sss_se05x_asymmetric_verify_digest(&ctx, (uint8_t *)msg, msg_len,
						(uint8_t *)sig, sig_len);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_SIGNATURE_INVALID;

	sss_se05x_key_store_erase_key(se050_kstore, &kobject);
	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}
