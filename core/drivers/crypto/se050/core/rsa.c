// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <drvcrypt_math.h>
#include <initcall.h>
#include <mempool.h>
#include <se050.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <tee_api_defines_extensions.h>

static sss_cipher_type_t oefid_cipher_type(void)
{
	switch (se050_get_oefid()) {
	case SE050F_ID:
		return kSSS_CipherType_RSA_CRT;
	default:
		return kSSS_CipherType_RSA;
	}
}

static bool oefid_keylen_supported(size_t bits)
{
	switch (se050_get_oefid()) {
	case SE050F_ID:
		return bits >= 2048;
	default:
		return true;
	}
}

static bool rsa_keypair_has_crt(struct rsa_keypair *key)
{
	if (key->p && crypto_bignum_num_bytes(key->p) &&
	    key->q && crypto_bignum_num_bytes(key->q) &&
	    key->qp && crypto_bignum_num_bytes(key->qp) &&
	    key->dp && crypto_bignum_num_bytes(key->dp) &&
	    key->dq && crypto_bignum_num_bytes(key->dq))
		return true;

	return false;
}

static bool keypair_supported(struct rsa_keypair *key, sss_cipher_type_t ctype)
{
	if (se050_rsa_keypair_from_nvm(key))
		return true;

	if (ctype == kSSS_CipherType_RSA_CRT)
		return rsa_keypair_has_crt(key);

	return true;
}

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
		return kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH;
#endif
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5SHA1:
	default:
		return kAlgorithm_None;
	}
}

static bool bn_alloc_max(struct bignum **s)
{
	*s = crypto_bignum_allocate(4096);

	return *s;
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
	struct se050_rsa_keypub key_bin = { };
	uint32_t oid = 0;

	st = sss_se05x_key_object_init(k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(&oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	/*
	 * Keys 2048 and above MUST to be placed on persistent storage even
	 * though the keys will be deleted after the operation. This is a
	 * memory restriction in the secure element.
	 */
	st = sss_se05x_key_object_allocate_handle(k_object, oid,
						  kSSS_KeyPart_Public,
						  oefid_cipher_type(), 0,
						  kKeyObject_Mode_Persistent);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	set_binary_data(key->e, &key_bin.e, &key_bin.e_len);
	set_binary_data(key->n, &key_bin.n, &key_bin.n_len);
	st = se050_key_store_set_rsa_key_bin(se050_kstore, k_object, NULL,
					     &key_bin, key_bin.n_len * 8);
	free(key_bin.n);
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
	struct se050_rsa_keypair key_bin = { };
	uint32_t key_id = 0;
	uint32_t oid = 0;

	st = sss_se05x_key_object_init(k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	key_id = se050_rsa_keypair_from_nvm(key);
	if (key_id) {
		st = sss_se05x_key_object_get_handle(k_object, key_id);
		if (st != kStatus_SSS_Success)
			return TEE_ERROR_BAD_PARAMETERS;
		return TEE_SUCCESS;
	}

	st = se050_get_oid(&oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	/* Keys 2048 and above need to be placed on persistent storage */
	st = sss_se05x_key_object_allocate_handle(k_object, oid,
						  kSSS_KeyPart_Pair,
						  oefid_cipher_type(), 0,
						  kKeyObject_Mode_Persistent);
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
					     crypto_bignum_num_bits(key->n));
	free(key_bin.e);
	free(key_bin.d);
	free(key_bin.n);
	free(key_bin.p);
	free(key_bin.q);
	free(key_bin.qp);
	free(key_bin.dp);
	free(key_bin.dq);

	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, k_object);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result decrypt_es(uint32_t algo, struct rsa_keypair *key,
			     const uint8_t *src, size_t src_len,
			     uint8_t *dst, size_t *dst_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	size_t buf_len = src_len;

	res = se050_inject_keypair(&kobject, key);
	if (res)
		return res;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       tee2se050(algo),
					       kMode_SSS_Decrypt);
	if (st != kStatus_SSS_Success) {
		if (!se050_rsa_keypair_from_nvm(key))
			sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* we don't know the size of the decrypted data, just the upper limit */
	buf = mempool_calloc(mempool_default, 1, buf_len);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	st = sss_se05x_asymmetric_decrypt(&ctx, src, src_len, buf,  &buf_len);
	if (st != kStatus_SSS_Success) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (buf_len > *dst_len) {
		*dst_len = buf_len;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	*dst_len = buf_len;
	memcpy(dst, buf, buf_len);
out:
	if (!se050_rsa_keypair_from_nvm(key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	sss_se05x_asymmetric_context_free(&ctx);
	mempool_free(mempool_default, buf);

	return res;
}

static TEE_Result encrypt_es(uint32_t algo, struct rsa_public_key *key,
			     const uint8_t *src, size_t src_len,
			     uint8_t *dst, size_t *dst_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;

	if (*dst_len < crypto_bignum_num_bytes(key->n)) {
		*dst_len = crypto_bignum_num_bytes(key->n);
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (se050_inject_public_key(&kobject, key))
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

static TEE_Result decrypt_nopad(struct rsa_keypair *key, const uint8_t *src,
				size_t src_len, uint8_t *dst, size_t *dst_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	size_t offset = 0;
	size_t blen = 0;
	size_t rsa_len = 0;

	res = se050_inject_keypair(&kobject, key);
	if (res)
		return res;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       kAlgorithm_SSS_RSASSA_NO_PADDING,
					       kMode_SSS_Decrypt);
	if (st != kStatus_SSS_Success) {
		if (!se050_rsa_keypair_from_nvm(key))
			sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	blen = CFG_CORE_BIGNUM_MAX_BITS / 8;
	buf = mempool_calloc(mempool_default, 1, blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	rsa_len = crypto_bignum_num_bytes(key->n);
	memcpy(buf + rsa_len - src_len, src, src_len);

	st = sss_se05x_asymmetric_decrypt(&ctx, buf, rsa_len, buf, &blen);
	if (st != kStatus_SSS_Success) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < blen - 1) && (buf[offset] == 0))
		offset++;

	if (*dst_len < blen - offset) {
		*dst_len = blen - offset;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	*dst_len = blen - offset;
	memcpy(dst, buf + offset, *dst_len);
out:
	mempool_free(mempool_default, buf);
	if (!se050_rsa_keypair_from_nvm(key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

static TEE_Result encrypt_nopad(struct rsa_public_key *key, const uint8_t *src,
				size_t src_len, uint8_t *dst, size_t *dst_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	size_t offset = 0;
	size_t blen = 0;
	size_t rsa_len = 0;

	if (se050_inject_public_key(&kobject, key))
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       kAlgorithm_SSS_RSASSA_NO_PADDING,
					       kMode_SSS_Encrypt);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	blen = CFG_CORE_BIGNUM_MAX_BITS / 8;
	buf = mempool_calloc(mempool_default, 1, blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	rsa_len = crypto_bignum_num_bytes(key->n);
	memcpy(buf + rsa_len - src_len, src, src_len);

	st = sss_se05x_asymmetric_encrypt(&ctx, buf, rsa_len, buf, &blen);
	if (st != kStatus_SSS_Success) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < blen - 1) && (buf[offset] == 0))
		offset++;

	if (*dst_len < blen - offset) {
		*dst_len = blen - offset;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	*dst_len = blen - offset;
	memcpy(dst, buf + offset, *dst_len);
out:
	mempool_free(mempool_default, buf);
	sss_se05x_key_store_erase_key(se050_kstore, &kobject);
	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

static TEE_Result sign_ssa(uint32_t algo, struct rsa_keypair *key,
			   const uint8_t *msg, size_t msg_len,
			   uint8_t *sig, size_t *sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;

	if (*sig_len < crypto_bignum_num_bytes(key->n)) {
		*sig_len = crypto_bignum_num_bytes(key->n);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = se050_inject_keypair(&kobject, key);
	if (res)
		return res;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       tee2se050(algo), kMode_SSS_Sign);
	if (st != kStatus_SSS_Success) {
		if (!se050_rsa_keypair_from_nvm(key))
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

static TEE_Result verify_ssa(uint32_t algo, struct rsa_public_key *key,
			     const uint8_t *msg, size_t msg_len,
			     const uint8_t *sig, size_t sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { };
	sss_se05x_object_t kobject = { };
	TEE_Result res = TEE_SUCCESS;

	if (se050_inject_public_key(&kobject, key))
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

static TEE_Result do_alloc_keypair(struct rsa_keypair *s,
				   size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e))
		return TEE_ERROR_OUT_OF_MEMORY;
	if (!bn_alloc_max(&s->d))
		goto err;
	if (!bn_alloc_max(&s->n))
		goto err;
	if (!bn_alloc_max(&s->p))
		goto err;
	if (!bn_alloc_max(&s->q))
		goto err;
	if (!bn_alloc_max(&s->qp))
		goto err;
	if (!bn_alloc_max(&s->dp))
		goto err;
	if (!bn_alloc_max(&s->dq))
		goto err;

	return TEE_SUCCESS;
err:
	crypto_bignum_free(&s->e);
	crypto_bignum_free(&s->d);
	crypto_bignum_free(&s->n);
	crypto_bignum_free(&s->p);
	crypto_bignum_free(&s->q);
	crypto_bignum_free(&s->qp);
	crypto_bignum_free(&s->dp);
	crypto_bignum_free(&s->dq);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result do_alloc_publickey(struct rsa_public_key *s,
				     size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e))
		return TEE_ERROR_OUT_OF_MEMORY;
	if (!bn_alloc_max(&s->n)) {
		crypto_bignum_free(&s->e);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static void do_free_publickey(struct rsa_public_key *s)
{
	if (s) {
		crypto_bignum_free(&s->n);
		crypto_bignum_free(&s->e);
	}
}

static void do_free_keypair(struct rsa_keypair *s)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_object_t k_object = { };
	uint32_t key_id = 0;

	if (!s)
		return;

	key_id = se050_rsa_keypair_from_nvm(s);
	if (key_id) {
		st = sss_se05x_key_object_get_handle(&k_object, key_id);
		if (st == kStatus_SSS_Success)
			sss_se05x_key_store_erase_key(se050_kstore, &k_object);
	}

	crypto_bignum_free(&s->e);
	crypto_bignum_free(&s->d);
	crypto_bignum_free(&s->n);
	crypto_bignum_free(&s->p);
	crypto_bignum_free(&s->q);
	crypto_bignum_free(&s->qp);
	crypto_bignum_free(&s->dp);
	crypto_bignum_free(&s->dq);
}

static TEE_Result do_gen_keypair(struct rsa_keypair *key, size_t kb)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_object_t k_object = { };
	uint32_t oid = 0;
	uint64_t kid = 0;
	uint8_t k[2048] = { 0 };
	uint8_t *n = NULL;
	uint8_t *e = NULL;
	size_t n_len = 0;
	size_t e_len = 0;
	size_t k_len = sizeof(k);

	if (!oefid_keylen_supported(kb)) {
		if (!IS_ENABLED(CFG_NXP_SE05X_RSA_DRV_FALLBACK))
			return TEE_ERROR_NOT_IMPLEMENTED;

		DMSG("se050: debug: RSA software fallback: KEYGEN");
		return sw_crypto_acipher_gen_rsa_key(key, kb);
	}

	st = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(&oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(&k_object, oid,
						  kSSS_KeyPart_Pair,
						  oefid_cipher_type(), 0,
						  kKeyObject_Mode_Persistent);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_key_store_generate_key(se050_kstore, &k_object, kb,
					      &se050_asym_policy);
	if (st != kStatus_SSS_Success)
		goto error;

	st = sss_se05x_key_store_get_key(se050_kstore, &k_object, k, &k_len,
					 &kb);
	if (st != kStatus_SSS_Success)
		goto error;

	st = sss_util_asn1_rsa_parse_public(k, k_len, &n, &n_len, &e, &e_len);
	if (st != kStatus_SSS_Success)
		goto error;

	crypto_bignum_bin2bn(n, n_len, key->n);
	crypto_bignum_bin2bn(e, e_len, key->e);
	kid = se050_generate_private_key(oid);
	crypto_bignum_bin2bn((uint8_t *)&kid, sizeof(kid), (key->d));
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->p);
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->q);
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->qp);
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->dp);
	crypto_bignum_bin2bn((uint8_t *)&oid, sizeof(oid), key->dq);
	free(n);
	free(e);

	return TEE_SUCCESS;
error:
	sss_se05x_key_store_erase_key(se050_kstore, &k_object);
	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result encrypt_fallback(struct drvcrypt_rsa_ed *p)
{
	if (!IS_ENABLED(CFG_NXP_SE05X_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	switch (p->rsa_id) {
	case DRVCRYPT_RSA_NOPAD:
		DMSG("se050: debug: RSA software fallback: ENCRYPT_NOPAD");
		return sw_crypto_acipher_rsanopad_encrypt(p->key.key,
							  p->message.data,
							  p->message.length,
							  p->cipher.data,
							  &p->cipher.length);

	case DRVCRYPT_RSA_OAEP:
	case DRVCRYPT_RSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PSS:
	default:
		DMSG("se050: debug: RSA software fallback: ENCRYPT_ES");
		return sw_crypto_acipher_rsaes_encrypt(p->algo,
						       p->key.key,
						       p->label.data,
						       p->label.length,
						       p->message.data,
						       p->message.length,
						       p->cipher.data,
						       &p->cipher.length);
	}
}

static TEE_Result do_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	if (!oefid_keylen_supported(rsa_data->key.n_size * 8))
		return encrypt_fallback(rsa_data);

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_NOPAD:
	case DRVCRYPT_RSASSA_PSS:
	case DRVCRYPT_RSASSA_PKCS_V1_5:
		return encrypt_nopad(rsa_data->key.key,
				     rsa_data->message.data,
				     rsa_data->message.length,
				     rsa_data->cipher.data,
				     &rsa_data->cipher.length);

	case DRVCRYPT_RSA_PKCS_V1_5:
		return encrypt_es(TEE_ALG_RSAES_PKCS1_V1_5,
				  rsa_data->key.key,
				  rsa_data->message.data,
				  rsa_data->message.length,
				  rsa_data->cipher.data,
				  &rsa_data->cipher.length);

	case DRVCRYPT_RSA_OAEP:
		if (rsa_data->hash_algo != TEE_ALG_SHA1)
			return encrypt_fallback(rsa_data);

		return encrypt_es(TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
				  rsa_data->key.key,
				  rsa_data->message.data,
				  rsa_data->message.length,
				  rsa_data->cipher.data,
				  &rsa_data->cipher.length);

	default:
		break;
	}

	return encrypt_fallback(rsa_data);
}

static TEE_Result decrypt_fallback(struct drvcrypt_rsa_ed *p)
{
	if (!IS_ENABLED(CFG_NXP_SE05X_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (se050_rsa_keypair_from_nvm(p->key.key))
		return TEE_ERROR_NOT_IMPLEMENTED;

	switch (p->rsa_id) {
	case DRVCRYPT_RSA_NOPAD:
		DMSG("se050: debug: RSA software fallback: DECRYPT_NOPAD");
		return sw_crypto_acipher_rsanopad_decrypt(p->key.key,
							  p->cipher.data,
							  p->cipher.length,
							  p->message.data,
							  &p->message.length);

	case DRVCRYPT_RSA_OAEP:
	case DRVCRYPT_RSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PSS:
	default:
		DMSG("se050: debug: RSA software fallback: DECRYPT_ES");
		return sw_crypto_acipher_rsaes_decrypt(p->algo,
						       p->key.key,
						       p->label.data,
						       p->label.length,
						       p->cipher.data,
						       p->cipher.length,
						       p->message.data,
						       &p->message.length);
	}
}

static TEE_Result do_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	if (!oefid_keylen_supported(rsa_data->key.n_size * 8))
		return decrypt_fallback(rsa_data);

	if (!keypair_supported(rsa_data->key.key, oefid_cipher_type()))
		return decrypt_fallback(rsa_data);

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_NOPAD:
	case DRVCRYPT_RSASSA_PSS:
	case DRVCRYPT_RSASSA_PKCS_V1_5:
		return decrypt_nopad(rsa_data->key.key,
				     rsa_data->cipher.data,
				     rsa_data->cipher.length,
				     rsa_data->message.data,
				     &rsa_data->message.length);

	case DRVCRYPT_RSA_PKCS_V1_5:
		return decrypt_es(TEE_ALG_RSAES_PKCS1_V1_5,
				  rsa_data->key.key,
				  rsa_data->cipher.data,
				  rsa_data->cipher.length,
				  rsa_data->message.data,
				  &rsa_data->message.length);

	case DRVCRYPT_RSA_OAEP:
		if (rsa_data->hash_algo != TEE_ALG_SHA1)
			return decrypt_fallback(rsa_data);

		return decrypt_es(TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
				  rsa_data->key.key,
				  rsa_data->cipher.data,
				  rsa_data->cipher.length,
				  rsa_data->message.data,
				  &rsa_data->message.length);

	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result sign_ssa_fallback(struct drvcrypt_rsa_ssa *p)
{
	if (!IS_ENABLED(CFG_NXP_SE05X_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (se050_rsa_keypair_from_nvm(p->key.key))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("se050: debug: RSA software fallback: SIGN");
	return sw_crypto_acipher_rsassa_sign(p->algo,
					     p->key.key,
					     p->salt_len,
					     p->message.data,
					     p->message.length,
					     p->signature.data,
					     &p->signature.length);
}

static TEE_Result do_ssa_sign(struct drvcrypt_rsa_ssa *ssa_data)
{
	if (!oefid_keylen_supported(ssa_data->key.n_size * 8))
		return sign_ssa_fallback(ssa_data);

	if (!keypair_supported(ssa_data->key.key, oefid_cipher_type()))
		return sign_ssa_fallback(ssa_data);

	/* PKCS1_PSS_MGF1 padding limitations */
	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		if (ssa_data->key.n_size * 8 <= 512)
			return sign_ssa_fallback(ssa_data);
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		if (ssa_data->key.n_size * 8 <= 1024)
			return sign_ssa_fallback(ssa_data);
		break;
	default:
		break;
	}

	return sign_ssa(ssa_data->algo,
			ssa_data->key.key,
			ssa_data->message.data,
			ssa_data->message.length,
			ssa_data->signature.data,
			&ssa_data->signature.length);
}

static TEE_Result verify_ssa_fallback(struct drvcrypt_rsa_ssa *p)
{
	if (!IS_ENABLED(CFG_NXP_SE05X_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("se050: debug: RSA software fallback: VERIFY");
	return sw_crypto_acipher_rsassa_verify(p->algo,
					       p->key.key,
					       p->salt_len,
					       p->message.data,
					       p->message.length,
					       p->signature.data,
					       p->signature.length);
}

static TEE_Result do_ssa_verify(struct drvcrypt_rsa_ssa *ssa_data)
{
	if (!oefid_keylen_supported(ssa_data->key.n_size * 8))
		return verify_ssa_fallback(ssa_data);

	/* PKCS1_PSS_MGF1 padding limitations */
	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		if (ssa_data->key.n_size * 8 <= 512)
			return verify_ssa_fallback(ssa_data);
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		if (ssa_data->key.n_size * 8 <= 1024)
			return verify_ssa_fallback(ssa_data);
		break;
	default:
		break;
	}

	return verify_ssa(ssa_data->algo,
			ssa_data->key.key,
			ssa_data->message.data,
			ssa_data->message.length,
			ssa_data->signature.data,
			ssa_data->signature.length);
}

static const struct drvcrypt_rsa driver_rsa = {
	.alloc_keypair = do_alloc_keypair,
	.alloc_publickey = do_alloc_publickey,
	.free_publickey = do_free_publickey,
	.free_keypair = do_free_keypair,
	.gen_keypair = do_gen_keypair,
	.encrypt = do_encrypt,
	.decrypt = do_decrypt,
	.optional.ssa_sign = do_ssa_sign,
	.optional.ssa_verify = do_ssa_verify,
};

static TEE_Result rsa_init(void)
{
	return drvcrypt_register_rsa(&driver_rsa);
}

driver_init_late(rsa_init);
