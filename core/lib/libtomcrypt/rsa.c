// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, 2022 Linaro Limited
 */

#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <fault_mitigation.h>
#include <mempool.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

#include "acipher_helpers.h"


/*
 * Compute the LibTomCrypt "hashindex" given a TEE Algorithm "algo"
 * Return
 * - TEE_SUCCESS in case of success,
 * - TEE_ERROR_BAD_PARAMETERS in case algo is not a valid algo
 * - TEE_ERROR_NOT_SUPPORTED in case algo is not supported by LTC
 * Return -1 in case of error
 */
static TEE_Result tee_algo_to_ltc_hashindex(uint32_t algo, int *ltc_hashindex)
{
	switch (algo) {
#if defined(_CFG_CORE_LTC_SHA1_DESC)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		*ltc_hashindex = find_hash("sha1");
		break;
#endif
#if defined(_CFG_CORE_LTC_MD5_DESC)
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_MD5:
		*ltc_hashindex = find_hash("md5");
		break;
#endif
#if defined(_CFG_CORE_LTC_SHA224_DESC)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		*ltc_hashindex = find_hash("sha224");
		break;
#endif
#if defined(_CFG_CORE_LTC_SHA256_DESC)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		*ltc_hashindex = find_hash("sha256");
		break;
#endif
#if defined(_CFG_CORE_LTC_SHA384_DESC)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		*ltc_hashindex = find_hash("sha384");
		break;
#endif
#if defined(_CFG_CORE_LTC_SHA512_DESC)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		*ltc_hashindex = find_hash("sha512");
		break;
#endif
	case TEE_ALG_RSASSA_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_V1_5:
		/* invalid one. but it should not be used anyway */
		*ltc_hashindex = -1;
		return TEE_SUCCESS;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (*ltc_hashindex < 0)
		return TEE_ERROR_NOT_SUPPORTED;
	else
		return TEE_SUCCESS;
}

TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s,
					    size_t key_size_bits __unused)
__weak __alias("sw_crypto_acipher_alloc_rsa_keypair");

TEE_Result sw_crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s,
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
	crypto_acipher_free_rsa_keypair(s);
	return TEE_ERROR_OUT_OF_MEMORY;
}


TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s,
					       size_t key_size_bits __unused)
__weak __alias("sw_crypto_acipher_alloc_rsa_public_key");

TEE_Result sw_crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s,
						  size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e))
		return TEE_ERROR_OUT_OF_MEMORY;
	if (!bn_alloc_max(&s->n))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(&s->e);
	return TEE_ERROR_OUT_OF_MEMORY;
}


void crypto_acipher_free_rsa_public_key(struct rsa_public_key *s)
__weak __alias("sw_crypto_acipher_free_rsa_public_key");

void sw_crypto_acipher_free_rsa_public_key(struct rsa_public_key *s)
{
	if (!s)
		return;
	crypto_bignum_free(&s->n);
	crypto_bignum_free(&s->e);
}


void crypto_acipher_free_rsa_keypair(struct rsa_keypair *s)
__weak __alias("sw_crypto_acipher_free_rsa_keypair");

void sw_crypto_acipher_free_rsa_keypair(struct rsa_keypair *s)
{
	if (!s)
		return;
	crypto_bignum_free(&s->e);
	crypto_bignum_free(&s->d);
	crypto_bignum_free(&s->n);
	crypto_bignum_free(&s->p);
	crypto_bignum_free(&s->q);
	crypto_bignum_free(&s->qp);
	crypto_bignum_free(&s->dp);
	crypto_bignum_free(&s->dq);
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key,
				      size_t key_size)
__weak __alias("sw_crypto_acipher_gen_rsa_key");

TEE_Result sw_crypto_acipher_gen_rsa_key(struct rsa_keypair *key,
					 size_t key_size)
{
	TEE_Result res;
	rsa_key ltc_tmp_key;
	int ltc_res;

	/* Generate a temporary RSA key */
	ltc_res = rsa_make_key_bn_e(NULL, find_prng("prng_crypto"),
				    key_size / 8, key->e, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.N) != key_size) {
		rsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* Copy the key */
		ltc_mp.copy(ltc_tmp_key.d,  key->d);
		ltc_mp.copy(ltc_tmp_key.N,  key->n);
		ltc_mp.copy(ltc_tmp_key.p,  key->p);
		ltc_mp.copy(ltc_tmp_key.q,  key->q);
		ltc_mp.copy(ltc_tmp_key.qP, key->qp);
		ltc_mp.copy(ltc_tmp_key.dP, key->dp);
		ltc_mp.copy(ltc_tmp_key.dQ, key->dq);

		/* Free the temporary key */
		rsa_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}

	return res;
}

static TEE_Result rsadorep(rsa_key *ltc_key, const uint8_t *src,
			   size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	unsigned long blen, offset;
	int ltc_res;

	/*
	 * Use a temporary buffer since we don't know exactly how large the
	 * required size of the out buffer without doing a partial decrypt.
	 * We know the upper bound though.
	 */
	blen = _CFG_CORE_LTC_BIGNUM_MAX_BITS / sizeof(uint8_t);
	buf = mempool_alloc(mempool_default, blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_exptmod(src, src_len, buf, &blen, ltc_key->type,
			      ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_NOT_PRIVATE:
	case CRYPT_PK_INVALID_TYPE:
	case CRYPT_PK_INVALID_SIZE:
	case CRYPT_INVALID_PACKET:
		EMSG("rsa_exptmod() returned %d", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_exptmod() returned %d", ltc_res);
		res = TEE_ERROR_GENERIC;
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

	res = TEE_SUCCESS;
	*dst_len = blen - offset;
	memcpy(dst, (char *)buf + offset, *dst_len);

out:
	mempool_free(mempool_default, buf);

	return res;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *src,
					   size_t src_len, uint8_t *dst,
					   size_t *dst_len)
__weak __alias("sw_crypto_acipher_rsanopad_encrypt");

TEE_Result sw_crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					      const uint8_t *src,
					      size_t src_len, uint8_t *dst,
					      size_t *dst_len)
{
	TEE_Result res;
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PUBLIC;
	ltc_key.e = key->e;
	ltc_key.N = key->n;

	res = rsadorep(&ltc_key, src, src_len, dst, dst_len);
	return res;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					   const uint8_t *src,
					   size_t src_len, uint8_t *dst,
					   size_t *dst_len)
__weak __alias("sw_crypto_acipher_rsanopad_decrypt");

TEE_Result sw_crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					      const uint8_t *src,
					      size_t src_len, uint8_t *dst,
					      size_t *dst_len)
{
	TEE_Result res;
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PRIVATE;
	ltc_key.e = key->e;
	ltc_key.N = key->n;
	ltc_key.d = key->d;
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	res = rsadorep(&ltc_key, src, src_len, dst, dst_len);
	return res;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo,
					struct rsa_keypair *key,
					const uint8_t *label,
					size_t label_len, const uint8_t *src,
					size_t src_len, uint8_t *dst,
					size_t *dst_len)
__weak __alias("sw_crypto_acipher_rsaes_decrypt");

TEE_Result sw_crypto_acipher_rsaes_decrypt(uint32_t algo,
					   struct rsa_keypair *key,
					   const uint8_t *label,
					   size_t label_len, const uint8_t *src,
					   size_t src_len, uint8_t *dst,
					   size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	void *buf = NULL;
	unsigned long blen;
	int ltc_hashindex, ltc_res, ltc_stat, ltc_rsa_algo;
	size_t mod_size;
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PRIVATE;
	ltc_key.e = key->e;
	ltc_key.d = key->d;
	ltc_key.N = key->n;
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		EMSG("tee_algo_to_ltc_hashindex() returned %d", (int)res);
		goto out;
	}

	/*
	 * Use a temporary buffer since we don't know exactly how large
	 * the required size of the out buffer without doing a partial
	 * decrypt. We know the upper bound though.
	 */
	if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
		mod_size = ltc_mp.unsigned_size((void *)(ltc_key.N));
		blen = mod_size - 11;
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
	} else {
		/* Decoded message is always shorter than encrypted message */
		blen = src_len;
		ltc_rsa_algo = LTC_PKCS_1_OAEP;
	}

	buf = mempool_alloc(mempool_default, blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_decrypt_key_ex(src, src_len, buf, &blen,
				     ((label_len == 0) ? 0 : label), label_len,
				     ltc_hashindex, -1, ltc_rsa_algo, &ltc_stat,
				     &ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_INVALID_PADDING:
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_SIZE:
		EMSG("rsa_decrypt_key_ex() returned %d", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_decrypt_key_ex() returned %d", ltc_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	if (ltc_stat != 1) {
		/* This will result in a panic */
		EMSG("rsa_decrypt_key_ex() returned %d and %d",
		     ltc_res, ltc_stat);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (*dst_len < blen) {
		*dst_len = blen;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = TEE_SUCCESS;
	*dst_len = blen;
	memcpy(dst, buf, blen);

out:
	mempool_free(mempool_default, buf);

	return res;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label,
					size_t label_len, const uint8_t *src,
					size_t src_len, uint8_t *dst,
					size_t *dst_len)
__weak __alias("sw_crypto_acipher_rsaes_encrypt");

TEE_Result sw_crypto_acipher_rsaes_encrypt(uint32_t algo,
					   struct rsa_public_key *key,
					   const uint8_t *label,
					   size_t label_len, const uint8_t *src,
					   size_t src_len, uint8_t *dst,
					   size_t *dst_len)
{
	TEE_Result res;
	uint32_t mod_size;
	int ltc_hashindex, ltc_res, ltc_rsa_algo;
	rsa_key ltc_key = {
		.type = PK_PUBLIC,
		.e = key->e,
		.N = key->n
	};

	mod_size =  ltc_mp.unsigned_size((void *)(ltc_key.N));
	if (*dst_len < mod_size) {
		*dst_len = mod_size;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*dst_len = mod_size;

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS)
		goto out;

	if (algo == TEE_ALG_RSAES_PKCS1_V1_5)
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
	else
		ltc_rsa_algo = LTC_PKCS_1_OAEP;

	ltc_res = rsa_encrypt_key_ex(src, src_len, dst,
				     (unsigned long *)(dst_len), label,
				     label_len, NULL, find_prng("prng_crypto"),
				     ltc_hashindex, -1, ltc_rsa_algo, &ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_INVALID_PADDING:
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_SIZE:
		EMSG("rsa_encrypt_key_ex() returned %d", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = TEE_SUCCESS;

out:
	return res;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
				      int salt_len, const uint8_t *msg,
				      size_t msg_len, uint8_t *sig,
				      size_t *sig_len)
__weak __alias("sw_crypto_acipher_rsassa_sign");

TEE_Result sw_crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
					 int salt_len, const uint8_t *msg,
					 size_t msg_len, uint8_t *sig,
					 size_t *sig_len)
{
	TEE_Result res;
	size_t hash_size, mod_size;
	int ltc_res, ltc_rsa_algo, ltc_hashindex;
	unsigned long ltc_sig_len;
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PRIVATE;
	ltc_key.e = key->e;
	ltc_key.N = key->n;
	ltc_key.d = key->d;
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5:
		ltc_rsa_algo = LTC_PKCS_1_V1_5_NA1;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_PSS;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	if (ltc_rsa_algo != LTC_PKCS_1_V1_5_NA1) {
		ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
		if (ltc_res != CRYPT_OK) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		res = tee_alg_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
					      &hash_size);
		if (res != TEE_SUCCESS)
			goto err;

		if (msg_len != hash_size) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}
	}

	mod_size = ltc_mp.unsigned_size((void *)(ltc_key.N));

	if (*sig_len < mod_size) {
		*sig_len = mod_size;
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	ltc_sig_len = mod_size;

	ltc_res = rsa_sign_hash_ex(msg, msg_len, sig, &ltc_sig_len,
				   ltc_rsa_algo, NULL, find_prng("prng_crypto"),
				   ltc_hashindex, salt_len, &ltc_key);

	*sig_len = ltc_sig_len;

	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	res = TEE_SUCCESS;

err:
	return res;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len, const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len)
__weak __alias("sw_crypto_acipher_rsassa_verify");

TEE_Result sw_crypto_acipher_rsassa_verify(uint32_t algo,
					   struct rsa_public_key *key,
					   int salt_len, const uint8_t *msg,
					   size_t msg_len, const uint8_t *sig,
					   size_t sig_len)
{
	TEE_Result res;
	uint32_t bigint_size;
	size_t hash_size;
	int stat, ltc_hashindex, ltc_res, ltc_rsa_algo;
	rsa_key ltc_key = {
		.type = PK_PUBLIC,
		.e = key->e,
		.N = key->n
	};
	struct ftmn   ftmn = { };

	/*
	 * The caller expects to call crypto_acipher_rsassa_verify(),
	 * update the hash as needed.
	 */
	FTMN_CALLEE_SWAP_HASH(FTMN_FUNC_HASH("crypto_acipher_rsassa_verify"));

	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		res = tee_alg_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
					      &hash_size);
		if (res != TEE_SUCCESS)
			goto err;

		if (msg_len != hash_size) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}
	}

	bigint_size = ltc_mp.unsigned_size(ltc_key.N);
	if (sig_len < bigint_size) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto err;
	}

	/* Get the algorithm */
	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
		if (res != TEE_SUCCESS)
			goto err;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5:
		ltc_rsa_algo = LTC_PKCS_1_V1_5_NA1;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_PSS;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	FTMN_PUSH_LINKED_CALL(&ftmn, FTMN_FUNC_HASH("rsa_verify_hash_ex"));
	ltc_res = rsa_verify_hash_ex(sig, sig_len, msg, msg_len, ltc_rsa_algo,
				     ltc_hashindex, salt_len, &stat, &ltc_key);
	res = convert_ltc_verify_status(ltc_res, stat);
	if (res)
		FTMN_SET_CHECK_RES_NOT_ZERO(&ftmn, FTMN_INCR0, res);
	else
		FTMN_SET_CHECK_RES_FROM_CALL(&ftmn, FTMN_INCR0, 0);
	FTMN_POP_LINKED_CALL(&ftmn);
	FTMN_CALLEE_DONE_CHECK(&ftmn, FTMN_INCR0, FTMN_STEP_COUNT(1), res);
	return res;
err:
	FTMN_CALLEE_DONE_NOT_ZERO(res);
	return res;
}
