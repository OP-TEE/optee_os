// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee_api_defines_extensions.h>
#include <tee/tee_cryp_utl.h>
#include <tomcrypt.h>
#include "tomcrypt_mp.h"
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#if defined(CFG_WITH_VFP)
#include <tomcrypt_arm_neon.h>
#include <kernel/thread.h>
#endif

/* Random generator */
static int prng_mpa_start(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_add_entropy(const unsigned char *in __unused,
				unsigned long inlen __unused,
				union Prng_state *prng __unused)
{
	/* No entropy is required */
	return CRYPT_OK;
}

static int prng_mpa_ready(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static unsigned long prng_mpa_read(unsigned char *out, unsigned long outlen,
				   union Prng_state *prng __unused)
{
	if (crypto_rng_read(out, outlen))
		return 0;

	return outlen;
}

static int prng_mpa_done(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_export(unsigned char *out __unused,
			   unsigned long *outlen __unused,
			   union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_import(const unsigned char *in  __unused,
			   unsigned long inlen __unused,
			   union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_test(void)
{
	return CRYPT_OK;
}

static const struct ltc_prng_descriptor prng_mpa_desc = {
	.name = "prng_mpa",
	.export_size = 64,
	.start = &prng_mpa_start,
	.add_entropy = &prng_mpa_add_entropy,
	.ready = &prng_mpa_ready,
	.read = &prng_mpa_read,
	.done = &prng_mpa_done,
	.pexport = &prng_mpa_export,
	.pimport = &prng_mpa_import,
	.test = &prng_mpa_test,
};

/*
 * tee_ltc_reg_algs(): Registers
 *	- algorithms
 *	- hash
 *	- prng (pseudo random generator)
 */

static void tee_ltc_reg_algs(void)
{
#if defined(CFG_CRYPTO_AES)
	register_cipher(&aes_desc);
#endif
#if defined(CFG_CRYPTO_DES)
	register_cipher(&des_desc);
	register_cipher(&des3_desc);
#endif
#if defined(CFG_CRYPTO_MD5)
	register_hash(&md5_desc);
#endif
#if defined(CFG_CRYPTO_SHA1)
	register_hash(&sha1_desc);
#endif
#if defined(CFG_CRYPTO_SHA224)
	register_hash(&sha224_desc);
#endif
#if defined(CFG_CRYPTO_SHA256)
	register_hash(&sha256_desc);
#endif
#if defined(CFG_CRYPTO_SHA384)
	register_hash(&sha384_desc);
#endif
#if defined(CFG_CRYPTO_SHA512)
	register_hash(&sha512_desc);
#endif
	register_prng(&prng_mpa_desc);
}


#if defined(CFG_CRYPTO_RSA)

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
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		*ltc_hashindex = find_hash("sha1");
		break;
#endif
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		*ltc_hashindex = find_hash("md5");
		break;
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		*ltc_hashindex = find_hash("sha224");
		break;
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		*ltc_hashindex = find_hash("sha256");
		break;
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		*ltc_hashindex = find_hash("sha384");
		break;
#endif
#if defined(CFG_CRYPTO_SHA512)
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
#endif /* defined(CFG_CRYPTO_RSA) */

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_ACIPHER)

static bool bn_alloc_max(struct bignum **s)
{
	*s = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);

	return *s;
}

static TEE_Result __maybe_unused convert_ltc_verify_status(int ltc_res,
							   int ltc_stat)
{
	switch (ltc_res) {
	case CRYPT_OK:
		if (ltc_stat == 1)
			return TEE_SUCCESS;
		else
			return TEE_ERROR_SIGNATURE_INVALID;
	case CRYPT_INVALID_PACKET:
		return TEE_ERROR_SIGNATURE_INVALID;
	default:
		return TEE_ERROR_GENERIC;
	}
}

#if defined(CFG_CRYPTO_RSA)

TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s,
					    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e)) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}
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
	crypto_bignum_free(s->e);
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->n);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	crypto_bignum_free(s->qp);
	crypto_bignum_free(s->dp);

	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s,
					       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e)) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	if (!bn_alloc_max(&s->n))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->e);
	return TEE_ERROR_OUT_OF_MEMORY;
}

void crypto_acipher_free_rsa_public_key(struct rsa_public_key *s)
{
	if (!s)
		return;
	crypto_bignum_free(s->n);
	crypto_bignum_free(s->e);
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result res;
	rsa_key ltc_tmp_key;
	int ltc_res;
	long e;

	/* get the public exponent */
	e = mp_get_int(key->e);

	/* Generate a temporary RSA key */
	ltc_res = rsa_make_key(NULL, find_prng("prng_mpa"), key_size / 8, e,
			       &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.N) != key_size) {
		rsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* Copy the key */
		ltc_mp.copy(ltc_tmp_key.e,  key->e);
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
	blen = CFG_CORE_BIGNUM_MAX_BITS / sizeof(uint8_t);
	buf = malloc(blen);
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
	if (buf)
		free(buf);

	return res;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
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
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
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

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
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

	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_decrypt_key_ex(src, src_len, buf, &blen,
				     ((label_len == 0) ? 0 : label), label_len,
				     ltc_hashindex, ltc_rsa_algo, &ltc_stat,
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
	if (buf)
		free(buf);

	return res;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
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
				     label_len, NULL, find_prng("prng_mpa"),
				     ltc_hashindex, ltc_rsa_algo, &ltc_key);
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

		res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
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
				   ltc_rsa_algo, NULL, find_prng("prng_mpa"),
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

	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
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

	ltc_res = rsa_verify_hash_ex(sig, sig_len, msg, msg_len, ltc_rsa_algo,
				     ltc_hashindex, salt_len, &stat, &ltc_key);
	res = convert_ltc_verify_status(ltc_res, stat);
err:
	return res;
}

#endif /* CFG_CRYPTO_RSA */


#if defined(CFG_CRYPTO_DH)

TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s,
					   size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->g)) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	if (!bn_alloc_max(&s->p))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->q))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->y);
	crypto_bignum_free(s->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key, struct bignum *q,
				     size_t xbits)
{
	TEE_Result res;
	dh_key ltc_tmp_key;
	int ltc_res;

	/* Generate the DH key */
	ltc_tmp_key.g = key->g;
	ltc_tmp_key.p = key->p;
	ltc_res = dh_make_key(NULL, find_prng("prng_mpa"), q, xbits,
			      &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		ltc_mp.copy(ltc_tmp_key.y,  key->y);
		ltc_mp.copy(ltc_tmp_key.x,  key->x);

		/* Free the tempory key */
		dh_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *public_key,
					   struct bignum *secret)
{
	int err;
	dh_key pk = {
		.type = PK_PRIVATE,
		.g = private_key->g,
		.p = private_key->p,
		.y = private_key->y,
		.x = private_key->x
	};

	err = dh_shared_secret(&pk, public_key, secret);
	return ((err == CRYPT_OK) ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS);
}

#endif /* CFG_CRYPTO_DH */
#endif /* _CFG_CRYPTO_WITH_ACIPHER */


TEE_Result crypto_init(void)
{
	init_mp_tomcrypt();
	tee_ltc_reg_algs();

	return TEE_SUCCESS;
}

#if defined(CFG_WITH_VFP)
void tomcrypt_arm_neon_enable(struct tomcrypt_arm_neon_state *state)
{
	state->state = thread_kernel_enable_vfp();
}

void tomcrypt_arm_neon_disable(struct tomcrypt_arm_neon_state *state)
{
	thread_kernel_disable_vfp(state->state);
}
#endif

#if defined(CFG_CRYPTO_SHA256)
TEE_Result hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size)
{
	hash_state hs;
	uint8_t digest[TEE_SHA256_HASH_SIZE];

	if (sha256_init(&hs) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha256_process(&hs, data, data_size) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha256_done(&hs, digest) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (consttime_memcmp(digest, hash, sizeof(digest)) != 0)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}
#endif

#if defined(CFG_CRYPTO_SHA512_256)
TEE_Result hash_sha512_256_compute(uint8_t *digest, const uint8_t *data,
		size_t data_size)
{
	hash_state hs;

	if (sha512_256_init(&hs) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha512_256_process(&hs, data, data_size) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha512_256_done(&hs, digest) != CRYPT_OK)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
#endif

TEE_Result crypto_aes_expand_enc_key(const void *key, size_t key_len,
				     void *enc_key, size_t enc_keylen,
				     unsigned int *rounds)
{
	symmetric_key skey;

	if (enc_keylen < sizeof(skey.rijndael.eK))
		return TEE_ERROR_BAD_PARAMETERS;

	if (aes_setup(key, key_len, 0, &skey))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(enc_key, skey.rijndael.eK, sizeof(skey.rijndael.eK));
	*rounds = skey.rijndael.Nr;
	return TEE_SUCCESS;
}

void crypto_aes_enc_block(const void *enc_key, size_t enc_keylen __maybe_unused,
			  unsigned int rounds, const void *src, void *dst)
{
	symmetric_key skey;

	assert(enc_keylen >= sizeof(skey.rijndael.eK));
	memcpy(skey.rijndael.eK, enc_key, sizeof(skey.rijndael.eK));
	skey.rijndael.Nr = rounds;
	if (aes_ecb_encrypt(src, dst, &skey))
		panic();
}
