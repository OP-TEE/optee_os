/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tomcrypt.h>
#include <mpalib.h>

#include <stdlib.h>
#include <string.h>
#include <tee/tee_acipher.h>
#include <utee_defines.h>
#include <tee/tee_hash.h>
#include <kernel/tee_core_trace.h>
#include <tee_ltc_wrapper.h>

TEE_Result tee_acipher_gen_rsa_keys(rsa_key *ltc_key, size_t key_size)
{
	TEE_Result res;
	rsa_key ltc_tmp_key;
	int ltc_res;

	/* Get the rsa key */
	ltc_res = rsa_make_key(
		0, tee_ltc_get_rng_mpa(), key_size/8, 65537, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.N) != key_size) {
		rsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* copy the key */
		ltc_mp.copy(ltc_tmp_key.e,  ltc_key->e);
		ltc_mp.copy(ltc_tmp_key.d,  ltc_key->d);
		ltc_mp.copy(ltc_tmp_key.N,  ltc_key->N);
		ltc_mp.copy(ltc_tmp_key.p,  ltc_key->p);
		ltc_mp.copy(ltc_tmp_key.q,  ltc_key->q);
		ltc_mp.copy(ltc_tmp_key.qP, ltc_key->qP);
		ltc_mp.copy(ltc_tmp_key.dP, ltc_key->dP);
		ltc_mp.copy(ltc_tmp_key.dQ, ltc_key->dQ);

		/* free the tempory key */
		rsa_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result tee_acipher_gen_dh_keys(dh_key *ltc_key, void *q, size_t xbits)
{
	TEE_Result res;
	dh_key ltc_tmp_key;
	int ltc_res;

	/* Get the dh key */
	ltc_tmp_key.g = ltc_key->g;
	ltc_tmp_key.p = ltc_key->p;
	ltc_res = dh_make_key(
		0, tee_ltc_get_rng_mpa(),
		q, xbits, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		ltc_mp.copy(ltc_tmp_key.y,  ltc_key->y);
		ltc_mp.copy(ltc_tmp_key.x,  ltc_key->x);

		/* free the tempory key */
		dh_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result tee_acipher_gen_dsa_keys(dsa_key *ltc_key, size_t key_size)
{
	TEE_Result res;
	dsa_key ltc_tmp_key;
	size_t group_size, modulus_size = key_size/8;
	int ltc_res;

	if (modulus_size <= 128)
		group_size = 20;
	else if (modulus_size <= 256)
		group_size = 30;
	else if (modulus_size <= 384)
		group_size = 35;
	else
		group_size = 40;

	/* Get the dsa key */
	ltc_res = dsa_make_key(
		0, tee_ltc_get_rng_mpa(),
		group_size, modulus_size, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.p) != key_size) {
		dsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* copy the key */
		ltc_mp.copy(ltc_tmp_key.g,  ltc_key->g);
		ltc_mp.copy(ltc_tmp_key.p,  ltc_key->p);
		ltc_mp.copy(ltc_tmp_key.q,  ltc_key->q);
		ltc_mp.copy(ltc_tmp_key.y,  ltc_key->y);
		ltc_mp.copy(ltc_tmp_key.x,  ltc_key->x);

		/* free the tempory key */
		dsa_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result tee_derive_dh_shared_secret(
		dh_key *private_key, void *public_key, void *secret)
{
	int err;
	err = dh_shared_secret(private_key, public_key, secret);

	return ((err == CRYPT_OK) ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS);
}

TEE_Result tee_acipher_rsadorep(
	rsa_key *ltc_key,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	uint32_t blen, offset;
	int ltc_res;

	/*
	 * Use a temporary buffer since we don't know exactly how large the
	 * required size of the out buffer without doing a partial decrypt.
	 * We know the upper bound though.
	 */
	blen = (mpa_StaticTempVarSizeInU32(LTC_MAX_BITS_PER_VARIABLE)) *
	       sizeof(uint32_t);
	buf = malloc(blen);
	if (buf == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_exptmod(
		src, src_len,	/* input message and length */
		buf, (unsigned long *)(&blen),	/* decrypted message and len */
		ltc_key->type,
		ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_NOT_PRIVATE:
	case CRYPT_PK_INVALID_TYPE:
	case CRYPT_PK_INVALID_SIZE:
	case CRYPT_INVALID_PACKET:
		EMSG("rsa_exptmod() returned %d\n", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_exptmod() returned %d\n", ltc_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* remove the zero-padding (leave one zero if buff is all zeroes) */
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

TEE_Result tee_acipher_rsaes_decrypt(
	uint32_t algo, rsa_key *ltc_key, const uint8_t *label, size_t label_len,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	void *buf = NULL;
	uint32_t blen;
	int ltc_hashindex, ltc_res, ltc_stat, ltc_rsa_algo;
	size_t mod_size;

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		goto out;
	}

	if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
		mod_size = ltc_mp.unsigned_size((void *)(ltc_key->N));
		/*
		 * Use a temporary buffer since we don't know exactly how large
		 * the required size of the out buffer without doing a partial
		 * decrypt. We know the upper bound though.
		 */
		blen = mod_size - 11;
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
	} else {
		/*
		 * Use a temporary buffer since we don't know exactly how
		 * large the required size of the out buffer without doing a
		 * partial decrypt. We know the upper bound though: the length
		 * of the decoded message is lower than the encrypted message
		 */
		blen = src_len;
		ltc_rsa_algo = LTC_LTC_PKCS_1_OAEP;
	}

	buf = malloc(blen);
	if (buf == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_decrypt_key_ex(
		src, src_len,	/* input message and length */
		buf, (unsigned long *)(&blen),	/* decrypted message and len */
		((label_len == 0) ? 0 : label), label_len, /* label and len */
		ltc_hashindex,	/* hash index, based on the algo */
		ltc_rsa_algo,
		&ltc_stat,
		ltc_key);

	switch (ltc_res) {
	case CRYPT_PK_INVALID_PADDING:
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_SIZE:
		EMSG("rsa_decrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_decrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (ltc_stat != 1) {
		/* This will result in a panic */
		EMSG("rsa_decrypt_key_ex() returned %d and %d\n",
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

TEE_Result tee_acipher_rsaes_encrypt(
	uint32_t algo, rsa_key *ltc_key, const uint8_t *label, size_t label_len,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result res;
	uint32_t mod_size;
	int ltc_hashindex, ltc_res, ltc_rsa_algo;

	mod_size =  ltc_mp.unsigned_size((void *)(ltc_key->N));
	if (*dst_len < mod_size) {
		*dst_len = mod_size;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*dst_len = mod_size;

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		goto out;
	}

	if (algo == TEE_ALG_RSAES_PKCS1_V1_5)
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
	else
		ltc_rsa_algo = LTC_LTC_PKCS_1_OAEP;

	ltc_res = rsa_encrypt_key_ex(
		src, src_len,	/* input message and length */
		dst, (unsigned long *)(dst_len), /* encrypted message and len */
		label, label_len, /* label and  length */
		0, tee_ltc_get_rng_mpa(),
		ltc_hashindex,	/* hash index, based on the algo */
		ltc_rsa_algo,
		ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_INVALID_PADDING:
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_SIZE:
		EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = TEE_SUCCESS;

out:
	return res;
}


TEE_Result tee_acipher_rsassa_sign(
	uint32_t algo, rsa_key *ltc_key, int salt_len,
	const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	size_t hash_size;
	size_t mod_size;
	int ltc_res, ltc_rsa_algo, ltc_hashindex;

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_PSS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	res =
	    tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo), &hash_size);
	if (res != TEE_SUCCESS)
		return res;

	if (msg_len != hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	mod_size = ltc_mp.unsigned_size((void *)(ltc_key->N));

	if (*sig_len < mod_size) {
		*sig_len = mod_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	*sig_len = mod_size;

	ltc_res = rsa_sign_hash_ex(
		msg, msg_len,
		sig, (unsigned long *)(&sig_len),
		ltc_rsa_algo,
		0, tee_ltc_get_rng_mpa(),
		ltc_hashindex,
		salt_len,
		ltc_key);

	if (ltc_res != CRYPT_OK) {
		EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_acipher_rsassa_verify(
	uint32_t algo, rsa_key *ltc_key, int salt_len,
	const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len)
{
	TEE_Result res;
	uint32_t bigint_size;
	int stat, ltc_hashindex, ltc_res, ltc_rsa_algo;

	bigint_size = ltc_mp.unsigned_size(ltc_key->N);
	if (sig_len < bigint_size)
		return TEE_ERROR_SIGNATURE_INVALID;


	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		return res;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_PSS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ltc_res = rsa_verify_hash_ex(
		sig, sig_len,
		msg, msg_len,
		ltc_rsa_algo, ltc_hashindex,
		salt_len,
		&stat,
		ltc_key);
	if ((ltc_res != CRYPT_OK) || (stat != 1)) {
		EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_acipher_dsa_sign(
	uint32_t algo, dsa_key *ltc_key,
	const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	int ltc_res;
	void *r, *s;
	if (*sig_len < 2 * mp_unsigned_bin_size(ltc_key->q)) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key->q);
		return TEE_ERROR_SHORT_BUFFER;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;
	ltc_res = dsa_sign_hash_raw(
		msg, msg_len, r, s, 0, tee_ltc_get_rng_mpa(), ltc_key);

	if (ltc_res == CRYPT_OK) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key->q);
		memset(sig, 0, *sig_len);
		mp_to_unsigned_bin(
			r,
			(uint8_t *)sig + *sig_len/2 - mp_unsigned_bin_size(r));
		mp_to_unsigned_bin(
			s,
			(uint8_t *)sig + *sig_len   - mp_unsigned_bin_size(s));
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_GENERIC;
	}

	mp_clear_multi(r, s, NULL);
	return res;
}

TEE_Result tee_acipher_dsa_verify(
	uint32_t algo, dsa_key *ltc_key,
	const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len)
{
	TEE_Result res;
	int ltc_stat, ltc_res;
	void *r, *s;

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;
	mp_read_unsigned_bin(r, (uint8_t *)sig, sig_len/2);
	mp_read_unsigned_bin(s, (uint8_t *)sig + sig_len/2, sig_len/2);
	ltc_res = dsa_verify_hash_raw(r, s, msg, msg_len, &ltc_stat, ltc_key);
	mp_clear_multi(r, s, NULL);

	if ((ltc_res == CRYPT_OK) && (ltc_stat == 1))
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_GENERIC;

	mp_clear_multi(r, s, NULL);
	return res;
}
