// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <util.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

/* SM2 uses 256 bit unsigned integers in big endian format */
#define SM2_INT_SIZE_BYTES 32

/*
 * GM/T 0003.1‒2012 Part1 2 Section 6.1
 */
TEE_Result sm2_ltc_dsa_sign(uint32_t algo, struct ecc_keypair *key,
			    const uint8_t *msg, size_t msg_len, uint8_t *sig,
			    size_t *sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	ecc_point *x1y1p = NULL;
	ecc_key ltc_key = { };
	int ltc_res = 0;
	void *k = NULL;
	void *e = NULL;
	void *r = NULL;
	void *s = NULL;
	void *tmp = NULL;

	if (*sig_len < 2 * SM2_INT_SIZE_BYTES) {
		*sig_len = 64;
		return TEE_ERROR_SHORT_BUFFER;
	}

	ltc_res = mp_init_multi(&k, &e, &r, &s, &tmp, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;

	x1y1p = ltc_ecc_new_point();
	if (!x1y1p) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = ecc_populate_ltc_private_key(&ltc_key, key, algo, NULL);
	if (res)
		goto out;

	/*
	 * Steps A1 and A2 are the generation of the hash value e from user
	 * information (ZA) and the message to be signed (M). There are not done
	 * here since @msg is expected to be the hash value e already.
	 */

	/* Step A3: generate random number 1 <= k < n */
A3:
	ltc_res = rand_bn_upto(k, ltc_key.dp.order, NULL,
			       find_prng("prng_crypto"));
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Step A4: compute (x1, y1) = [k]G */

	ltc_res = ltc_ecc_mulmod(k, &ltc_key.dp.base, x1y1p, ltc_key.dp.A,
				 ltc_key.dp.prime, 1);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Step A5: compute r = (e + x1) mod n */

	mp_read_unsigned_bin(e, (unsigned char *)msg, msg_len);
	ltc_res = mp_addmod(e, x1y1p->x, ltc_key.dp.order, r);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	ltc_res = mp_add(r, k, tmp);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	if (mp_cmp_d(r, 0) == LTC_MP_EQ ||
	    mp_cmp(tmp, ltc_key.dp.order) == LTC_MP_EQ)
		goto A3;

	/* Step A6: compute s = ((1 + dA)^-1 * (k - r*dA)) mod n */

	ltc_res = mp_add_d(ltc_key.k, 1, s);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	ltc_res = mp_invmod(s, ltc_key.dp.order, s);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	ltc_res = mp_mul(r, ltc_key.k, tmp);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	ltc_res = mp_sub(k, tmp, tmp);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	ltc_res = mp_mulmod(s, tmp, ltc_key.dp.order, s);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Step A7: convert (r, s) to binary for output */

	*sig_len = 2 * SM2_INT_SIZE_BYTES;
	memset(sig, 0, *sig_len);
	mp_to_unsigned_bin2(r, sig, SM2_INT_SIZE_BYTES);
	mp_to_unsigned_bin2(s, sig + SM2_INT_SIZE_BYTES, SM2_INT_SIZE_BYTES);
out:
	ecc_free(&ltc_key);
	ltc_ecc_del_point(x1y1p);
	mp_clear_multi(k, e, r, s, tmp, NULL);
	return res;
}

/*
 * GM/T 0003.1‒2012 Part1 2 Section 7.1
 */
TEE_Result sm2_ltc_dsa_verify(uint32_t algo, struct ecc_public_key *key,
			      const uint8_t *msg, size_t msg_len,
			      const uint8_t *sig, size_t sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	ecc_key ltc_key = { };
	int ltc_res = 0;
	void *rprime = NULL;
	void *sprime = NULL;
	void *t = NULL;
	void *mp = NULL;
	void *mu = NULL;
	void *ma = NULL;
	void *eprime = NULL;
	void *R = NULL;
	ecc_point *x1y1p = NULL;

	if (sig_len != 64)
		return TEE_ERROR_BAD_PARAMETERS;

	ltc_res = mp_init_multi(&rprime, &sprime, &t, &mu, &ma, &eprime, &R,
				NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;

	mp_read_unsigned_bin(rprime, (unsigned char *)sig, 32);
	mp_read_unsigned_bin(sprime, (unsigned char *)sig + 32, 32);

	res = ecc_populate_ltc_public_key(&ltc_key, key, algo, NULL);
	if (res)
		goto out;

	/* Step B1: verify r' in [1, n - 1] */

	if (mp_cmp_d(rprime, 1) == LTC_MP_LT ||
	    mp_cmp(rprime, ltc_key.dp.order) != LTC_MP_LT) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	/* Step B2: verify s' in [1, n - 1] */

	if (mp_cmp_d(sprime, 1) == LTC_MP_LT ||
	    mp_cmp(sprime, ltc_key.dp.order) != LTC_MP_LT) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	/*
	 * Steps B3: M'bar = (ZA || M') and B4: e' = Hv(M'bar) are not done here
	 * because @msg is supposed to contain the hash value e' already.
	 */

	/* Step B5: t = (r' + s') mod n and check t != 0 */

	ltc_res = mp_addmod(rprime, sprime, ltc_key.dp.order, t);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	if (mp_cmp_d(t, 0) == LTC_MP_EQ) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	/* Step B6: (x1', y1') = [s']G + [t]PA */

	x1y1p = ltc_ecc_new_point();
	if (!x1y1p) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	ltc_res = mp_montgomery_setup(ltc_key.dp.prime, &mp);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	ltc_res = mp_montgomery_normalization(mu, ltc_key.dp.prime);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	ltc_res = mp_mulmod(ltc_key.dp.A, mu, ltc_key.dp.prime, ma);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	ltc_res = ltc_ecc_mul2add(&ltc_key.dp.base, sprime, &ltc_key.pubkey, t,
				  x1y1p, ma, ltc_key.dp.prime);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Step B7: compute R = (e' + x1') mod n and verify R == r' */

	mp_read_unsigned_bin(eprime, (unsigned char *)msg, msg_len);
	ltc_res = mp_addmod(eprime, x1y1p->x, ltc_key.dp.order, R);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	if (mp_cmp(R, rprime) != LTC_MP_EQ)
		res = TEE_ERROR_SIGNATURE_INVALID;
out:
	mp_montgomery_free(mp);
	ltc_ecc_del_point(x1y1p);
	ecc_free(&ltc_key);
	mp_clear_multi(rprime, sprime, t, mu, ma, eprime, R, NULL);
	return res;
}
