// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <io.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <util.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

static TEE_Result
sm2_uncompressed_bytes_to_point(ecc_point *p, const ltc_ecc_dp *dp,
				const uint8_t *x1y1, size_t max_size,
				size_t *consumed)
{
	uint8_t *ptr = (uint8_t *)x1y1;
	TEE_Result res = TEE_SUCCESS;
	uint8_t one[] = { 1 };
	int ltc_res = 0;
	void *x1 = NULL;
	void *y1 = NULL;

	if (max_size < (size_t)(2 * dp->size))
		return TEE_ERROR_BAD_PARAMETERS;

	ltc_res = mp_init_multi(&x1, &y1, &p->z, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;

	ltc_res = mp_read_unsigned_bin(x1, ptr, dp->size);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	ptr += dp->size;

	ltc_res = mp_read_unsigned_bin(y1, ptr, dp->size);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	ltc_res = ltc_ecc_is_point(dp, x1, y1);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	p->x = x1;
	p->y = y1;
	mp_read_unsigned_bin(p->z, one, sizeof(one));

	*consumed = 2 * dp->size + 1; /* PC */

	return TEE_SUCCESS;
err:
	mp_clear_multi(x1, y1, p->z, NULL);
	return res;
}

/*
 * GM/T 0003.1‒2012 Part 1 Section 4.2.9
 * Conversion of a byte string @buf to a point @p. Makes sure @p is on the curve
 * defined by domain parameters @dp.
 * Note: only the uncompressed form is supported. Uncompressed and hybrid forms
 * are TBD.
 */
static TEE_Result sm2_bytes_to_point(ecc_point *p, const ltc_ecc_dp *dp,
				     const uint8_t *buf, size_t max_size,
				     size_t *consumed)
{
	uint8_t PC = 0;

	if (!max_size)
		return TEE_ERROR_BAD_PARAMETERS;

	PC = buf[0];

	switch (PC) {
	case 0x02:
	case 0x03:
		/* Compressed form */
		return TEE_ERROR_NOT_SUPPORTED;
	case 0x04:
		/* UNcompressed form */
		return sm2_uncompressed_bytes_to_point(p, dp, buf + 1,
						       max_size - 1, consumed);
	case 0x06:
	case 0x07:
		/* Hybrid form */
		return TEE_ERROR_NOT_SUPPORTED;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_ERROR_GENERIC;
}

/*
 * GM/T 0003.1‒2012 Part 4 Sections 5.4.2 and 5.4.3
 * Key derivation function based on the SM3 hash function
 */
static TEE_Result sm2_kdf(const uint8_t *Z, size_t Z_len, uint8_t *t,
			  size_t tlen)
{
	TEE_Result res = TEE_SUCCESS;
	size_t remain = tlen;
	uint32_t count = 1;
	uint32_t be_count = 0;
	void *ctx = NULL;
	uint8_t *out = t;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SM3);
	if (res)
		return res;

	while (remain) {
		uint8_t tmp[TEE_SM3_HASH_SIZE] = { };
		uint8_t *buf = NULL;

		if (remain >= TEE_SM3_HASH_SIZE)
			buf = out;
		else
			buf = tmp;

		put_be32(&be_count, count);
		res = crypto_hash_init(ctx);
		if (res)
			goto out;
		res = crypto_hash_update(ctx, Z, Z_len);
		if (res)
			goto out;
		res = crypto_hash_update(ctx, (const uint8_t *)&be_count,
					 sizeof(be_count));
		if (res)
			goto out;
		res = crypto_hash_final(ctx, buf, TEE_SM3_HASH_SIZE);
		if (res)
			goto out;

		if (remain < TEE_SM3_HASH_SIZE) {
			memcpy(out, tmp, remain);
			break;
		}

		out += TEE_SM3_HASH_SIZE;
		remain -= TEE_SM3_HASH_SIZE;
		count++;
	}
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

static bool is_zero(const uint8_t *buf, size_t size)
{
	uint8_t v = 0;
	size_t i = 0;

	for (i = 0; i < size; i++)
		v |= buf[i];

	return !v;
}

/*
 * GM/T 0003.1‒2012 Part 4 Section 7.1
 * Decryption algorithm
 */
TEE_Result crypto_acipher_sm2_pke_decrypt(struct ecc_keypair *key,
					  const uint8_t *src, size_t src_len,
					  uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t x2y2[64] = { };
	ecc_key ltc_key = { };
	ecc_point *C1 = NULL;
	size_t C1_len = 0;
	ecc_point *S = NULL;
	ecc_point *x2y2p = NULL;
	void *ctx = NULL;
	int ltc_res = 0;
	void *h = NULL;
	int inf = 0;
	uint8_t *t = NULL;
	size_t C2_len = 0;
	size_t i = 0;
	size_t out_len = 0;
	uint8_t *eom = NULL;
	uint8_t u[TEE_SM3_HASH_SIZE] = { };

	/*
	 * Input buffer src is (C1 || C2 || C3)
	 * - C1 represents a point (should be on the curve)
	 * - C2 is the encrypted message
	 * - C3 is a SM3 hash
	 */

	res = ecc_populate_ltc_private_key(&ltc_key, key, TEE_ALG_SM2_PKE,
					   NULL);
	if (res)
		goto out;

	/* Step B1: read and validate point C1 from encrypted message */

	C1 = ltc_ecc_new_point();
	if (!C1) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = sm2_bytes_to_point(C1, &ltc_key.dp, src, src_len, &C1_len);
	if (res)
		goto out;

	/* Step B2: S = [h]C1 */

	if (ltc_key.dp.cofactor != 1) {
		S = ltc_ecc_new_point();
		if (!S) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		ltc_res = mp_init_multi(&h, NULL);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_OUT_OF_MEMORY;

		ltc_res = mp_set_int(h, ltc_key.dp.cofactor);
		if (ltc_res != CRYPT_OK) {
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}

		ltc_res = ltc_ecc_mulmod(h, C1, S, ltc_key.dp.A,
					 ltc_key.dp.prime, 1);
		if (ltc_res != CRYPT_OK) {
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}

		ltc_res = ltc_ecc_is_point_at_infinity(S, ltc_key.dp.prime,
						       &inf);
	} else {
		ltc_res = ltc_ecc_is_point_at_infinity(C1, ltc_key.dp.prime,
						       &inf);
	}
	if (inf) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Step B3: (x2, y2) = [dB]C1 */

	x2y2p = ltc_ecc_new_point();
	if (!x2y2p) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = ltc_ecc_mulmod(ltc_key.k, C1, x2y2p, ltc_key.dp.A,
				 ltc_key.dp.prime, 1);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (mp_unsigned_bin_size(x2y2p->x) != 32 ||
	    mp_unsigned_bin_size(x2y2p->y) != 32) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	mp_to_unsigned_bin(x2y2p->x, x2y2);
	mp_to_unsigned_bin(x2y2p->y, x2y2 + 32);

	/* Step B4: t = KDF(x2 || y2, klen) */

	/* C = C1 || C2 || C3 */
	if (src_len <= C1_len + TEE_SM3_HASH_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	C2_len = src_len - C1_len - TEE_SM3_HASH_SIZE;

	t = calloc(1, C2_len);
	if (!t) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = sm2_kdf(x2y2, sizeof(x2y2), t, C2_len);
	if (res)
		goto out;

	if (is_zero(t, C2_len)) {
		res = TEE_ERROR_CIPHERTEXT_INVALID;
		goto out;
	}

	/* Step B5: get C2 from C and compute Mprime = C2 (+) t */

	out_len = MIN(*dst_len, C2_len);
	for (i = 0; i < out_len; i++)
		dst[i] = src[C1_len + i] ^ t[i];
	*dst_len = out_len;
	if (out_len < C2_len) {
		eom = calloc(1, C2_len - out_len);
		if (!eom)
			goto out;
		for (i = out_len; i < C2_len; i++)
		       eom[i - out_len] = src[C1_len + i] ^ t[i];
	}

	/* Step B6: compute u = Hash(x2 || M' || y2) and compare with C3 */

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SM3);
	if (res)
		goto out;
	res = crypto_hash_init(ctx);
	if (res)
		goto out;
	res = crypto_hash_update(ctx, x2y2, 32);
	if (res)
		goto out;
	res = crypto_hash_update(ctx, dst, out_len);
	if (res)
		goto out;
	if (out_len < C2_len) {
		res = crypto_hash_update(ctx, eom, C2_len - out_len);
		if (res)
			goto out;
	}
	res = crypto_hash_update(ctx, x2y2 + 32, 32);
	if (res)
		goto out;
	res = crypto_hash_final(ctx, u, sizeof(u));
	if (res)
		goto out;

	if (consttime_memcmp(u, src + C1_len + C2_len, TEE_SM3_HASH_SIZE)) {
		res = TEE_ERROR_CIPHERTEXT_INVALID;
		goto out;
	}
out:
	free(eom);
	free(t);
	crypto_hash_free_ctx(ctx);
	ltc_ecc_del_point(x2y2p);
	ltc_ecc_del_point(S);
	ltc_ecc_del_point(C1);
	mp_clear_multi(h, NULL);
	return res;
}

/*
 * GM/T 0003.1‒2012 Part 1 Section 4.2.8
 * Conversion of point @p to a byte string @buf (uncompressed form).
 */
static TEE_Result sm2_point_to_bytes(uint8_t *buf, size_t *size,
				     const ecc_point *p)
{
	size_t xsize = mp_unsigned_bin_size(p->x);
	size_t ysize = mp_unsigned_bin_size(p->y);

	if (*size < xsize + ysize + 1)
		return TEE_ERROR_BAD_STATE;

	buf[0] = 0x04;  /* Uncompressed form indicator */
	mp_to_unsigned_bin(p->x, buf + 1);
	mp_to_unsigned_bin(p->y, buf + 1 + xsize);

	*size = xsize + ysize + 1;

	return TEE_SUCCESS;
}

/*
 * GM/T 0003.1‒2012 Part 4 Section 6.1
 * Encryption algorithm
 */
TEE_Result crypto_acipher_sm2_pke_encrypt(struct ecc_public_key *key,
					  const uint8_t *src, size_t src_len,
					  uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	ecc_key ltc_key = { };
	ecc_point *x2y2p = NULL;
	ecc_point *C1 = NULL;
	ecc_point *S = NULL;
	uint8_t x2y2[64] = { };
	uint8_t *t = NULL;
	int ltc_res = 0;
	void *k = NULL;
	void *h = NULL;
	int inf = 0;
	size_t C1_len = 0;
	void *ctx = NULL;
	size_t i = 0;

	ltc_res = mp_init_multi(&k, &h, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = ecc_populate_ltc_public_key(&ltc_key, key, TEE_ALG_SM2_PKE, NULL);
	if (res)
		goto out;

	/* Step A1: generate random number 1 <= k < n */

	ltc_res = rand_bn_upto(k, ltc_key.dp.order, NULL,
			       find_prng("prng_crypto"));
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Step A2: compute C1 = [k]G */

	C1 = ltc_ecc_new_point();
	if (!C1) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = ltc_ecc_mulmod(k, &ltc_key.dp.base, C1, ltc_key.dp.A,
				 ltc_key.dp.prime, 1);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Step A3: compute S = [h]PB and check for infinity */

	if (ltc_key.dp.cofactor != 1) {
		S = ltc_ecc_new_point();
		if (!S) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		ltc_res = mp_set_int(h, ltc_key.dp.cofactor);
		if (ltc_res != CRYPT_OK) {
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}

		ltc_res = ltc_ecc_mulmod(h, &ltc_key.pubkey, S, ltc_key.dp.A,
					 ltc_key.dp.prime, 1);
		if (ltc_res != CRYPT_OK) {
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}

		ltc_res = ltc_ecc_is_point_at_infinity(S, ltc_key.dp.prime,
						       &inf);
	} else {
		ltc_res = ltc_ecc_is_point_at_infinity(&ltc_key.pubkey,
						       ltc_key.dp.prime, &inf);
	}
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	if (inf) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Step A4: compute (x2, y2) = [k]PB */

	x2y2p = ltc_ecc_new_point();
	if (!x2y2p) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = ltc_ecc_mulmod(k, &ltc_key.pubkey, x2y2p, ltc_key.dp.A,
				 ltc_key.dp.prime, 1);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (mp_unsigned_bin_size(x2y2p->x) != 32 ||
	    mp_unsigned_bin_size(x2y2p->y) != 32) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	mp_to_unsigned_bin(x2y2p->x, x2y2);
	mp_to_unsigned_bin(x2y2p->y, x2y2 + 32);

	/* Step A5: compute t = KDF(x2 || y2, klen) */

	t = calloc(1, src_len);
	if (!t) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = sm2_kdf(x2y2, sizeof(x2y2), t, src_len);
	if (res)
		goto out;

	if (is_zero(t, src_len)) {
		res = TEE_ERROR_CIPHERTEXT_INVALID;
		goto out;
	}

	/*
	 * Steps A6, A7, A8:
	 * Compute C2 = M (+) t
	 * Compute C3 = Hash(x2 || M || y2)
	 * Output C = C1 || C2 || C3
	 */

	/* C1 */
	C1_len = *dst_len;
	res = sm2_point_to_bytes(dst, &C1_len, C1);
	if (res)
		goto out;

	if (*dst_len < C1_len + src_len + TEE_SM3_HASH_SIZE) {
		*dst_len = C1_len + src_len + TEE_SM3_HASH_SIZE;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	/* C2 */
	for (i = 0; i < src_len; i++)
		dst[i + C1_len] = src[i] ^ t[i];

	/* C3 */
        res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SM3);
        if (res)
                goto out;
        res = crypto_hash_init(ctx);
        if (res)
                goto out;
        res = crypto_hash_update(ctx, x2y2, 32);
        if (res)
                goto out;
        res = crypto_hash_update(ctx, src, src_len);
        if (res)
                goto out;
        res = crypto_hash_update(ctx, x2y2 + 32, 32);
        if (res)
                goto out;
        res = crypto_hash_final(ctx, dst + C1_len + src_len, TEE_SM3_HASH_SIZE);
        if (res)
                goto out;

	*dst_len = C1_len + src_len + TEE_SM3_HASH_SIZE;
out:
	crypto_hash_free_ctx(ctx);
	free(t);
	ltc_ecc_del_point(x2y2p);
	ltc_ecc_del_point(S);
	ltc_ecc_del_point(C1);
	mp_clear_multi(k, h, NULL);
	return res;
}
