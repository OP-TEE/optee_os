// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2021 Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <crypto/sm2-kdf.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <util.h>
#include <utee_defines.h>

#include "mbed_helpers.h"
#include "sm2-pke.h"

/* SM2 uses 256 bit unsigned integers in big endian format */
#define SM2_INT_SIZE_BYTES 32

static TEE_Result
sm2_uncompressed_bytes_to_point(const mbedtls_ecp_group *grp,
				mbedtls_ecp_point *p, const uint8_t *x1y1,
				size_t max_size, size_t *consumed)
{
	uint8_t *ptr = (uint8_t *)x1y1;
	int mres = 0;

	if (max_size < (size_t)(2 * SM2_INT_SIZE_BYTES))
		return TEE_ERROR_BAD_PARAMETERS;

	mres = mbedtls_mpi_read_binary(&p->X, ptr, SM2_INT_SIZE_BYTES);
	if (mres)
		return TEE_ERROR_BAD_PARAMETERS;

	ptr += SM2_INT_SIZE_BYTES;

	mres = mbedtls_mpi_read_binary(&p->Y, ptr, SM2_INT_SIZE_BYTES);
	if (mres)
		return TEE_ERROR_BAD_PARAMETERS;

	mres = mbedtls_mpi_lset(&p->Z, 1);
	if (mres)
		return TEE_ERROR_BAD_PARAMETERS;

	mres = mbedtls_ecp_check_pubkey(grp, p);
	if (mres)
		return TEE_ERROR_BAD_PARAMETERS;

	*consumed = 2 * SM2_INT_SIZE_BYTES + 1; /* PC */

	return TEE_SUCCESS;
}

/*
 * GM/T 0003.1‒2012 Part 1 Section 4.2.9
 * Conversion of a byte string @buf to a point @p. Makes sure @p is on the curve
 * defined by domain parameters @dp.
 * Note: only the uncompressed form is supported. Uncompressed and hybrid forms
 * are TBD.
 */
static TEE_Result sm2_bytes_to_point(const mbedtls_ecp_group *grp,
				     mbedtls_ecp_point *p, const uint8_t *buf,
				     size_t max_size, size_t *consumed)
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
		/* Uncompressed form */
		return sm2_uncompressed_bytes_to_point(grp, p, buf + 1,
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
TEE_Result sm2_mbedtls_pke_decrypt(struct ecc_keypair *key, const uint8_t *src,
				   size_t src_len, uint8_t *dst,
				   size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t x2y2[64] = { };
	mbedtls_ecp_point C1 = { };
	size_t C1_len = 0;
	mbedtls_ecp_point x2y2p = { };
	mbedtls_ecp_group grp = { };
	void *ctx = NULL;
	int mres = 0;
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

	mbedtls_ecp_point_init(&C1);
	mbedtls_ecp_point_init(&x2y2p);

	mbedtls_ecp_group_init(&grp);
	mres = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SM2);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Step B1: read and validate point C1 from encrypted message */

	res = sm2_bytes_to_point(&grp, &C1, src, src_len, &C1_len);
	if (res)
		goto out;

	/*
	 * Step B2: S = [h]C1, the cofactor h is 1 for SM2 so S == C1.
	 * The fact that S is on the curve has already been checked in
	 * sm2_bytes_to_point().
	 */

	/* Step B3: (x2, y2) = [dB]C1 */

	mres = mbedtls_ecp_mul(&grp, &x2y2p, (mbedtls_mpi *)key->d, &C1,
			       mbd_rand, NULL);
	if (mres) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (mbedtls_mpi_size(&x2y2p.X) > SM2_INT_SIZE_BYTES ||
	    mbedtls_mpi_size(&x2y2p.Y) > SM2_INT_SIZE_BYTES) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	mres = mbedtls_mpi_write_binary(&x2y2p.X, x2y2, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	mres = mbedtls_mpi_write_binary(&x2y2p.Y, x2y2 + SM2_INT_SIZE_BYTES,
					SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

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
		if (!eom) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
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
	res = crypto_hash_update(ctx, x2y2, SM2_INT_SIZE_BYTES);
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
	res = crypto_hash_update(ctx, x2y2 + SM2_INT_SIZE_BYTES,
				 SM2_INT_SIZE_BYTES);
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
	mbedtls_ecp_point_free(&C1);
	mbedtls_ecp_point_free(&x2y2p);
	mbedtls_ecp_group_free(&grp);
	return res;
}

/*
 * GM/T 0003.1‒2012 Part 1 Section 4.2.8
 * Conversion of point @p to a byte string @buf (uncompressed form).
 */
static TEE_Result sm2_point_to_bytes(uint8_t *buf, size_t *size,
				     const mbedtls_ecp_point *p)
{
	size_t xsize = mbedtls_mpi_size(&p->X);
	size_t ysize = mbedtls_mpi_size(&p->Y);
	size_t sz = 2 * SM2_INT_SIZE_BYTES + 1;
	int mres = 0;

	if (xsize > SM2_INT_SIZE_BYTES || ysize > SM2_INT_SIZE_BYTES ||
	    *size < sz)
		return TEE_ERROR_BAD_STATE;

	memset(buf, 0, sz);
	buf[0] = 0x04;  /* Uncompressed form indicator */
	mres = mbedtls_mpi_write_binary(&p->X, buf + 1, SM2_INT_SIZE_BYTES);
	if (mres)
		return TEE_ERROR_BAD_STATE;
	mres = mbedtls_mpi_write_binary(&p->Y, buf + 1 + SM2_INT_SIZE_BYTES,
					SM2_INT_SIZE_BYTES);
	if (mres)
		return TEE_ERROR_BAD_STATE;

	*size = sz;

	return TEE_SUCCESS;
}

/*
 * GM/T 0003.1‒2012 Part 4 Section 6.1
 * Encryption algorithm
 */
TEE_Result sm2_mbedtls_pke_encrypt(struct ecc_public_key *key,
				   const uint8_t *src, size_t src_len,
				   uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_ecp_group grp = { };
	mbedtls_ecp_point x2y2p = { };
	mbedtls_ecp_point PB = { };
	mbedtls_ecp_point C1 = { };
	uint8_t x2y2[64] = { };
	uint8_t *t = NULL;
	int mres = 0;
	mbedtls_mpi k = { };
	size_t C1_len = 0;
	void *ctx = NULL;
	size_t i = 0;

	mbedtls_mpi_init(&k);

	mbedtls_ecp_point_init(&x2y2p);
	mbedtls_ecp_point_init(&PB);
	mbedtls_ecp_point_init(&C1);

	mbedtls_ecp_group_init(&grp);
	mres = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SM2);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Step A1: generate random number 1 <= k < n */

	res = mbed_gen_random_upto(&k, &grp.N);
	if (res)
		goto out;

	/* Step A2: compute C1 = [k]G */

	mres = mbedtls_ecp_mul(&grp, &C1, &k, &grp.G, mbd_rand, NULL);
	if (mres) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/*
	 * Step A3: compute S = [h]PB and check for infinity.
	 * The cofactor h is 1 for SM2 so S == PB, nothing to do.
	 */

	/* Step A4: compute (x2, y2) = [k]PB */

	mbedtls_mpi_copy(&PB.X, (mbedtls_mpi *)key->x);
	mbedtls_mpi_copy(&PB.Y, (mbedtls_mpi *)key->y);
	mbedtls_mpi_lset(&PB.Z, 1);

	mres = mbedtls_ecp_mul(&grp, &x2y2p, &k, &PB, mbd_rand, NULL);
	if (mres) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (mbedtls_mpi_size(&x2y2p.X) > SM2_INT_SIZE_BYTES ||
	    mbedtls_mpi_size(&x2y2p.Y) > SM2_INT_SIZE_BYTES) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	mres = mbedtls_mpi_write_binary(&x2y2p.X, x2y2, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	mres = mbedtls_mpi_write_binary(&x2y2p.Y, x2y2 + SM2_INT_SIZE_BYTES,
					SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

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
	res = sm2_point_to_bytes(dst, &C1_len, &C1);
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
        res = crypto_hash_update(ctx, x2y2, SM2_INT_SIZE_BYTES);
        if (res)
                goto out;
        res = crypto_hash_update(ctx, src, src_len);
        if (res)
                goto out;
        res = crypto_hash_update(ctx, x2y2 + SM2_INT_SIZE_BYTES,
				 SM2_INT_SIZE_BYTES);
        if (res)
                goto out;
        res = crypto_hash_final(ctx, dst + C1_len + src_len, TEE_SM3_HASH_SIZE);
        if (res)
                goto out;

	*dst_len = C1_len + src_len + TEE_SM3_HASH_SIZE;
out:
	crypto_hash_free_ctx(ctx);
	free(t);
	mbedtls_ecp_point_free(&x2y2p);
	mbedtls_ecp_point_free(&PB);
	mbedtls_ecp_point_free(&C1);
	mbedtls_ecp_group_free(&grp);
	mbedtls_mpi_free(&k);
	return res;
}
