// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-21 Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <crypto/sm2-kdf.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <utee_defines.h>

#include "mbed_helpers.h"

/* SM2 uses 256 bit unsigned integers in big endian format */
#define SM2_INT_SIZE_BYTES 32

/* The public x and y values extracted from a public or private ECC key */
struct key_xy {
	mbedtls_mpi *x;
	mbedtls_mpi *y;
};

/*
 * Compute a hash of a user's identity and public key
 * For user A: ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
 */
static TEE_Result sm2_kep_compute_Z(const mbedtls_ecp_group *grp, uint8_t *Z,
				    size_t Zlen, const uint8_t *id,
				    size_t idlen, struct key_xy *key)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t ENTLEN[2] = { };
	uint8_t buf[SM2_INT_SIZE_BYTES] = { };
	void *ctx = NULL;
	int mres = 0;

	if (Zlen < TEE_SM3_HASH_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	/*
	 * ENTLEN is the length in bits if the user's distinguished identifier
	 * encoded over 16 bits in big endian format.
	 */
	ENTLEN[0] = (idlen * 8) >> 8;
	ENTLEN[1] = idlen * 8;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SM3);
	if (res)
		goto out;

	res = crypto_hash_init(ctx);
	if (res)
		goto out;

	res = crypto_hash_update(ctx, ENTLEN, sizeof(ENTLEN));
	if (res)
		goto out;

	res = crypto_hash_update(ctx, id, idlen);
	if (res)
		goto out;

	mres = mbedtls_mpi_write_binary(&grp->A, buf, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mres = mbedtls_mpi_write_binary(&grp->B, buf, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mres = mbedtls_mpi_write_binary(&grp->G.X, buf, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mres = mbedtls_mpi_write_binary(&grp->G.Y, buf, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mres = mbedtls_mpi_write_binary(key->x, buf, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mres = mbedtls_mpi_write_binary(key->y, buf, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	res = crypto_hash_final(ctx, Z, TEE_SM3_HASH_SIZE);
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

/*
 * Compute a verification value, to be checked against the value sent by the
 * peer.
 * On the initiator's side:
 *   S1 = SM3(0x02 || yU || SM3(xU || ZA || ZB || x1 || y1 || x2 || y2))
 * On the responder's side:
 *   S2 = SM3(0x03 || yV || SM3(xV || ZA || ZB || x1 || y1 || x2 || y2))
 */
static TEE_Result sm2_kep_compute_S(uint8_t *S, size_t S_len, uint8_t flag,
				    mbedtls_ecp_point *UV, const uint8_t *ZAZB,
				    size_t ZAZB_len,
				    struct key_xy *initiator_eph_key,
				    struct key_xy *responder_eph_key)
{
	uint8_t hash[TEE_SM3_HASH_SIZE] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t buf[SM2_INT_SIZE_BYTES];
	void *ctx = NULL;
	int mres = 0;

	if (S_len < TEE_SM3_HASH_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SM3);
	if (res)
		goto out;

	/* Compute the inner hash */

	res = crypto_hash_init(ctx);
	if (res)
		goto out;

	/* xU or xV */
	mres = mbedtls_mpi_write_binary(&UV->X, buf, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* ZA || ZB */
	res = crypto_hash_update(ctx, ZAZB, ZAZB_len);
	if (res)
		goto out;

	/* x1 */
	mres = mbedtls_mpi_write_binary(initiator_eph_key->x, buf,
					SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* y1 */
	mres = mbedtls_mpi_write_binary(initiator_eph_key->y, buf,
					SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* x2 */
	mres = mbedtls_mpi_write_binary(responder_eph_key->x, buf,
					SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* y2 */
	mres = mbedtls_mpi_write_binary(responder_eph_key->y, buf,
					SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	res = crypto_hash_final(ctx, hash, sizeof(hash));
	if (res)
		goto out;

	/* Now compute S */

	res = crypto_hash_init(ctx);
	if (res)
		goto out;

	/* 0x02 or 0x03  */
	res = crypto_hash_update(ctx, &flag, sizeof(flag));
	if (res)
		goto out;

	/* yU or yV */
	mres = mbedtls_mpi_write_binary(&UV->Y, buf, SM2_INT_SIZE_BYTES);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* Inner SM3(...) */
	res = crypto_hash_update(ctx, hash, sizeof(hash));
	if (res)
		goto out;

	res = crypto_hash_final(ctx, S, TEE_SM3_HASH_SIZE);

out:
	crypto_hash_free_ctx(ctx);
	return res;

}

static void extract_xy_from_keypair(struct key_xy *xy,
				    const struct ecc_keypair *pair)
{
	xy->x = (mbedtls_mpi *)pair->x;
	xy->y = (mbedtls_mpi *)pair->y;
	/* Other fields are not used */
}

static void extract_xy_from_public_key(struct key_xy *xy,
				       const struct ecc_public_key *from)
{
	xy->x = (mbedtls_mpi *)from->x;
	xy->y = (mbedtls_mpi *)from->y;
}

/*
 * GM/T 0003.1‒2012 Part 3 Section 6.1
 * Key exchange protocol
 */
TEE_Result crypto_acipher_sm2_kep_derive(struct ecc_keypair *my_key,
					 struct ecc_keypair *my_eph_key,
					 struct ecc_public_key *peer_key,
					 struct ecc_public_key *peer_eph_key,
					 struct sm2_kep_parms *p)
{
	/*
	 * Variable names and documented steps reflect the initator side (user A
	 * in the spec), but the other side is quite similar hence only one
	 * function.
	 */
	uint8_t xUyUZAZB[2 * SM2_INT_SIZE_BYTES + 2 * TEE_SM3_HASH_SIZE] = { };
	struct key_xy initiator_eph_key = { };
	struct key_xy responder_eph_key = { };
	struct key_xy initiator_key = { };
	struct key_xy responder_key = { };
	TEE_Result res = TEE_ERROR_BAD_STATE;
	uint8_t tmp[SM2_INT_SIZE_BYTES] = { };
	mbedtls_ecp_group grp = { };
	mbedtls_ecp_point PB = { };
	mbedtls_ecp_point RB = { };
	mbedtls_ecp_point U = { };
	mbedtls_mpi x1bar = { };
	mbedtls_mpi x2bar = { };
	mbedtls_mpi tA = { };
	mbedtls_mpi h = { };
	mbedtls_mpi htA = { };
	mbedtls_mpi one = { };
	int mres = 0;

	if (p->is_initiator) {
		extract_xy_from_keypair(&initiator_eph_key, my_eph_key);
		extract_xy_from_public_key(&responder_eph_key, peer_eph_key);
		extract_xy_from_keypair(&initiator_key, my_key);
		extract_xy_from_public_key(&responder_key, peer_key);
	} else {
		extract_xy_from_public_key(&initiator_eph_key, peer_eph_key);
		extract_xy_from_keypair(&responder_eph_key, my_eph_key);
		extract_xy_from_public_key(&initiator_key, peer_key);
		extract_xy_from_keypair(&responder_key, my_key);
	}

	mbedtls_mpi_init(&x1bar);
	mbedtls_mpi_init(&x2bar);
	mbedtls_mpi_init(&tA);
	mbedtls_mpi_init(&h);
	mbedtls_mpi_init(&htA);
	mbedtls_mpi_init(&one);

	mbedtls_ecp_point_init(&PB);
	mbedtls_ecp_point_init(&RB);
	mbedtls_ecp_point_init(&U);

	mbedtls_ecp_group_init(&grp);
	mres = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SM2);
	if (mres)
		goto out;

	/*
	 * Steps A1-A3 are supposedly done already (generate ephemeral key, send
	 * it to peer).
	 * Step A4: (x1, y1) = RA; x1bar = 2^w + (x1 & (2^w - 1))
	 */

	mres = mbedtls_mpi_write_binary((mbedtls_mpi *)my_eph_key->x, tmp,
					SM2_INT_SIZE_BYTES);
	if (mres)
		goto out;
	tmp[SM2_INT_SIZE_BYTES / 2] |= 0x80;
	mres = mbedtls_mpi_read_binary(&x1bar,  tmp + SM2_INT_SIZE_BYTES / 2,
				       SM2_INT_SIZE_BYTES / 2);
	if (mres)
		goto out;

	/* Step A5: tA = (dA + x1bar * rA) mod n */

	mres = mbedtls_mpi_mul_mpi(&tA, &x1bar, (mbedtls_mpi *)my_eph_key->d);
	if (mres)
		goto out;
	mres = mbedtls_mpi_mod_mpi(&tA, &tA, &grp.N);
	if (mres)
		goto out;
	mres = mbedtls_mpi_add_mpi(&tA, &tA, (mbedtls_mpi *)my_key->d);
	if (mres)
		goto out;
	mres = mbedtls_mpi_mod_mpi(&tA, &tA, &grp.N);
	if (mres)
		goto out;

	/* Step A6: verify whether RB verifies the curve equation */

	mbedtls_mpi_copy(&RB.X, (mbedtls_mpi *)peer_eph_key->x);
	mbedtls_mpi_copy(&RB.Y, (mbedtls_mpi *)peer_eph_key->y);
	mbedtls_mpi_lset(&RB.Z, 1);
	mres = mbedtls_ecp_check_pubkey(&grp, &RB);
	if (mres)
		goto out;

	/* Step A6 (continued): (x2, y2) = RB; x2bar = 2^w + (x2 & (2^w - 1)) */

	mres = mbedtls_mpi_write_binary((mbedtls_mpi *)peer_eph_key->x, tmp,
					SM2_INT_SIZE_BYTES);
	if (mres)
		goto out;
	tmp[SM2_INT_SIZE_BYTES / 2] |= 0x80;
	mres = mbedtls_mpi_read_binary(&x2bar,  tmp + SM2_INT_SIZE_BYTES / 2,
				SM2_INT_SIZE_BYTES / 2);
	if (mres)
		goto out;

	/* Step A7: compute U = [h.tA](PB + [x2bar]RB) and check for infinity */

	mres = mbedtls_mpi_copy(&PB.X, (mbedtls_mpi *)peer_key->x);
	if (mres)
		goto out;
	mres = mbedtls_mpi_copy(&PB.Y, (mbedtls_mpi *)peer_key->y);
	if (mres)
		goto out;
	mres = mbedtls_mpi_lset(&PB.Z, 1);
	if (mres)
		goto out;
	mres = mbedtls_mpi_lset(&one, 1);
	if (mres)
		goto out;

	mres = mbedtls_ecp_muladd(&grp, &U, &one, &PB, &x2bar, &RB);
	if (mres)
		goto out;

	/* Note: the cofactor for SM2 is 1 so [h.tA] == tA */
	mres = mbedtls_ecp_mul(&grp, &U, &tA, &U, mbd_rand, NULL);
	if (mres)
		goto out;

	/*
	 * "Point is zero" is same as "point is at infinity". Returns 1 if
	 * point is zero, < 0 on error and 0 if point is non-zero.
	 */
	mres = mbedtls_ecp_is_zero(&U);
	if (mres)
		goto out;

	/* Step A8: compute KA = KDF(xU || yU || ZA || ZB, klen) */

	/* xU */
	mres = mbedtls_mpi_write_binary(&U.X, xUyUZAZB, SM2_INT_SIZE_BYTES);
	if (mres)
		goto out;

	/* yU */
	mres = mbedtls_mpi_write_binary(&U.Y, xUyUZAZB + SM2_INT_SIZE_BYTES,
					SM2_INT_SIZE_BYTES);
	if (mres)
		goto out;

	/* ZA */
	res = sm2_kep_compute_Z(&grp, xUyUZAZB + 2 * SM2_INT_SIZE_BYTES,
				TEE_SM3_HASH_SIZE, p->initiator_id,
				p->initiator_id_len, &initiator_key);
	if (res)
		goto out;

	/* ZB */
	res = sm2_kep_compute_Z(&grp, xUyUZAZB + 2 * SM2_INT_SIZE_BYTES +
					TEE_SM3_HASH_SIZE,
				TEE_SM3_HASH_SIZE, p->responder_id,
				p->responder_id_len, &responder_key);
	if (res)
		goto out;

	res = sm2_kdf(xUyUZAZB, sizeof(xUyUZAZB), p->out, p->out_len);
	if (res)
		goto out;

	/* Step A9: compute S1 and check S1 == SB */

	if (p->conf_in) {
		uint8_t S1[TEE_SM3_HASH_SIZE] = { };
		uint8_t flag = p->is_initiator ? 0x02 : 0x03;

		if (p->conf_in_len < TEE_SM3_HASH_SIZE) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
		res = sm2_kep_compute_S(S1, sizeof(S1), flag, &U,
					xUyUZAZB + 2 * SM2_INT_SIZE_BYTES,
					2 * SM2_INT_SIZE_BYTES,
					&initiator_eph_key, &responder_eph_key);
		if (res)
			goto out;

		if (consttime_memcmp(S1, p->conf_in, sizeof(S1))) {
			/* Verification failed */
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}
	}

	/* Step A10: compute SA */

	if (p->conf_out) {
		uint8_t flag = p->is_initiator ? 0x03 : 0x02;

		if (p->conf_out_len < TEE_SM3_HASH_SIZE) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		res = sm2_kep_compute_S(p->conf_out, TEE_SM3_HASH_SIZE, flag,
					&U, xUyUZAZB + 2 * SM2_INT_SIZE_BYTES,
					2 * SM2_INT_SIZE_BYTES,
					&initiator_eph_key, &responder_eph_key);
	}
out:
	mbedtls_mpi_free(&x1bar);
	mbedtls_mpi_free(&x2bar);
	mbedtls_mpi_free(&tA);
	mbedtls_mpi_free(&h);
	mbedtls_mpi_free(&htA);
	mbedtls_mpi_free(&one);
	mbedtls_ecp_point_free(&PB);
	mbedtls_ecp_point_free(&RB);
	mbedtls_ecp_point_free(&U);
	mbedtls_ecp_group_free(&grp);
	return res;
}
