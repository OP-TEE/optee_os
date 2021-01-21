// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020 Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <crypto/sm2-kdf.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <util.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

/* SM2 uses 256 bit unsigned integers in big endian format */
#define SM2_INT_SIZE_BYTES 32

/*
 * Compute a hash of a user's identity and public key
 * For user A: ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
 */
static TEE_Result sm2_kep_compute_Z(uint8_t *Z, size_t Zlen, const uint8_t *id,
				    size_t idlen, const ecc_key *key)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t ENTLEN[2] = { };
	uint8_t buf[SM2_INT_SIZE_BYTES];
	void *ctx = NULL;

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

	mp_to_unsigned_bin2(key->dp.A, buf, SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mp_to_unsigned_bin2(key->dp.B, buf, SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mp_to_unsigned_bin2(key->dp.base.x, buf, SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mp_to_unsigned_bin2(key->dp.base.y, buf, SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mp_to_unsigned_bin2(key->pubkey.x, buf, SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	mp_to_unsigned_bin2(key->pubkey.y, buf, SM2_INT_SIZE_BYTES);
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
				    ecc_point *UV, const uint8_t *ZAZB,
				    size_t ZAZB_len, ecc_key *initiator_eph_key,
				    ecc_key *responder_eph_key)
{
	uint8_t hash[TEE_SM3_HASH_SIZE] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t buf[SM2_INT_SIZE_BYTES];
	void *ctx = NULL;

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
	mp_to_unsigned_bin2(UV->x, buf, SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* ZA || ZB */
	res = crypto_hash_update(ctx, ZAZB, ZAZB_len);
	if (res)
		goto out;

	/* x1 */
	mp_to_unsigned_bin2(initiator_eph_key->pubkey.x, buf,
			    SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* y1 */
	mp_to_unsigned_bin2(initiator_eph_key->pubkey.y, buf,
			    SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* x2 */
	mp_to_unsigned_bin2(responder_eph_key->pubkey.x, buf,
			    SM2_INT_SIZE_BYTES);
	res = crypto_hash_update(ctx, buf, sizeof(buf));
	if (res)
		goto out;

	/* y2 */
	mp_to_unsigned_bin2(responder_eph_key->pubkey.y, buf,
			   SM2_INT_SIZE_BYTES);
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
	mp_to_unsigned_bin2(UV->y, buf, SM2_INT_SIZE_BYTES);
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

/*
 * GM/T 0003.1‒2012 Part 3 Section 6.1
 * Key exchange protocol
 */
static TEE_Result sm2_kep_derive(ecc_key *my_key, ecc_key *my_eph_key,
				 ecc_key *peer_key, ecc_key *peer_eph_key,
				 struct sm2_kep_parms *p)
{
	/*
	 * Variable names and documented steps reflect the initator side (user A
	 * in the spec), but the other side is quite similar hence only one
	 * function.
	 */
	uint8_t xUyUZAZB[2 * SM2_INT_SIZE_BYTES + 2 * TEE_SM3_HASH_SIZE] = { };
	ecc_key *initiator_eph_key = p->is_initiator ? my_eph_key :
						       peer_eph_key;
	ecc_key *responder_eph_key = p->is_initiator ? peer_eph_key :
						       my_eph_key;
	ecc_key *initiator_key = p->is_initiator ? my_key : peer_key;
	ecc_key *responder_key = p->is_initiator ? peer_key : my_key;
	TEE_Result res = TEE_ERROR_BAD_STATE;
	uint8_t tmp[SM2_INT_SIZE_BYTES];
	void *n = my_key->dp.order;
	ecc_point *U = NULL;
	void *x1bar = NULL;
	void *x2bar = NULL;
	void *tA = NULL;
	void *h = NULL;
	void *htA = NULL;
	void *mp = NULL;
	void *mu = NULL;
	void *ma = NULL;
	void *one = NULL;
	int ltc_res = 0;
	int inf = 0;

	ltc_res = mp_init_multi(&x1bar, &x2bar, &tA, &h, &htA, &mu, &ma, &one,
				NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	U = ltc_ecc_new_point();
	if (!U) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Steps A1-A3 are supposedly done already (generate ephemeral key, send
	 * it to peer).
	 * Step A4: (x1, y1) = RA; x1bar = 2^w + (x1 & (2^w - 1))
	 */

	mp_to_unsigned_bin2(my_eph_key->pubkey.x, tmp, SM2_INT_SIZE_BYTES);
	tmp[SM2_INT_SIZE_BYTES / 2] |= 0x80;
	mp_read_unsigned_bin(x1bar, tmp + SM2_INT_SIZE_BYTES / 2,
			     SM2_INT_SIZE_BYTES / 2);

	/* Step A5: tA = (dA + x1bar * rA) mod n */

	ltc_res = mp_mulmod(x1bar, my_eph_key->k, n, tA);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = mp_addmod(tA, my_key->k, n, tA);
	if (ltc_res != CRYPT_OK)
		goto out;

	/* Step A6: verify whether RB verifies the curve equation */

	ltc_res = ltc_ecc_is_point(&peer_eph_key->dp, peer_eph_key->pubkey.x,
				   peer_eph_key->pubkey.y);
	if (ltc_res != CRYPT_OK)
		goto out;

	/* Step A6 (continued): (x2, y2) = RB; x2bar = 2^w + (x2 & (2^w - 1)) */

	mp_to_unsigned_bin2(peer_eph_key->pubkey.x, tmp, SM2_INT_SIZE_BYTES);
	tmp[SM2_INT_SIZE_BYTES / 2] |= 0x80;
	mp_read_unsigned_bin(x2bar, tmp + SM2_INT_SIZE_BYTES / 2,
			     SM2_INT_SIZE_BYTES / 2);


	/* Step A7: compute U = [h.tA](PB + [x2bar]RB) and check for infinity */

	ltc_res = mp_montgomery_setup(peer_key->dp.prime, &mp);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = mp_montgomery_normalization(mu, peer_key->dp.prime);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = mp_mulmod(peer_key->dp.A, mu, peer_key->dp.prime, ma);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = mp_set_int(one, 1);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = ltc_ecc_mul2add(&peer_key->pubkey, one, &peer_eph_key->pubkey,
				  x2bar, U, ma, peer_key->dp.prime);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = mp_set_int(h, peer_key->dp.cofactor);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = mp_mul(h, tA, htA);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = ltc_ecc_mulmod(htA, U, U, peer_key->dp.A, peer_key->dp.prime,
				 1);
	if (ltc_res != CRYPT_OK)
		goto out;

	ltc_res = ltc_ecc_is_point_at_infinity(U, peer_key->dp.prime, &inf);
	if (ltc_res != CRYPT_OK)
		goto out;

	if (inf)
		goto out;

	/* Step A8: compute KA = KDF(xU || yU || ZA || ZB, klen) */

	/* xU */
	mp_to_unsigned_bin2(U->x, xUyUZAZB, SM2_INT_SIZE_BYTES);

	/* yU */
	mp_to_unsigned_bin2(U->y, xUyUZAZB + SM2_INT_SIZE_BYTES,
			    SM2_INT_SIZE_BYTES);

	/* ZA */
	res = sm2_kep_compute_Z(xUyUZAZB + 2 * SM2_INT_SIZE_BYTES,
				TEE_SM3_HASH_SIZE, p->initiator_id,
				p->initiator_id_len, initiator_key);
	if (res)
		goto out;

	/* ZB */
	res = sm2_kep_compute_Z(xUyUZAZB + 2 * SM2_INT_SIZE_BYTES +
					TEE_SM3_HASH_SIZE,
				TEE_SM3_HASH_SIZE, p->responder_id,
				p->responder_id_len, responder_key);
	if (res)
		goto out;

	res = sm2_kdf(xUyUZAZB, sizeof(xUyUZAZB), p->out, p->out_len);
	if (res)
		goto out;

	/* Step A9: compute S1 and check S1 == SB */

	if (p->conf_in) {
		uint8_t S1[TEE_SM3_HASH_SIZE];
		uint8_t flag = p->is_initiator ? 0x02 : 0x03;

		if (p->conf_in_len < TEE_SM3_HASH_SIZE) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
		res = sm2_kep_compute_S(S1, sizeof(S1), flag, U,
					xUyUZAZB + 2 * SM2_INT_SIZE_BYTES,
					2 * SM2_INT_SIZE_BYTES,
					initiator_eph_key, responder_eph_key);
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

		res = sm2_kep_compute_S(p->conf_out, TEE_SM3_HASH_SIZE, flag, U,
					xUyUZAZB + 2 * SM2_INT_SIZE_BYTES,
					2 * SM2_INT_SIZE_BYTES,
					initiator_eph_key, responder_eph_key);
		if (res)
			goto out;
	}
out:
	mp_montgomery_free(mp);
	ltc_ecc_del_point(U);
	mp_clear_multi(x1bar, x2bar, tA, h, htA, mu, ma, one, NULL);
	return res;
}

TEE_Result crypto_acipher_sm2_kep_derive(struct ecc_keypair *my_key,
					 struct ecc_keypair *my_eph_key,
					 struct ecc_public_key *peer_key,
					 struct ecc_public_key *peer_eph_key,
					 struct sm2_kep_parms *p)
{
	TEE_Result res = TEE_SUCCESS;
	ecc_key ltc_my_key = { };
	ecc_key ltc_my_eph_key = { };
	ecc_key ltc_peer_key = { };
	ecc_key ltc_peer_eph_key = { };

	res = ecc_populate_ltc_private_key(&ltc_my_key, my_key,
					   TEE_ALG_SM2_KEP, NULL);
	if (res)
		goto out;

	res = ecc_populate_ltc_private_key(&ltc_my_eph_key, my_eph_key,
					   TEE_ALG_SM2_KEP, NULL);
	if (res)
		goto out;

	res = ecc_populate_ltc_public_key(&ltc_peer_key, peer_key,
					  TEE_ALG_SM2_KEP, NULL);
	if (res)
		goto out;

	res = ecc_populate_ltc_public_key(&ltc_peer_eph_key, peer_eph_key,
					  TEE_ALG_SM2_KEP, NULL);
	if (res)
		goto out;

	res = sm2_kep_derive(&ltc_my_key, &ltc_my_eph_key, &ltc_peer_key,
			     &ltc_peer_eph_key, p);
out:
	ecc_free(&ltc_peer_eph_key);
	ecc_free(&ltc_peer_key);
	ecc_free(&ltc_my_eph_key);
	ecc_free(&ltc_my_key);
	return res;
}
