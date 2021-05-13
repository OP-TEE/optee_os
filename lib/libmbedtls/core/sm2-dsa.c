// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2021 Huawei Technologies Co., Ltd
 */

#include <compiler.h>
#include <crypto/crypto.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <util.h>
#include <utee_defines.h>

#include "mbed_helpers.h"
#include "sm2-dsa.h"

/* SM2 uses 256 bit unsigned integers in big endian format */
#define SM2_INT_SIZE_BYTES 32

/*
 * GM/T 0003.1‒2012 Part1 2 Section 6.1
 */
TEE_Result sm2_mbedtls_dsa_sign(uint32_t algo __unused, struct ecc_keypair *key,
				const uint8_t *msg, size_t msg_len,
				uint8_t *sig, size_t *sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_ecp_group grp = { };
	mbedtls_ecp_point x1y1p = { };
	int mres = 0;
	mbedtls_mpi k = { };
	mbedtls_mpi e = { };
	mbedtls_mpi r = { };
	mbedtls_mpi s = { };
	mbedtls_mpi tmp = { };

	if (*sig_len < 2 * SM2_INT_SIZE_BYTES) {
		*sig_len = 64;
		return TEE_ERROR_SHORT_BUFFER;
	}

	mbedtls_mpi_init(&k);
	mbedtls_mpi_init(&e);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_mpi_init(&tmp);

	mbedtls_ecp_point_init(&x1y1p);

	mbedtls_ecp_group_init(&grp);
	mres = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SM2);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/*
	 * Steps A1 and A2 are the generation of the hash value e from user
	 * information (ZA) and the message to be signed (M). There are not done
	 * here since @msg is expected to be the hash value e already.
	 */

	/* Step A3: generate random number 1 <= k < n */
	do {
		res = mbed_gen_random_upto(&k, &grp.N);
		if (res)
			goto out;

		res = TEE_ERROR_BAD_STATE;

		/* Step A4: compute (x1, y1) = [k]G */

		mres = mbedtls_ecp_mul(&grp, &x1y1p, &k, &grp.G, mbd_rand,
				       NULL);
		if (mres)
			goto out;

		/* Step A5: compute r = (e + x1) mod n */

		mbedtls_mpi_read_binary(&e, (unsigned char *)msg, msg_len);
		mres = mbedtls_mpi_add_mpi(&r, &e, &x1y1p.X);
		if (mres)
			goto out;
		mres = mbedtls_mpi_mod_mpi(&r, &r, &grp.N);
		if (mres)
			goto out;

		/* Step A5 (continued): return to A3 if r = 0 or r + k = n */

		mres = mbedtls_mpi_add_mpi(&tmp, &r, &k);
		if (mres)
			goto out;
	} while (!mbedtls_mpi_cmp_int(&r, 0) ||
		 !mbedtls_mpi_cmp_mpi(&tmp, &grp.N));

	/* Step A6: compute s = ((1 + dA)^-1 * (k - r*dA)) mod n */

	mres = mbedtls_mpi_add_int(&s, (mbedtls_mpi *)key->d, 1);
	if (mres)
		goto out;
	mres = mbedtls_mpi_inv_mod(&s, &s, &grp.N);
	if (mres)
		goto out;
	mres = mbedtls_mpi_mul_mpi(&tmp, &r, (mbedtls_mpi *)key->d);
	if (mres)
		goto out;
	mres = mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp.N);
	if (mres)
		goto out;
	mres = mbedtls_mpi_sub_mpi(&tmp, &k, &tmp);
	if (mres)
		goto out;
	mres = mbedtls_mpi_mul_mpi(&s, &s, &tmp);
	if (mres)
		goto out;
	mres = mbedtls_mpi_mod_mpi(&s, &s, &grp.N);
	if (mres)
		goto out;

	/* Step A7: convert (r, s) to binary for output */

	*sig_len = 2 * SM2_INT_SIZE_BYTES;
	memset(sig, 0, *sig_len);
	mres = mbedtls_mpi_write_binary(&r, sig, SM2_INT_SIZE_BYTES);
	if (mres)
		goto out;
	mres = mbedtls_mpi_write_binary(&s, sig + SM2_INT_SIZE_BYTES,
					SM2_INT_SIZE_BYTES);
	if (mres)
		goto out;

	res = TEE_SUCCESS;
out:
	mbedtls_ecp_point_free(&x1y1p);
	mbedtls_mpi_free(&k);
	mbedtls_mpi_free(&e);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&tmp);
	mbedtls_ecp_group_free(&grp);
	return res;
}

/*
 * GM/T 0003.1‒2012 Part1 2 Section 7.1
 */
TEE_Result sm2_mbedtls_dsa_verify(uint32_t algo __unused,
				  struct ecc_public_key *key,
				  const uint8_t *msg, size_t msg_len,
				  const uint8_t *sig, size_t sig_len)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	mbedtls_ecp_group grp = { };
	mbedtls_mpi rprime = { };
	mbedtls_mpi sprime = { };
	mbedtls_mpi t = { };
	mbedtls_mpi eprime = { };
	mbedtls_mpi R = { };
	mbedtls_ecp_point x1y1p = { };
	mbedtls_ecp_point PA = { };
	int mres = 0;

	if (sig_len != 64)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_mpi_init(&rprime);
	mbedtls_mpi_init(&sprime);
	mbedtls_mpi_init(&t);
	mbedtls_mpi_init(&eprime);
	mbedtls_mpi_init(&R);

	mbedtls_ecp_point_init(&x1y1p);
	mbedtls_ecp_point_init(&PA);

	mbedtls_ecp_group_init(&grp);
	mres = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SM2);
	if (mres) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	mres = mbedtls_mpi_read_binary(&rprime, sig, 32);
	if (mres)
		goto out;
	mres = mbedtls_mpi_read_binary(&sprime, sig + 32, 32);
	if (mres)
		goto out;

	/* Step B1: verify r' in [1, n - 1] */

	if (mbedtls_mpi_cmp_int(&rprime, 1) < 0 ||
	    mbedtls_mpi_cmp_mpi(&rprime, &grp.N) >= 0) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	/* Step B2: verify s' in [1, n - 1] */

	if (mbedtls_mpi_cmp_int(&sprime, 1) < 0 ||
	    mbedtls_mpi_cmp_mpi(&sprime, &grp.N) >= 0) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	/*
	 * Steps B3: M'bar = (ZA || M') and B4: e' = Hv(M'bar) are not done here
	 * because @msg is supposed to contain the hash value e' already.
	 */

	/* Step B5: t = (r' + s') mod n and check t != 0 */

	mres = mbedtls_mpi_add_mpi(&t, &rprime, &sprime);
	if (mres)
		goto out;
	mres = mbedtls_mpi_mod_mpi(&t, &t, &grp.N);
	if (mres)
		goto out;
	if (!mbedtls_mpi_cmp_int(&t, 0)) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	/* Step B6: (x1', y1') = [s']G + [t]PA */

	mres = mbedtls_mpi_copy(&PA.X, (mbedtls_mpi *)key->x);
	if (mres)
		goto out;
	mres = mbedtls_mpi_copy(&PA.Y, (mbedtls_mpi *)key->y);
	if (mres)
		goto out;
	mres = mbedtls_mpi_lset(&PA.Z, 1);
	if (mres)
		goto out;

	mres = mbedtls_ecp_muladd(&grp, &x1y1p, &sprime, &grp.G, &t, &PA);
	if (mres)
		goto out;

	/* Step B7: compute R = (e' + x1') mod n and verify R == r' */

	mres = mbedtls_mpi_read_binary(&eprime, msg, msg_len);
	if (mres)
		goto out;
	mres = mbedtls_mpi_add_mpi(&R, &eprime, &x1y1p.X);
	if (mres)
		goto out;
	mres = mbedtls_mpi_mod_mpi(&R, &R, &grp.N);
	if (mres)
		goto out;
	if (mbedtls_mpi_cmp_mpi(&R, &rprime)) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	res = TEE_SUCCESS;
out:
	mbedtls_ecp_point_free(&x1y1p);
	mbedtls_ecp_point_free(&PA);
	mbedtls_mpi_free(&rprime);
	mbedtls_mpi_free(&sprime);
	mbedtls_mpi_free(&t);
	mbedtls_mpi_free(&eprime);
	mbedtls_mpi_free(&R);
	mbedtls_ecp_group_free(&grp);
	return res;
}
