// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <stdlib.h>
#include <string.h>

#include "mbd_rand.h"

/* Translate mbedtls result to TEE result */
static TEE_Result get_tee_result(int lmd_res)
{
	switch (lmd_res) {
	case 0:
		return TEE_SUCCESS;
	case MBEDTLS_ERR_ECP_VERIFY_FAILED:
		return TEE_ERROR_SIGNATURE_INVALID;
	case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;
	default:
		return TEE_ERROR_BAD_STATE;
	}
}

TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s,
					    size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->d = crypto_bignum_allocate(key_size_bits);
	if (!s->d)
		goto err;
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!s->x)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s,
					       size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!s->x)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

void crypto_acipher_free_ecc_public_key(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
}

/*
 * curve is part of TEE_ECC_CURVE_NIST_P192,...
 * algo is part of TEE_ALG_ECDSA_P192,..., and 0 if we do not have it
 */
static TEE_Result ecc_get_keysize(uint32_t curve, uint32_t algo,
				  size_t *key_size_bytes, size_t *key_size_bits)
{
	/*
	 * Note GPv1.1 indicates TEE_ALG_ECDH_NIST_P192_DERIVE_SHARED_SECRET
	 * but defines TEE_ALG_ECDH_P192
	 */
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*key_size_bits = 192;
		*key_size_bytes = 24;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P192) &&
		    (algo != TEE_ALG_ECDH_P192))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*key_size_bits = 224;
		*key_size_bytes = 28;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P224) &&
		    (algo != TEE_ALG_ECDH_P224))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*key_size_bits = 256;
		*key_size_bytes = 32;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P256) &&
		    (algo != TEE_ALG_ECDH_P256))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*key_size_bits = 384;
		*key_size_bytes = 48;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P384) &&
		    (algo != TEE_ALG_ECDH_P384))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*key_size_bits = 521;
		*key_size_bytes = 66;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P521) &&
		    (algo != TEE_ALG_ECDH_P521))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		*key_size_bits = 0;
		*key_size_bytes = 0;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

/*
 * Clear some memory that was used to prepare the context
 */
static void ecc_clear_precomputed(mbedtls_ecp_group *grp)
{
	size_t i = 0;

	if (grp->T) {
		for (i = 0; i < grp->T_size; i++)
			mbedtls_ecp_point_free(&grp->T[i]);
		free(grp->T);
	}
	grp->T = NULL;
	grp->T_size = 0;
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	mbedtls_ecdsa_context ecdsa;
	size_t key_size_bytes = 0;
	size_t key_size_bits = 0;

	memset(&ecdsa, 0, sizeof(ecdsa));

	res = ecc_get_keysize(key->curve, 0, &key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	mbedtls_ecdsa_init(&ecdsa);

	/* Generate the ECC key */
	lmd_res = mbedtls_ecdsa_genkey(&ecdsa, key->curve, mbd_rand, NULL);
	if (lmd_res != 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		FMSG("mbedtls_ecdsa_genkey failed.");
		goto exit;
	}
	ecc_clear_precomputed(&ecdsa.grp);

	/* check the size of the keys */
	if ((mbedtls_mpi_bitlen(&ecdsa.Q.X) > key_size_bits) ||
	    (mbedtls_mpi_bitlen(&ecdsa.Q.Y) > key_size_bits) ||
	    (mbedtls_mpi_bitlen(&ecdsa.d) > key_size_bits)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		FMSG("Check the size of the keys failed.");
		goto exit;
	}

	/* check LMD is returning z==1 */
	if (mbedtls_mpi_bitlen(&ecdsa.Q.Z) != 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		FMSG("Check LMD failed.");
		goto exit;
	}

	/* Copy the key */
	crypto_bignum_copy(key->d, (void *)&ecdsa.d);
	crypto_bignum_copy(key->x, (void *)&ecdsa.Q.X);
	crypto_bignum_copy(key->y, (void *)&ecdsa.Q.Y);

	res = TEE_SUCCESS;
exit:
	mbedtls_ecdsa_free(&ecdsa);		/* Free the temporary key */
	return res;
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	const mbedtls_pk_info_t *pk_info = NULL;
	mbedtls_ecdsa_context ecdsa;
	size_t key_size_bytes = 0;
	size_t key_size_bits = 0;
	mbedtls_mpi r;
	mbedtls_mpi s;

	memset(&ecdsa, 0, sizeof(ecdsa));
	memset(&r, 0, sizeof(r));
	memset(&s, 0, sizeof(s));

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_ecdsa_init(&ecdsa);
	lmd_res = mbedtls_ecp_group_load(&ecdsa.grp, key->curve);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ecdsa.d = *(mbedtls_mpi *)key->d;

	res = ecc_get_keysize(key->curve, algo, &key_size_bytes,
			      &key_size_bits);
	if (res != TEE_SUCCESS)
		goto out;

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA);
	if (pk_info == NULL) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	lmd_res = mbedtls_ecdsa_sign(&ecdsa.grp, &r, &s, &ecdsa.d, msg,
				     msg_len, mbd_rand, NULL);
	if (lmd_res == 0) {
		*sig_len = 2 * key_size_bytes;
		memset(sig, 0, *sig_len);
		mbedtls_mpi_write_binary(&r, sig + *sig_len / 2 -
					 mbedtls_mpi_size(&r),
					 mbedtls_mpi_size(&r));

		mbedtls_mpi_write_binary(&s, sig + *sig_len -
					 mbedtls_mpi_size(&s),
					 mbedtls_mpi_size(&s));
		res = TEE_SUCCESS;
	} else {
		FMSG("mbedtls_ecdsa_sign failed, returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_GENERIC;
	}
out:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&ecdsa.d);
	mbedtls_ecdsa_free(&ecdsa);
	return res;
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	mbedtls_ecdsa_context ecdsa;
	size_t key_size_bytes, key_size_bits = 0;
	uint8_t one[1] = { 1 };
	mbedtls_mpi r;
	mbedtls_mpi s;

	memset(&ecdsa, 0, sizeof(ecdsa));
	memset(&r, 0, sizeof(r));
	memset(&s, 0, sizeof(s));

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_ecdsa_init(&ecdsa);

	lmd_res = mbedtls_ecp_group_load(&ecdsa.grp, key->curve);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ecdsa.Q.X = *(mbedtls_mpi *)key->x;
	ecdsa.Q.Y = *(mbedtls_mpi *)key->y;
	mbedtls_mpi_read_binary(&ecdsa.Q.Z, one, sizeof(one));

	res = ecc_get_keysize(key->curve, algo,
			      &key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* check keysize vs sig_len */
	if ((key_size_bytes * 2) != sig_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	mbedtls_mpi_read_binary(&r, sig, sig_len / 2);
	mbedtls_mpi_read_binary(&s, sig + sig_len / 2, sig_len / 2);

	lmd_res = mbedtls_ecdsa_verify(&ecdsa.grp, msg, msg_len, &ecdsa.Q,
				       &r, &s);
	if (lmd_res != 0) {
		FMSG("mbedtls_ecdsa_verify failed, returned 0x%x", -lmd_res);
		res = get_tee_result(lmd_res);
	}
out:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&ecdsa.Q.X);
	mbedtls_mpi_init(&ecdsa.Q.Y);
	mbedtls_ecdsa_free(&ecdsa);
	return res;
}

TEE_Result crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
					    struct ecc_public_key *public_key,
					    void *secret,
					    unsigned long *secret_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	uint8_t one[1] = { 1 };
	mbedtls_ecdh_context ecdh;
	size_t out_len = 0;

	memset(&ecdh, 0, sizeof(ecdh));
	mbedtls_ecdh_init(&ecdh);
	lmd_res = mbedtls_ecp_group_load(&ecdh.grp, private_key->curve);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ecdh.d = *(mbedtls_mpi *)private_key->d;
	ecdh.Qp.X = *(mbedtls_mpi *)public_key->x;
	ecdh.Qp.Y = *(mbedtls_mpi *)public_key->y;
	mbedtls_mpi_read_binary(&ecdh.Qp.Z, one, sizeof(one));

	lmd_res = mbedtls_ecdh_calc_secret(&ecdh, &out_len, secret,
					   *secret_len, mbd_rand, NULL);
	if (lmd_res != 0) {
		res = get_tee_result(lmd_res);
		goto out;
	}
	*secret_len = out_len;
out:
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&ecdh.d);
	mbedtls_mpi_init(&ecdh.Qp.X);
	mbedtls_mpi_init(&ecdh.Qp.Y);
	mbedtls_ecdh_free(&ecdh);
	return res;
}
