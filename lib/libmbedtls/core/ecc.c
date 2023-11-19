// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto_impl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <stdlib.h>
#include <string.h>

#include "mbed_helpers.h"
#include "sm2-dsa.h"
#include "sm2-pke.h"

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

static void ecc_free_public_key(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(&s->x);
	crypto_bignum_free(&s->y);
}

static TEE_Result ecc_get_keysize(uint32_t curve, uint32_t algo,
				  size_t *key_size_bytes, size_t *key_size_bits)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*key_size_bits = 192;
		*key_size_bytes = 24;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*key_size_bits = 224;
		*key_size_bytes = 28;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*key_size_bits = 256;
		*key_size_bytes = 32;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*key_size_bits = 384;
		*key_size_bytes = 48;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*key_size_bits = 521;
		*key_size_bytes = 66;
		break;
	case TEE_ECC_CURVE_SM2:
		*key_size_bits = 256;
		*key_size_bytes = 32;
		if (algo != 0 && algo != TEE_ALG_SM2_DSA_SM3 &&
		    algo != TEE_ALG_SM2_KEP && algo != TEE_ALG_SM2_PKE)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		*key_size_bits = 0;
		*key_size_bytes = 0;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static mbedtls_ecp_group_id curve_to_group_id(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		return MBEDTLS_ECP_DP_SECP192R1;
	case TEE_ECC_CURVE_NIST_P224:
		return MBEDTLS_ECP_DP_SECP224R1;
	case TEE_ECC_CURVE_NIST_P256:
		return MBEDTLS_ECP_DP_SECP256R1;
	case TEE_ECC_CURVE_NIST_P384:
		return MBEDTLS_ECP_DP_SECP384R1;
	case TEE_ECC_CURVE_NIST_P521:
		return MBEDTLS_ECP_DP_SECP521R1;
	case TEE_ECC_CURVE_SM2:
		return MBEDTLS_ECP_DP_SM2;
	default:
		return MBEDTLS_ECP_DP_NONE;
	}
}

static TEE_Result ecc_generate_keypair(struct ecc_keypair *key, size_t key_size)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	mbedtls_ecdsa_context ecdsa;
	mbedtls_ecp_group_id gid;
	size_t key_size_bytes = 0;
	size_t key_size_bits = 0;

	memset(&ecdsa, 0, sizeof(ecdsa));
	memset(&gid, 0, sizeof(gid));

	res = ecc_get_keysize(key->curve, 0, &key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	if (key_size != key_size_bits)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_ecdsa_init(&ecdsa);

	/* Generate the ECC key */
	gid = curve_to_group_id(key->curve);
	lmd_res = mbedtls_ecdsa_genkey(&ecdsa, gid, mbd_rand, NULL);
	if (lmd_res != 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		FMSG("mbedtls_ecdsa_genkey failed.");
		goto exit;
	}

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

static TEE_Result ecc_sign(uint32_t algo, struct ecc_keypair *key,
			   const uint8_t *msg, size_t msg_len, uint8_t *sig,
			   size_t *sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	const mbedtls_pk_info_t *pk_info = NULL;
	mbedtls_ecdsa_context ecdsa;
	mbedtls_ecp_group_id gid;
	size_t key_size_bytes = 0;
	size_t key_size_bits = 0;
	mbedtls_mpi r;
	mbedtls_mpi s;

	memset(&ecdsa, 0, sizeof(ecdsa));
	memset(&gid, 0, sizeof(gid));
	memset(&r, 0, sizeof(r));
	memset(&s, 0, sizeof(s));

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_ecdsa_init(&ecdsa);

	gid = curve_to_group_id(key->curve);
	lmd_res = mbedtls_ecp_group_load(&ecdsa.grp, gid);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ecdsa.d = *(mbedtls_mpi *)key->d;

	res = ecc_get_keysize(key->curve, algo, &key_size_bytes,
			      &key_size_bits);
	if (res != TEE_SUCCESS)
		goto out;

	if (*sig_len < 2 * key_size_bytes) {
		*sig_len = 2 * key_size_bytes;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

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
		FMSG("mbedtls_ecdsa_sign failed, returned 0x%x", -lmd_res);
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

static TEE_Result ecc_verify(uint32_t algo, struct ecc_public_key *key,
			     const uint8_t *msg, size_t msg_len,
			     const uint8_t *sig, size_t sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	mbedtls_ecdsa_context ecdsa;
	mbedtls_ecp_group_id gid;
	size_t key_size_bytes, key_size_bits = 0;
	uint8_t one[1] = { 1 };
	mbedtls_mpi r;
	mbedtls_mpi s;

	memset(&ecdsa, 0, sizeof(ecdsa));
	memset(&gid, 0, sizeof(gid));
	memset(&r, 0, sizeof(r));
	memset(&s, 0, sizeof(s));

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_ecdsa_init(&ecdsa);

	gid = curve_to_group_id(key->curve);
	lmd_res = mbedtls_ecp_group_load(&ecdsa.grp, gid);
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

static TEE_Result ecc_shared_secret(struct ecc_keypair *private_key,
				    struct ecc_public_key *public_key,
				    void *secret, unsigned long *secret_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	uint8_t one[1] = { 1 };
	mbedtls_ecdh_context ecdh;
	mbedtls_ecp_group_id gid;
	size_t out_len = 0;

	memset(&ecdh, 0, sizeof(ecdh));
	memset(&gid, 0, sizeof(gid));
	mbedtls_ecdh_init(&ecdh);
	gid = curve_to_group_id(private_key->curve);
	lmd_res = mbedtls_ecdh_setup(&ecdh, gid);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	assert(ecdh.var == MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0);
	ecdh.ctx.mbed_ecdh.d = *(mbedtls_mpi *)private_key->d;
	ecdh.ctx.mbed_ecdh.Qp.X = *(mbedtls_mpi *)public_key->x;
	ecdh.ctx.mbed_ecdh.Qp.Y = *(mbedtls_mpi *)public_key->y;
	mbedtls_mpi_read_binary(&ecdh.ctx.mbed_ecdh.Qp.Z, one, sizeof(one));

	lmd_res = mbedtls_ecdh_calc_secret(&ecdh, &out_len, secret,
					   *secret_len, mbd_rand, NULL);
	if (lmd_res != 0) {
		res = get_tee_result(lmd_res);
		goto out;
	}
	*secret_len = out_len;
out:
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&ecdh.ctx.mbed_ecdh.d);
	mbedtls_mpi_init(&ecdh.ctx.mbed_ecdh.Qp.X);
	mbedtls_mpi_init(&ecdh.ctx.mbed_ecdh.Qp.Y);
	mbedtls_ecdh_free(&ecdh);
	return res;
}

static const struct crypto_ecc_keypair_ops ecc_keypair_ops = {
	.generate = ecc_generate_keypair,
	.sign = ecc_sign,
	.shared_secret = ecc_shared_secret,
};

static const struct crypto_ecc_keypair_ops sm2_pke_keypair_ops = {
	.generate = ecc_generate_keypair,
	.decrypt = sm2_mbedtls_pke_decrypt,
};

static const struct crypto_ecc_keypair_ops sm2_kep_keypair_ops = {
	.generate = ecc_generate_keypair,
};

static const struct crypto_ecc_keypair_ops sm2_dsa_keypair_ops = {
	.generate = ecc_generate_keypair,
	.sign = sm2_mbedtls_dsa_sign,
};

const struct crypto_ecc_keypair_ops *
crypto_asym_get_ecc_keypair_ops(uint32_t key_type)
{
	switch (key_type) {
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
		return &ecc_keypair_ops;
	case TEE_TYPE_SM2_DSA_KEYPAIR:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_DSA))
			return NULL;
		return &sm2_dsa_keypair_ops;
	case TEE_TYPE_SM2_PKE_KEYPAIR:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_PKE))
			return NULL;
		return &sm2_pke_keypair_ops;
	case TEE_TYPE_SM2_KEP_KEYPAIR:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_KEP))
			return NULL;
		return &sm2_kep_keypair_ops;
	default:
		return NULL;
	}
}

TEE_Result crypto_asym_alloc_ecc_keypair(struct ecc_keypair *s,
					 uint32_t key_type,
					 size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));

	switch (key_type) {
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
		s->ops = &ecc_keypair_ops;
		break;
	case TEE_TYPE_SM2_DSA_KEYPAIR:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_DSA))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->curve = TEE_ECC_CURVE_SM2;
		s->ops = &sm2_dsa_keypair_ops;
		break;
	case TEE_TYPE_SM2_PKE_KEYPAIR:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_PKE))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->curve = TEE_ECC_CURVE_SM2;
		s->ops = &sm2_pke_keypair_ops;
		break;
	case TEE_TYPE_SM2_KEP_KEYPAIR:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_KEP))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->curve = TEE_ECC_CURVE_SM2;
		s->ops = &sm2_kep_keypair_ops;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

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
	crypto_bignum_free(&s->d);
	crypto_bignum_free(&s->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static const struct crypto_ecc_public_ops ecc_public_key_ops = {
	.free = ecc_free_public_key,
	.verify = ecc_verify,
};

static const struct crypto_ecc_public_ops sm2_pke_public_key_ops = {
	.free = ecc_free_public_key,
	.encrypt = sm2_mbedtls_pke_encrypt,
};

static const struct crypto_ecc_public_ops sm2_kep_public_key_ops = {
	.free = ecc_free_public_key,
};

static const struct crypto_ecc_public_ops sm2_dsa_public_key_ops = {
	.free = ecc_free_public_key,
	.verify = sm2_mbedtls_dsa_verify,
};

const struct crypto_ecc_public_ops*
crypto_asym_get_ecc_public_ops(uint32_t key_type)
{
	switch (key_type) {
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
		return &ecc_public_key_ops;
	case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_DSA))
			return NULL;

		return &sm2_dsa_public_key_ops;
	case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_PKE))
			return NULL;

		return &sm2_pke_public_key_ops;
	case TEE_TYPE_SM2_KEP_PUBLIC_KEY:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_KEP))
			return NULL;
		return &sm2_kep_public_key_ops;
	default:
		return NULL;
	}
}

TEE_Result crypto_asym_alloc_ecc_public_key(struct ecc_public_key *s,
					    uint32_t key_type,
					    size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));

	switch (key_type) {
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
		s->ops = &ecc_public_key_ops;
		break;
	case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_DSA))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->curve = TEE_ECC_CURVE_SM2;
		s->ops = &sm2_dsa_public_key_ops;
		break;
	case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_PKE))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->curve = TEE_ECC_CURVE_SM2;
		s->ops = &sm2_pke_public_key_ops;
		break;
	case TEE_TYPE_SM2_KEP_PUBLIC_KEY:
		if (!IS_ENABLED(CFG_CRYPTO_SM2_KEP))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->curve = TEE_ECC_CURVE_SM2;
		s->ops = &sm2_kep_public_key_ops;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	s->x = crypto_bignum_allocate(key_size_bits);
	if (!s->x)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
		goto err;

	return TEE_SUCCESS;

err:
	crypto_bignum_free(&s->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}
