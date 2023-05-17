// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/dhm.h>
#include <stdlib.h>
#include <string.h>

#include "mbed_helpers.h"

TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s,
					   size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->g = crypto_bignum_allocate(key_size_bits);
	if (!s->g)
		goto err;
	s->p = crypto_bignum_allocate(key_size_bits);
	if (!s->p)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
		goto err;
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!s->x)
		goto err;
	s->q = crypto_bignum_allocate(key_size_bits);
	if (!s->q)
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(&s->g);
	crypto_bignum_free(&s->p);
	crypto_bignum_free(&s->y);
	crypto_bignum_free(&s->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key,
				     struct bignum *q __unused,
				     size_t xbits, size_t key_size)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	mbedtls_dhm_context dhm;
	unsigned char *buf = NULL;
	size_t xbytes = 0;
	size_t len = 0;

	memset(&dhm, 0, sizeof(dhm));
	mbedtls_dhm_init(&dhm);

	dhm.G = *(mbedtls_mpi *)key->g;
	dhm.P = *(mbedtls_mpi *)key->p;

	len = mbedtls_dhm_get_len(&dhm);
	if (key_size != 8 * len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (xbits == 0)
		xbytes = len;
	else
		xbytes = xbits / 8;

	buf = malloc(len);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	lmd_res = mbedtls_dhm_make_public(&dhm, (int)xbytes, buf,
					  len, mbd_rand, NULL);
	if (lmd_res != 0) {
		FMSG("mbedtls_dhm_make_public err, return is 0x%x", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		crypto_bignum_bin2bn(buf, xbytes, key->y);
		crypto_bignum_copy(key->x, (void *)&dhm.X);
		res = TEE_SUCCESS;
	}
out:
	free(buf);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&dhm.G);
	mbedtls_mpi_init(&dhm.P);
	mbedtls_dhm_free(&dhm);
	return res;
}

TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *public_key,
					   struct bignum *secret)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	mbedtls_dhm_context dhm;
	unsigned char *buf = NULL;
	size_t olen = 0;
	size_t len = 0;

	memset(&dhm, 0, sizeof(dhm));
	mbedtls_dhm_init(&dhm);

	dhm.G = *(mbedtls_mpi *)private_key->g;
	dhm.P = *(mbedtls_mpi *)private_key->p;
	dhm.GX = *(mbedtls_mpi *)private_key->y;
	dhm.X = *(mbedtls_mpi *)private_key->x;
	dhm.GY = *(mbedtls_mpi *)public_key;

	len = mbedtls_dhm_get_len(&dhm);

	buf = malloc(len);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	lmd_res = mbedtls_dhm_calc_secret(&dhm, buf, len,
					  &olen, mbd_rand, NULL);
	if (lmd_res != 0) {
		FMSG("mbedtls_dhm_calc_secret failed, ret is 0x%x", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		crypto_bignum_bin2bn(buf, olen, secret);
		res = TEE_SUCCESS;
	}
out:
	free(buf);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&dhm.G);
	mbedtls_mpi_init(&dhm.P);
	mbedtls_mpi_init(&dhm.GX);
	mbedtls_mpi_init(&dhm.X);
	mbedtls_mpi_init(&dhm.GY);
	mbedtls_dhm_free(&dhm);
	return res;
}
