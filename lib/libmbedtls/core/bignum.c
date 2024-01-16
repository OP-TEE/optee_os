// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <mbedtls/bignum.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#define ciL		(sizeof(mbedtls_mpi_uint))	/* chars in limb  */
#define biL		(ciL << 3)			/* bits  in limb  */
#define BITS_TO_LIMBS(i) ((i) / biL + ((i) % biL != 0))

size_t crypto_bignum_num_bytes(struct bignum *a)
{
	assert(a != NULL);
	return mbedtls_mpi_size((const mbedtls_mpi *)a);
}

size_t crypto_bignum_num_bits(struct bignum *a)
{
	assert(a != NULL);
	return mbedtls_mpi_bitlen((const mbedtls_mpi *)a);
}

int32_t crypto_bignum_compare(struct bignum *a, struct bignum *b)
{
	int ret = 0;

	assert(a != NULL);
	assert(b != NULL);
	ret = mbedtls_mpi_cmp_mpi((const mbedtls_mpi *)a,
				  (const mbedtls_mpi *)b);
	return CMP_TRILEAN(ret, 0);
}

void crypto_bignum_bn2bin(const struct bignum *from, uint8_t *to)
{
	size_t len = 0;

	assert(from != NULL);
	assert(to != NULL);
	len = crypto_bignum_num_bytes((struct bignum *)from);
	if (mbedtls_mpi_write_binary((mbedtls_mpi *)from, to, len))
		panic();
}

TEE_Result crypto_bignum_bin2bn(const uint8_t *from, size_t fromsize,
			 struct bignum *to)
{
	assert(from != NULL);
	assert(to != NULL);
	if (mbedtls_mpi_read_binary((mbedtls_mpi *)to, from, fromsize))
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

void crypto_bignum_copy(struct bignum *to, const struct bignum *from)
{
	assert(from != NULL);
	assert(to != NULL);
	if (mbedtls_mpi_copy((mbedtls_mpi *)to, (const mbedtls_mpi *)from))
		panic();
}

struct bignum *crypto_bignum_allocate(size_t size_bits)
{
	mbedtls_mpi *bn = NULL;

	if (size_bits > CFG_CORE_BIGNUM_MAX_BITS)
		size_bits = CFG_CORE_BIGNUM_MAX_BITS;

	bn = calloc(1, sizeof(mbedtls_mpi));
	if (!bn)
		return NULL;
	mbedtls_mpi_init(bn);
	if (mbedtls_mpi_grow(bn, BITS_TO_LIMBS(size_bits)) != 0) {
		free(bn);
		return NULL;
	}

	return (struct bignum *)bn;
}

void crypto_bignum_free(struct bignum **s)
{
	assert(s);

	mbedtls_mpi_free((mbedtls_mpi *)*s);
	free(*s);
	*s = NULL;
}

void crypto_bignum_clear(struct bignum *s)
{
	mbedtls_mpi *bn = (mbedtls_mpi *)s;

	memset(bn->p, 0, mbedtls_mpi_size((const mbedtls_mpi *)bn));
}
