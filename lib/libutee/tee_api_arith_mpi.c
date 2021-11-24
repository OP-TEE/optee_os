// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro limited
 */
#include <assert.h>
#include <mbedtls/bignum.h>
#include <mempool.h>
#include <stdio.h>
#include <string.h>
#include <tee_api.h>
#include <tee_arith_internal.h>
#include <utee_defines.h>
#include <utee_syscalls.h>
#include <util.h>

#define MPI_MEMPOOL_SIZE	(12 * 1024)

static void __noreturn api_panic(const char *func, int line, const char *msg)
{
	printf("Panic function %s, line %d: %s\n", func, line, msg);
	TEE_Panic(0xB16127 /*BIGINT*/);
	while (1)
		; /* Panic will crash the thread */
}

#define API_PANIC(x) api_panic(__func__, __LINE__, x)

static void __noreturn mpi_panic(const char *func, int line, int rc)
{
	printf("Panic function %s, line %d, code %d\n", func, line, rc);
	TEE_Panic(0xB16127 /*BIGINT*/);
	while (1)
		; /* Panic will crash the thread */
}

#define MPI_CHECK(x) do { \
		int _rc = (x); \
		 \
		if (_rc) \
			mpi_panic(__func__, __LINE__, _rc); \
	} while (0)

void _TEE_MathAPI_Init(void)
{
	static uint8_t data[MPI_MEMPOOL_SIZE] __aligned(MEMPOOL_ALIGN);

	mbedtls_mpi_mempool = mempool_alloc_pool(data, sizeof(data), NULL);
	if (!mbedtls_mpi_mempool)
		API_PANIC("Failed to initialize memory pool");
}

struct bigint_hdr {
	int32_t sign;
	uint16_t alloc_size;
	uint16_t nblimbs;
};

#define BIGINT_HDR_SIZE_IN_U32	2

static TEE_Result copy_mpi_to_bigint(mbedtls_mpi *mpi, TEE_BigInt *bigInt)
{
	struct bigint_hdr *hdr = (struct bigint_hdr *)bigInt;
	size_t n = mpi->n;

	/* Trim of eventual insignificant zeroes */
	while (n && !mpi->p[n - 1])
		n--;

	if (hdr->alloc_size < n)
		return TEE_ERROR_OVERFLOW;

	hdr->nblimbs = n;
	hdr->sign = mpi->s;
	memcpy(hdr + 1, mpi->p, mpi->n * sizeof(mbedtls_mpi_uint));

	return TEE_SUCCESS;
}

/*
 * Initializes a MPI.
 *
 * A temporary MPI is allocated and if a bigInt is supplied the MPI is
 * initialized with the value of the bigInt.
 */
static void get_mpi(mbedtls_mpi *mpi, const TEE_BigInt *bigInt)
{
	/*
	 * The way the GP spec is defining the bignums it's
	 * difficult/tricky to do it using 64-bit arithmetics given that
	 * we'd need 64-bit alignment of the data as well.
	 */
	COMPILE_TIME_ASSERT(sizeof(mbedtls_mpi_uint) == sizeof(uint32_t));

	/*
	 * The struct bigint_hdr is the overhead added to the bigint and
	 * is required to take exactly 2 uint32_t.
	 */
	COMPILE_TIME_ASSERT(sizeof(struct bigint_hdr) ==
			    sizeof(uint32_t) * BIGINT_HDR_SIZE_IN_U32);

	mbedtls_mpi_init_mempool(mpi);

	if (bigInt) {
		const struct bigint_hdr *hdr = (struct bigint_hdr *)bigInt;
		const mbedtls_mpi_uint *p = (const mbedtls_mpi_uint *)(hdr + 1);
		size_t n = hdr->nblimbs;

		/* Trim of eventual insignificant zeroes */
		while (n && !p[n - 1])
			n--;

		MPI_CHECK(mbedtls_mpi_grow(mpi, n));
		mpi->s = hdr->sign;
		memcpy(mpi->p, p, n * sizeof(mbedtls_mpi_uint));
	}
}

void TEE_BigIntInit(TEE_BigInt *bigInt, uint32_t len)
{
	struct bigint_hdr *hdr = (struct bigint_hdr *)bigInt;

	memset(bigInt, 0, len * sizeof(uint32_t));
	hdr->sign = 1;
	if ((len - BIGINT_HDR_SIZE_IN_U32) > MBEDTLS_MPI_MAX_LIMBS)
		API_PANIC("Too large bigint");
	hdr->alloc_size = len - BIGINT_HDR_SIZE_IN_U32;
}

TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest,
					    const uint8_t *buffer,
					    uint32_t bufferLen, int32_t sign)
{
	TEE_Result res;
	mbedtls_mpi mpi_dest;

	get_mpi(&mpi_dest, NULL);

	if (mbedtls_mpi_read_binary(&mpi_dest,  buffer, bufferLen))
		res = TEE_ERROR_OVERFLOW;
	else
		res = TEE_SUCCESS;

	if (sign < 0)
		mpi_dest.s = -1;

	if (!res)
		res = copy_mpi_to_bigint(&mpi_dest, dest);

	mbedtls_mpi_free(&mpi_dest);

	return res;
}

TEE_Result TEE_BigIntConvertToOctetString(uint8_t *buffer, uint32_t *bufferLen,
					  const TEE_BigInt *bigInt)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_mpi mpi;
	size_t sz;

	get_mpi(&mpi, bigInt);

	sz = mbedtls_mpi_size(&mpi);
	if (sz <= *bufferLen)
		MPI_CHECK(mbedtls_mpi_write_binary(&mpi, buffer, sz));
	else
		res = TEE_ERROR_SHORT_BUFFER;

	*bufferLen = sz;

	mbedtls_mpi_free(&mpi);

	return res;
}

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
	mbedtls_mpi mpi;

	get_mpi(&mpi, dest);

	MPI_CHECK(mbedtls_mpi_lset(&mpi, shortVal));

	MPI_CHECK(copy_mpi_to_bigint(&mpi, dest));
	mbedtls_mpi_free(&mpi);
}

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, const TEE_BigInt *src)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_mpi mpi;
	uint32_t v;

	get_mpi(&mpi, src);

	if (mbedtls_mpi_write_binary(&mpi, (void *)&v, sizeof(v))) {
		res = TEE_ERROR_OVERFLOW;
		goto out;
	}

	if (mpi.s > 0) {
		if (ADD_OVERFLOW(0, TEE_U32_FROM_BIG_ENDIAN(v), dest))
			res = TEE_ERROR_OVERFLOW;
	} else {
		if (SUB_OVERFLOW(0, TEE_U32_FROM_BIG_ENDIAN(v), dest))
			res = TEE_ERROR_OVERFLOW;
	}

out:
	mbedtls_mpi_free(&mpi);

	return res;
}

int32_t TEE_BigIntCmp(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
	mbedtls_mpi mpi1;
	mbedtls_mpi mpi2;
	int32_t rc;

	get_mpi(&mpi1, op1);
	get_mpi(&mpi2, op2);

	rc = mbedtls_mpi_cmp_mpi(&mpi1, &mpi2);

	mbedtls_mpi_free(&mpi1);
	mbedtls_mpi_free(&mpi2);

	return rc;
}

int32_t TEE_BigIntCmpS32(const TEE_BigInt *op, int32_t shortVal)
{
	mbedtls_mpi mpi;
	int32_t rc;

	get_mpi(&mpi, op);

	rc = mbedtls_mpi_cmp_int(&mpi, shortVal);

	mbedtls_mpi_free(&mpi);

	return rc;
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, const TEE_BigInt *op, size_t bits)
{
	mbedtls_mpi mpi_dest;
	mbedtls_mpi mpi_op;

	get_mpi(&mpi_dest, dest);

	if (dest == op) {
		MPI_CHECK(mbedtls_mpi_shift_r(&mpi_dest, bits));
		goto out;
	}

	get_mpi(&mpi_op, op);

	if (mbedtls_mpi_size(&mpi_dest) >= mbedtls_mpi_size(&mpi_op)) {
		MPI_CHECK(mbedtls_mpi_copy(&mpi_dest, &mpi_op));
		MPI_CHECK(mbedtls_mpi_shift_r(&mpi_dest, bits));
	} else {
		mbedtls_mpi mpi_t;

		get_mpi(&mpi_t, NULL);

		/*
		 * We're using a temporary buffer to avoid the corner case
		 * where destination is unexpectedly overflowed by up to
		 * @bits number of bits.
		 */
		MPI_CHECK(mbedtls_mpi_copy(&mpi_t, &mpi_op));
		MPI_CHECK(mbedtls_mpi_shift_r(&mpi_t, bits));
		MPI_CHECK(mbedtls_mpi_copy(&mpi_dest, &mpi_t));

		mbedtls_mpi_free(&mpi_t);
	}

	mbedtls_mpi_free(&mpi_op);

out:
	MPI_CHECK(copy_mpi_to_bigint(&mpi_dest, dest));
	mbedtls_mpi_free(&mpi_dest);
}

bool TEE_BigIntGetBit(const TEE_BigInt *src, uint32_t bitIndex)
{
	bool rc;
	mbedtls_mpi mpi;

	get_mpi(&mpi, src);

	rc = mbedtls_mpi_get_bit(&mpi, bitIndex);

	mbedtls_mpi_free(&mpi);

	return rc;
}

uint32_t TEE_BigIntGetBitCount(const TEE_BigInt *src)
{
	uint32_t rc;
	mbedtls_mpi mpi;

	get_mpi(&mpi, src);

	rc = mbedtls_mpi_bitlen(&mpi);

	mbedtls_mpi_free(&mpi);

	return rc;
}

static void bigint_binary(TEE_BigInt *dest, const TEE_BigInt *op1,
			  const TEE_BigInt *op2,
			  int (*func)(mbedtls_mpi *X, const mbedtls_mpi *A,
				      const mbedtls_mpi *B))
{
	mbedtls_mpi mpi_dest;
	mbedtls_mpi mpi_op1;
	mbedtls_mpi mpi_op2;
	mbedtls_mpi *pop1 = &mpi_op1;
	mbedtls_mpi *pop2 = &mpi_op2;

	get_mpi(&mpi_dest, dest);

	if (op1 == dest)
		pop1 = &mpi_dest;
	else
		get_mpi(&mpi_op1, op1);

	if (op2 == dest)
		pop2 = &mpi_dest;
	else if (op2 == op1)
		pop2 = pop1;
	else
		get_mpi(&mpi_op2, op2);

	MPI_CHECK(func(&mpi_dest, pop1, pop2));

	MPI_CHECK(copy_mpi_to_bigint(&mpi_dest, dest));
	mbedtls_mpi_free(&mpi_dest);
	if (pop1 == &mpi_op1)
		mbedtls_mpi_free(&mpi_op1);
	if (pop2 == &mpi_op2)
		mbedtls_mpi_free(&mpi_op2);
}

static void bigint_binary_mod(TEE_BigInt *dest, const TEE_BigInt *op1,
			      const TEE_BigInt *op2, const TEE_BigInt *n,
			      int (*func)(mbedtls_mpi *X, const mbedtls_mpi *A,
					  const mbedtls_mpi *B))
{
	mbedtls_mpi mpi_dest;
	mbedtls_mpi mpi_op1;
	mbedtls_mpi mpi_op2;
	mbedtls_mpi mpi_n;
	mbedtls_mpi *pop1 = &mpi_op1;
	mbedtls_mpi *pop2 = &mpi_op2;
	mbedtls_mpi mpi_t;

	if (TEE_BigIntCmpS32(n, 2) < 0)
		API_PANIC("Modulus is too short");

	get_mpi(&mpi_dest, dest);
	get_mpi(&mpi_n, n);

	if (op1 == dest)
		pop1 = &mpi_dest;
	else
		get_mpi(&mpi_op1, op1);

	if (op2 == dest)
		pop2 = &mpi_dest;
	else if (op2 == op1)
		pop2 = pop1;
	else
		get_mpi(&mpi_op2, op2);

	get_mpi(&mpi_t, NULL);

	MPI_CHECK(func(&mpi_t, pop1, pop2));
	MPI_CHECK(mbedtls_mpi_mod_mpi(&mpi_dest, &mpi_t, &mpi_n));

	MPI_CHECK(copy_mpi_to_bigint(&mpi_dest, dest));
	mbedtls_mpi_free(&mpi_dest);
	if (pop1 == &mpi_op1)
		mbedtls_mpi_free(&mpi_op1);
	if (pop2 == &mpi_op2)
		mbedtls_mpi_free(&mpi_op2);
	mbedtls_mpi_free(&mpi_t);
	mbedtls_mpi_free(&mpi_n);
}

void TEE_BigIntAdd(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	bigint_binary(dest, op1, op2, mbedtls_mpi_add_mpi);
}

void TEE_BigIntSub(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	bigint_binary(dest, op1, op2, mbedtls_mpi_sub_mpi);
}

void TEE_BigIntNeg(TEE_BigInt *dest, const TEE_BigInt *src)
{
	mbedtls_mpi mpi_dest;

	get_mpi(&mpi_dest, dest);

	if (dest != src) {
		mbedtls_mpi mpi_src;

		get_mpi(&mpi_src, src);

		MPI_CHECK(mbedtls_mpi_copy(&mpi_dest, &mpi_src));

		mbedtls_mpi_free(&mpi_src);
	}

	mpi_dest.s *= -1;

	MPI_CHECK(copy_mpi_to_bigint(&mpi_dest, dest));
	mbedtls_mpi_free(&mpi_dest);
}

void TEE_BigIntMul(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2)
{
	size_t bs1 = TEE_BigIntGetBitCount(op1);
	size_t bs2 = TEE_BigIntGetBitCount(op2);
	size_t s = TEE_BigIntSizeInU32(bs1) + TEE_BigIntSizeInU32(bs2);
	TEE_BigInt zero[TEE_BigIntSizeInU32(1)] = { 0 };
	TEE_BigInt *tmp = NULL;

	tmp = mempool_alloc(mbedtls_mpi_mempool, sizeof(uint32_t) * s);
	if (!tmp)
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	TEE_BigIntInit(tmp, s);
	TEE_BigIntInit(zero, TEE_BigIntSizeInU32(1));

	bigint_binary(tmp, op1, op2, mbedtls_mpi_mul_mpi);

	TEE_BigIntAdd(dest, tmp, zero);

	mempool_free(mbedtls_mpi_mempool, tmp);
}

void TEE_BigIntSquare(TEE_BigInt *dest, const TEE_BigInt *op)
{
	TEE_BigIntMul(dest, op, op);
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   const TEE_BigInt *op1, const TEE_BigInt *op2)
{
	mbedtls_mpi mpi_dest_q;
	mbedtls_mpi mpi_dest_r;
	mbedtls_mpi mpi_op1;
	mbedtls_mpi mpi_op2;
	mbedtls_mpi *pop1 = &mpi_op1;
	mbedtls_mpi *pop2 = &mpi_op2;

	get_mpi(&mpi_dest_q, dest_q);
	get_mpi(&mpi_dest_r, dest_r);

	if (op1 == dest_q)
		pop1 = &mpi_dest_q;
	else if (op1 == dest_r)
		pop1 = &mpi_dest_r;
	else
		get_mpi(&mpi_op1, op1);

	if (op2 == dest_q)
		pop2 = &mpi_dest_q;
	else if (op2 == dest_r)
		pop2 = &mpi_dest_r;
	else if (op2 == op1)
		pop2 = pop1;
	else
		get_mpi(&mpi_op2, op2);

	MPI_CHECK(mbedtls_mpi_div_mpi(&mpi_dest_q, &mpi_dest_r, pop1, pop2));

	if (dest_q)
		MPI_CHECK(copy_mpi_to_bigint(&mpi_dest_q, dest_q));
	if (dest_r)
		MPI_CHECK(copy_mpi_to_bigint(&mpi_dest_r, dest_r));
	mbedtls_mpi_free(&mpi_dest_q);
	mbedtls_mpi_free(&mpi_dest_r);
	if (pop1 == &mpi_op1)
		mbedtls_mpi_free(&mpi_op1);
	if (pop2 == &mpi_op2)
		mbedtls_mpi_free(&mpi_op2);
}

void TEE_BigIntMod(TEE_BigInt *dest, const TEE_BigInt *op, const TEE_BigInt *n)
{
	if (TEE_BigIntCmpS32(n, 2) < 0)
		API_PANIC("Modulus is too short");

	bigint_binary(dest, op, n, mbedtls_mpi_mod_mpi);
}

void TEE_BigIntAddMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	bigint_binary_mod(dest, op1, op2, n, mbedtls_mpi_add_mpi);
}

void TEE_BigIntSubMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	bigint_binary_mod(dest, op1, op2, n, mbedtls_mpi_sub_mpi);
}

void TEE_BigIntMulMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n)
{
	bigint_binary_mod(dest, op1, op2, n, mbedtls_mpi_mul_mpi);
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, const TEE_BigInt *op,
			 const TEE_BigInt *n)
{
	TEE_BigIntMulMod(dest, op, op, n);
}

void TEE_BigIntInvMod(TEE_BigInt *dest, const TEE_BigInt *op,
		      const TEE_BigInt *n)
{
	mbedtls_mpi mpi_dest;
	mbedtls_mpi mpi_op;
	mbedtls_mpi mpi_n;
	mbedtls_mpi *pop = &mpi_op;

	if (TEE_BigIntCmpS32(n, 2) < 0 || TEE_BigIntCmpS32(op, 0) == 0)
		API_PANIC("too small modulus or trying to invert zero");

	get_mpi(&mpi_dest, dest);
	get_mpi(&mpi_n, n);

	if (op == dest)
		pop = &mpi_dest;
	else
		get_mpi(&mpi_op, op);

	MPI_CHECK(mbedtls_mpi_inv_mod(&mpi_dest, pop, &mpi_n));

	MPI_CHECK(copy_mpi_to_bigint(&mpi_dest, dest));
	mbedtls_mpi_free(&mpi_dest);
	mbedtls_mpi_free(&mpi_n);
	if (pop == &mpi_op)
		mbedtls_mpi_free(&mpi_op);
}

bool TEE_BigIntRelativePrime(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
	bool rc;
	mbedtls_mpi mpi_op1;
	mbedtls_mpi mpi_op2;
	mbedtls_mpi *pop2 = &mpi_op2;
	mbedtls_mpi gcd;

	get_mpi(&mpi_op1, op1);

	if (op2 == op1)
		pop2 = &mpi_op1;
	else
		get_mpi(&mpi_op2, op2);

	get_mpi(&gcd, NULL);

	MPI_CHECK(mbedtls_mpi_gcd(&gcd, &mpi_op1, &mpi_op2));

	rc = !mbedtls_mpi_cmp_int(&gcd, 1);

	mbedtls_mpi_free(&gcd);
	mbedtls_mpi_free(&mpi_op1);
	if (pop2 == &mpi_op2)
		mbedtls_mpi_free(&mpi_op2);

	return rc;
}

static bool mpi_is_odd(mbedtls_mpi *x)
{
	return mbedtls_mpi_get_bit(x, 0);
}

static bool mpi_is_even(mbedtls_mpi *x)
{
	return !mpi_is_odd(x);
}

/*
 * Based on libmpa implementation __mpa_egcd(), modified to work with MPI
 * instead.
 */
static void mpi_egcd(mbedtls_mpi *gcd, mbedtls_mpi *a, mbedtls_mpi *b,
		     mbedtls_mpi *x_in, mbedtls_mpi *y_in)
{
	mbedtls_mpi_uint k;
	mbedtls_mpi A;
	mbedtls_mpi B;
	mbedtls_mpi C;
	mbedtls_mpi D;
	mbedtls_mpi x;
	mbedtls_mpi y;
	mbedtls_mpi u;

	get_mpi(&A, NULL);
	get_mpi(&B, NULL);
	get_mpi(&C, NULL);
	get_mpi(&D, NULL);
	get_mpi(&x, NULL);
	get_mpi(&y, NULL);
	get_mpi(&u, NULL);

	/* have y < x from assumption */
	if (!mbedtls_mpi_cmp_int(y_in, 0)) {
		MPI_CHECK(mbedtls_mpi_lset(a, 1));
		MPI_CHECK(mbedtls_mpi_lset(b, 0));
		MPI_CHECK(mbedtls_mpi_copy(gcd, x_in));
		goto out;
	}

	MPI_CHECK(mbedtls_mpi_copy(&x, x_in));
	MPI_CHECK(mbedtls_mpi_copy(&y, y_in));

	k = 0;
	while (mpi_is_even(&x) && mpi_is_even(&y)) {
		k++;
		MPI_CHECK(mbedtls_mpi_shift_r(&x, 1));
		MPI_CHECK(mbedtls_mpi_shift_r(&y, 1));
	}

	MPI_CHECK(mbedtls_mpi_copy(&u, &x));
	MPI_CHECK(mbedtls_mpi_copy(gcd, &y));
	MPI_CHECK(mbedtls_mpi_lset(&A, 1));
	MPI_CHECK(mbedtls_mpi_lset(&B, 0));
	MPI_CHECK(mbedtls_mpi_lset(&C, 0));
	MPI_CHECK(mbedtls_mpi_lset(&D, 1));

	while (mbedtls_mpi_cmp_int(&u, 0)) {
		while (mpi_is_even(&u)) {
			MPI_CHECK(mbedtls_mpi_shift_r(&u, 1));
			if (mpi_is_odd(&A) || mpi_is_odd(&B)) {
				MPI_CHECK(mbedtls_mpi_add_mpi(&A, &A, &y));
				MPI_CHECK(mbedtls_mpi_sub_mpi(&B, &B, &x));
			}
			MPI_CHECK(mbedtls_mpi_shift_r(&A, 1));
			MPI_CHECK(mbedtls_mpi_shift_r(&B, 1));
		}

		while (mpi_is_even(gcd)) {
			MPI_CHECK(mbedtls_mpi_shift_r(gcd, 1));
			if (mpi_is_odd(&C) || mpi_is_odd(&D)) {
				MPI_CHECK(mbedtls_mpi_add_mpi(&C, &C, &y));
				MPI_CHECK(mbedtls_mpi_sub_mpi(&D, &D, &x));
			}
			MPI_CHECK(mbedtls_mpi_shift_r(&C, 1));
			MPI_CHECK(mbedtls_mpi_shift_r(&D, 1));

		}

		if (mbedtls_mpi_cmp_mpi(&u, gcd) >= 0) {
			MPI_CHECK(mbedtls_mpi_sub_mpi(&u, &u, gcd));
			MPI_CHECK(mbedtls_mpi_sub_mpi(&A, &A, &C));
			MPI_CHECK(mbedtls_mpi_sub_mpi(&B, &B, &D));
		} else {
			MPI_CHECK(mbedtls_mpi_sub_mpi(gcd, gcd, &u));
			MPI_CHECK(mbedtls_mpi_sub_mpi(&C, &C, &A));
			MPI_CHECK(mbedtls_mpi_sub_mpi(&D, &D, &B));
		}
	}

	MPI_CHECK(mbedtls_mpi_copy(a, &C));
	MPI_CHECK(mbedtls_mpi_copy(b, &D));
	MPI_CHECK(mbedtls_mpi_shift_l(gcd, k));

out:
	mbedtls_mpi_free(&A);
	mbedtls_mpi_free(&B);
	mbedtls_mpi_free(&C);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&x);
	mbedtls_mpi_free(&y);
	mbedtls_mpi_free(&u);
}

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
				  TEE_BigInt *v, const TEE_BigInt *op1,
				  const TEE_BigInt *op2)
{
	mbedtls_mpi mpi_gcd_res;
	mbedtls_mpi mpi_op1;
	mbedtls_mpi mpi_op2;
	mbedtls_mpi *pop2 = &mpi_op2;

	get_mpi(&mpi_gcd_res, gcd);
	get_mpi(&mpi_op1, op1);

	if (op2 == op1)
		pop2 = &mpi_op1;
	else
		get_mpi(&mpi_op2, op2);

	if (!u && !v) {
		MPI_CHECK(mbedtls_mpi_gcd(&mpi_gcd_res, &mpi_op1, pop2));
	} else {
		mbedtls_mpi mpi_u;
		mbedtls_mpi mpi_v;
		int8_t s1 = mpi_op1.s;
		int8_t s2 = pop2->s;
		int cmp;

		mpi_op1.s = 1;
		pop2->s = 1;

		get_mpi(&mpi_u, u);
		get_mpi(&mpi_v, v);

		cmp = mbedtls_mpi_cmp_abs(&mpi_op1, pop2);
		if (cmp == 0) {
			MPI_CHECK(mbedtls_mpi_copy(&mpi_gcd_res, &mpi_op1));
			MPI_CHECK(mbedtls_mpi_lset(&mpi_u, 1));
			MPI_CHECK(mbedtls_mpi_lset(&mpi_v, 0));
		} else if (cmp > 0) {
			mpi_egcd(&mpi_gcd_res, &mpi_u, &mpi_v, &mpi_op1, pop2);
		} else {
			mpi_egcd(&mpi_gcd_res, &mpi_v, &mpi_u, pop2, &mpi_op1);
		}

		mpi_u.s *= s1;
		mpi_v.s *= s2;

		MPI_CHECK(copy_mpi_to_bigint(&mpi_u, u));
		MPI_CHECK(copy_mpi_to_bigint(&mpi_v, v));
		mbedtls_mpi_free(&mpi_u);
		mbedtls_mpi_free(&mpi_v);
	}

	MPI_CHECK(copy_mpi_to_bigint(&mpi_gcd_res, gcd));
	mbedtls_mpi_free(&mpi_gcd_res);
	mbedtls_mpi_free(&mpi_op1);
	if (pop2 == &mpi_op2)
		mbedtls_mpi_free(&mpi_op2);
}

static int rng_read(void *ignored __unused, unsigned char *buf, size_t blen)
{
	if (_utee_cryp_random_number_generate(buf, blen))
		return MBEDTLS_ERR_MPI_FILE_IO_ERROR;
	return 0;
}

int32_t TEE_BigIntIsProbablePrime(const TEE_BigInt *op,
				  uint32_t confidenceLevel __unused)
{
	int rc;
	mbedtls_mpi mpi_op;

	get_mpi(&mpi_op, op);

	rc = mbedtls_mpi_is_prime(&mpi_op, rng_read, NULL);

	mbedtls_mpi_free(&mpi_op);

	if (rc)
		return 0;

	return 1;
}

/*
 * Not so fast FMM implementation based on the normal big int functions.
 *
 * Note that these functions (along with all the other functions in this
 * file) only are used directly by the TA doing bigint arithmetics on its
 * own. Performance of RSA operations in TEE Internal API are not affected
 * by this.
 */
void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, uint32_t len)
{
	TEE_BigIntInit(bigIntFMM, len);
}

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context __unused,
			      uint32_t len __unused,
			      const TEE_BigInt *modulus __unused)
{
}

uint32_t TEE_BigIntFMMSizeInU32(uint32_t modulusSizeInBits)
{
	return TEE_BigIntSizeInU32(modulusSizeInBits);
}

uint32_t TEE_BigIntFMMContextSizeInU32(uint32_t modulusSizeInBits __unused)
{
	/* Return something larger than 0 to keep malloc() and friends happy */
	return 1;
}

void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, const TEE_BigInt *src,
			    const TEE_BigInt *n,
			    const TEE_BigIntFMMContext *context __unused)
{
	TEE_BigIntMod(dest, src, n);
}

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, const TEE_BigIntFMM *src,
			      const TEE_BigInt *n __unused,
			      const TEE_BigIntFMMContext *context __unused)
{
	mbedtls_mpi mpi_dst;
	mbedtls_mpi mpi_src;

	get_mpi(&mpi_dst, dest);
	get_mpi(&mpi_src, src);

	MPI_CHECK(mbedtls_mpi_copy(&mpi_dst, &mpi_src));

	MPI_CHECK(copy_mpi_to_bigint(&mpi_dst, dest));
	mbedtls_mpi_free(&mpi_dst);
	mbedtls_mpi_free(&mpi_src);
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, const TEE_BigIntFMM *op1,
			  const TEE_BigIntFMM *op2, const TEE_BigInt *n,
			  const TEE_BigIntFMMContext *context __unused)
{
	mbedtls_mpi mpi_dst;
	mbedtls_mpi mpi_op1;
	mbedtls_mpi mpi_op2;
	mbedtls_mpi mpi_n;
	mbedtls_mpi mpi_t;

	get_mpi(&mpi_dst, dest);
	get_mpi(&mpi_op1, op1);
	get_mpi(&mpi_op2, op2);
	get_mpi(&mpi_n, n);
	get_mpi(&mpi_t, NULL);

	MPI_CHECK(mbedtls_mpi_mul_mpi(&mpi_t, &mpi_op1, &mpi_op2));
	MPI_CHECK(mbedtls_mpi_mod_mpi(&mpi_dst, &mpi_t, &mpi_n));

	mbedtls_mpi_free(&mpi_t);
	mbedtls_mpi_free(&mpi_n);
	mbedtls_mpi_free(&mpi_op2);
	mbedtls_mpi_free(&mpi_op1);
	MPI_CHECK(copy_mpi_to_bigint(&mpi_dst, dest));
	mbedtls_mpi_free(&mpi_dst);
}
