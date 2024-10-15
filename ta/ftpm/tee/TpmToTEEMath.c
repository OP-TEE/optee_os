// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Siemens AG
 * All rights reserved.
 * Copyright (c) 2024, Linaro Limited
 */

#include "Tpm.h"

#ifdef MATH_LIB_TEE

#include <tee_internal_api.h>

#include <stdio.h>
static void __maybe_unused printf_bigint(const TEE_BigInt *bigint)
{
	size_t buffer_len = 1024;
	uint8_t buffer[buffer_len];
	if (TEE_BigIntConvertToOctetString(buffer, &buffer_len, bigint) ==
	    TEE_SUCCESS) {
		if (buffer_len != 0) {
			for (size_t k = 0; k < buffer_len; ++k) {
				printf("%.2x", buffer[k]);
			}
		} else {
			printf("0");
		}
	} else {
		printf("ERROR!\n");
	}
}

/*
 * The internal representation of big integers in the TEE is implementation
 * defined. If we used the fact that we know how OP-TEE represents big integers
 * internally, then we could directly convert between the TPM representation
 * and the TEE representation rather than go through representation as a byte
 * string.
 */

/*
 * Return the size of a bigNum in bytes (rounded up to the nearest multiple
 * of sizeof(crypt_uword_t)).
 */
static NUMBYTES bn_size_in_bytes(bigConst a)
{
	return sizeof(crypt_uword_t) * BnGetSize(a);
}

/*
 * Return the size of a bigNum in bytes (rounded up to the nearest multiple
 * of sizeof(crypt_uword_t) * 8).
 */
static NUMBYTES bn_size_in_bits(bigConst a)
{
	return bn_size_in_bytes(a) * 8;
}

static bool bignum_to_bigint(bigConst bn, TEE_BigInt *bi)
{
	NUMBYTES sz = bn_size_in_bytes(bn);
	BYTE buf[sz];

	if (!BnToBytes(bn, buf, &sz))
		return false;

	if (TEE_BigIntConvertFromOctetString(bi, buf, sz, 0))
		return false;

	return true;
}

static size_t bigint_size_in_bytes(TEE_BigInt *bi)
{
	size_t sz = 0;

	TEE_BigIntConvertToOctetString(NULL, &sz, bi);
	return sz;
}

static bool bigint_to_bignum(TEE_BigInt *bi, bigNum bn)
{
	size_t sz = bigint_size_in_bytes(bi);
	BYTE buf[sz];

	if (TEE_BigIntConvertToOctetString(buf, &sz, bi))
		return false;

	if (!BnFromBytes(bn, buf, sz))
		return false;

	return true;
}

static bool bigint_init_from_bn(TEE_BigInt *bi, size_t len, bigConst bn)
{
	TEE_BigIntInit(bi, len);
	return bignum_to_bigint(bn, bi);
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
#define BIGINT_INIT(bi)	TEE_BigIntInit((bi), ARRAY_SIZE(bi))
#define BIGINT_INIT_FROM_BN(bi, bn) \
	bigint_init_from_bn((bi), ARRAY_SIZE(bi), (bn))

static size_t bigint_len_from_bn(bigConst bn)
{
	return TEE_BigIntSizeInU32(bn_size_in_bits(bn));
}

static size_t fmm_ctx_size_from_bn(bigConst bn)
{
	return TEE_BigIntFMMContextSizeInU32(bn_size_in_bits(bn));
}

LIB_EXPORT BOOL BnDiv(bigNum quotient, bigNum remainder, bigConst dividend,
		      bigConst divisor)
{
	const size_t dividend_len = bigint_len_from_bn(dividend);
	const size_t divisor_len = bigint_len_from_bn(divisor);
	TEE_BigInt tee_dividend[dividend_len];
	TEE_BigInt tee_quotient[dividend_len];
	TEE_BigInt tee_divisor[divisor_len];
	TEE_BigInt tee_remainder[divisor_len];

	BIGINT_INIT(tee_quotient);
	BIGINT_INIT(tee_remainder);
	if (!BIGINT_INIT_FROM_BN(tee_dividend, dividend) ||
	    !BIGINT_INIT_FROM_BN(tee_divisor, divisor))
		return FALSE;

	TEE_BigIntDiv(tee_quotient, tee_remainder, tee_dividend, tee_divisor);

	if (quotient && !bigint_to_bignum(tee_quotient, quotient))
		return FALSE;
	if (remainder && !bigint_to_bignum(tee_remainder, remainder))
		return FALSE;

	return TRUE;
}

LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand,
		       bigConst multiplier)
{
	const size_t multiplicand_len = bigint_len_from_bn(multiplicand);
	const size_t multiplier_len = bigint_len_from_bn(multiplier);
	TEE_BigInt tee_result[multiplicand_len + multiplier_len];
	TEE_BigInt tee_multiplicand[multiplicand_len];
	TEE_BigInt tee_multiplier[multiplier_len];

	BIGINT_INIT(tee_result);
	if (!BIGINT_INIT_FROM_BN(tee_multiplicand, multiplicand) ||
	    !BIGINT_INIT_FROM_BN(tee_multiplier, multiplier))
		return FALSE;

	TEE_BigIntMul(tee_result, tee_multiplicand, tee_multiplier);

	return bigint_to_bignum(tee_result, result);
}

LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus)
{
	const size_t modulus_len = bigint_len_from_bn(modulus);
	const size_t number_len = bigint_len_from_bn(number);
	TEE_BigInt tee_modulus[modulus_len];
	TEE_BigInt tee_result[modulus_len];
	TEE_BigInt tee_number[number_len];

	BIGINT_INIT(tee_result);
	if (!BIGINT_INIT_FROM_BN(tee_modulus, modulus) ||
	    !BIGINT_INIT_FROM_BN(tee_number, number))
		return FALSE;

	// Just in case number >= modulus. JW: why?
	//TEE_BigIntMod(tee_number, tee_number, tee_modulus);
	TEE_BigIntInvMod(tee_result, tee_number, tee_modulus);

	return bigint_to_bignum(tee_result, result);
}

LIB_EXPORT BOOL BnModMult(bigNum result, bigConst op1, bigConst op2,
			  bigConst modulus)
{
	const size_t modulus_len = bigint_len_from_bn(modulus);
	TEE_BigInt tee_modulus[modulus_len];
	TEE_BigInt tee_result[modulus_len];
	TEE_BigInt tee_op1[bigint_len_from_bn(op1)];
	TEE_BigInt tee_op2[bigint_len_from_bn(op2)];

	BIGINT_INIT(tee_result);
	if (!BIGINT_INIT_FROM_BN(tee_modulus, modulus) ||
	    !BIGINT_INIT_FROM_BN(tee_op1, op1) ||
	    !BIGINT_INIT_FROM_BN(tee_op2, op2))
		return FALSE;

	TEE_BigIntMod(tee_op1, tee_op1, tee_modulus);
	TEE_BigIntMod(tee_op2, tee_op2, tee_modulus);
	TEE_BigIntMulMod(tee_result, tee_op1, tee_op2, tee_modulus);

	return bigint_to_bignum(tee_result, result);
}

LIB_EXPORT BOOL BnModExp(bigNum result, bigConst number, bigConst exponent,
			 bigConst modulus)
{
	const size_t modulus_len = bigint_len_from_bn(modulus);
	TEE_BigInt tee_modulus[modulus_len];
	TEE_BigInt tee_result[modulus_len];
	TEE_BigInt tee_number[bigint_len_from_bn(number)];
	TEE_BigInt tee_exponent[bigint_len_from_bn(exponent)];
	TEE_BigIntFMMContext fmm_ctx[fmm_ctx_size_from_bn(modulus)];

	BIGINT_INIT(tee_result);
	if (!BIGINT_INIT_FROM_BN(tee_modulus, modulus) ||
	    !BIGINT_INIT_FROM_BN(tee_number, number) ||
	    !BIGINT_INIT_FROM_BN(tee_exponent, exponent) ||
	    TEE_BigIntInitFMMContext1(fmm_ctx, ARRAY_SIZE(fmm_ctx),
				      tee_modulus))
		return FALSE;

	TEE_BigIntMod(tee_number, tee_number, tee_modulus);
	if (TEE_BigIntExpMod(tee_result, tee_number, tee_exponent, tee_modulus,
			     fmm_ctx))
		return FALSE;

	return bigint_to_bignum(tee_result, result);
}

LIB_EXPORT BOOL BnGcd(bigNum gcd, bigConst number1, bigConst number2)
{
	TEE_BigInt tee_number1[bigint_len_from_bn(number1)];
	TEE_BigInt tee_number2[bigint_len_from_bn(number2)];
	TEE_BigInt tee_gcd[MIN(ARRAY_SIZE(tee_number1),
			       ARRAY_SIZE(tee_number2))];

	BIGINT_INIT(tee_gcd);
	if (!BIGINT_INIT_FROM_BN(tee_number1, number1) ||
	    !BIGINT_INIT_FROM_BN(tee_number2, number2))
		return FALSE;

	TEE_BigIntComputeExtendedGcd(tee_gcd, 0, 0, tee_number1, tee_number2);

	return bigint_to_bignum(tee_gcd, gcd);
}

/**
 * This is an implementation of https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
*/
static void double_point_jacobi(TEE_BigInt *x3, TEE_BigInt *y3, TEE_BigInt *z3,
				const TEE_BigInt *x1, const TEE_BigInt *y1,
				const TEE_BigInt *z1, const TEE_BigInt *a,
				const TEE_BigInt *p)
{
	size_t number_size = TEE_BigIntSizeInU32(TEE_BigIntGetBitCount(p));
	TEE_BigInt xx[number_size];
	TEE_BigInt yy[number_size];
	TEE_BigInt yyyy[number_size];
	TEE_BigInt zz[number_size];
	TEE_BigInt s[number_size];
	TEE_BigInt m[number_size];

	BIGINT_INIT(xx);
	BIGINT_INIT(yy);
	BIGINT_INIT(yyyy);
	BIGINT_INIT(zz);
	BIGINT_INIT(s);
	BIGINT_INIT(m);

	/* xx = x1^2 */
	TEE_BigIntSquareMod(xx, x1, p);
	/* yy = y1^2 */
	TEE_BigIntSquareMod(yy, y1, p);
	/* yyyy = yy^2 */
	TEE_BigIntSquareMod(yyyy, yy, p);
	/* zz = z1^2 */
	TEE_BigIntSquareMod(zz, z1, p);
	/* s = 2*((x1 + yy)^2 - xx - yyyy) */
	TEE_BigIntAddMod(s, x1, yy, p);
	TEE_BigIntSquareMod(s, s, p);
	TEE_BigIntSubMod(s, s, xx, p);
	TEE_BigIntSubMod(s, s, yyyy, p);
	TEE_BigIntAddMod(s, s, s, p);
	/* m = 3*xx + a + zz^2 */
	TEE_BigIntSquareMod(m, zz, p);
	TEE_BigIntMulMod(m, m, a, p);
	TEE_BigIntAddMod(m, m, xx, p);
	TEE_BigIntAddMod(m, m, xx, p);
	TEE_BigIntAddMod(m, m, xx, p);
	/* x3 = m^2 - 2*s */
	TEE_BigIntSquareMod(x3, m, p);
	TEE_BigIntSubMod(x3, x3, s, p);
	TEE_BigIntSubMod(x3, x3, s, p);
	/* y3 = m * (x - x3) - 8 * yyyy */
	TEE_BigIntSubMod(y3, s, x3, p);
	TEE_BigIntMulMod(y3, y3, m, p);
	TEE_BigIntAddMod(z3, yyyy, yyyy, p);
	TEE_BigIntAddMod(z3, z3, z3, p);
	TEE_BigIntAddMod(z3, z3, z3, p);
	TEE_BigIntSubMod(y3, y3, z3, p);
	/* z3 = (y1 + z1)^2 - yy - zz */
	TEE_BigIntAddMod(z3, y1, z1, p);
	TEE_BigIntSquareMod(z3, z3, p);
	TEE_BigIntSubMod(z3, z3, yy, p);
	TEE_BigIntSubMod(z3, z3, zz, p);
}

/* return 0xffffffff if z is zer0 and 0 otherwise */
static uint32_t is_zero(const TEE_BigInt *z)
{
	uint32_t result = (uint32_t)TEE_BigIntCmpS32(z, 0);

	/*
	 * This looks like an attempt of protection against a side channel
	 * attack.
	 * JW: why is it needed or effective here?
	 */
	result--;
	result &= result >> 16;
	result &= result >> 8;
	result &= result >> 4;
	result &= result >> 2;
	result &= result >> 1;
	result = -result;
	return result;
}

/*
 * Copy src over dst if mask is 0xffffffff, do not if mask is 0.
 * This requires dst and src to have exactly the same size
 */
static void conditional_copy(TEE_BigInt *dst, const TEE_BigInt *src, size_t len,
			     uint32_t mask)
{
	size_t k = 0;

	/*
	 * This looks like an attempt of protection against a side channel
	 * attack.
	 * JW: why?
	 */
	for (k = 0; k < len; ++k)
		dst[k] = ((~mask) & dst[k]) | (mask & src[k]);
}

/*
 * This is an explicit implementation of
 * https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl.
 * output areas must not overlap with input areas.
 */
static void add_points_jacobi(TEE_BigInt *x3, TEE_BigInt *y3, TEE_BigInt *z3,
			      const TEE_BigInt *x1, const TEE_BigInt *y1,
			      const TEE_BigInt *z1, const TEE_BigInt *x2,
			      const TEE_BigInt *y2, const TEE_BigInt *z2,
			      const TEE_BigInt *p)
{
	size_t number_size = TEE_BigIntSizeInU32(TEE_BigIntGetBitCount(p));
	TEE_BigInt z1z1[number_size];
	TEE_BigInt z2z2[number_size];
	TEE_BigInt u1[number_size];
	TEE_BigInt u2[number_size];
	TEE_BigInt s1[number_size];
	TEE_BigInt s2[number_size];
	TEE_BigInt h[number_size];
	TEE_BigInt i[number_size];
	TEE_BigInt j[number_size];
	TEE_BigInt r[number_size];
	TEE_BigInt v[number_size];
	uint32_t z1_is_zero = 0;
	uint32_t z2_is_zero = 0;


	BIGINT_INIT(z1z1);
	BIGINT_INIT(z2z2);
	BIGINT_INIT(u1);
	BIGINT_INIT(u2);
	BIGINT_INIT(s1);
	BIGINT_INIT(s2);
	BIGINT_INIT(h);
	BIGINT_INIT(i);
	BIGINT_INIT(j);
	BIGINT_INIT(r);
	BIGINT_INIT(v);

	/* z1z1 = (z1 * z1) % p */
	TEE_BigIntSquareMod(z1z1, z1, p);
	/* z2z2 = (z2 * z2) % p */
	TEE_BigIntSquareMod(z2z2, z2, p);
	/* u1 = (x1 * z2z2) % p */
	TEE_BigIntMulMod(u1, x1, z2z2, p);
	/* u2 = (x2 * z1z1) % p */
	TEE_BigIntMulMod(u2, x2, z1z1, p);
	/* = (y1 * z2 * z2z2) % p */
	TEE_BigIntMulMod(s1, y1, z2, p);
	TEE_BigIntMulMod(s1, s1, z2z2, p);
	/* s2 = (y2 * z1 * z1z1) % p */
	TEE_BigIntMulMod(s2, y2, z1, p);
	TEE_BigIntMulMod(s2, s2, z1z1, p);
	/* h = (u2 - u1) % p */
	TEE_BigIntSubMod(h, u2, u1, p);
	/* i = (2 * h) % p */
	TEE_BigIntAddMod(i, h, h, p);
	/* i = (i * i) % p */
	TEE_BigIntSquareMod(i, i, p);
	/* j = (h * i) % p */
	TEE_BigIntMulMod(j, h, i, p);
	/* r = (2 * (s2 - s1)) % p */
	TEE_BigIntSubMod(r, s2, s1, p);
	TEE_BigIntAddMod(r, r, r, p);
	/* v = (u1 * i) % p */
	TEE_BigIntMulMod(v, u1, i, p);
	/* x3 = (r * r - j - 2 * v) % p */
	TEE_BigIntSquareMod(x3, r, p);
	TEE_BigIntSubMod(x3, x3, j, p);
	TEE_BigIntSubMod(x3, x3, v, p);
	TEE_BigIntSubMod(x3, x3, v, p);
	/* y3 = (r * (v - x3) - 2 * s1 * j) % p */
	TEE_BigIntSubMod(y3, v, x3, p);
	TEE_BigIntMulMod(y3, y3, r, p);
	TEE_BigIntMulMod(z3, s1, j, p);
	TEE_BigIntSubMod(y3, y3, z3, p);
	TEE_BigIntSubMod(y3, y3, z3, p);
	/* z3 = (z1 + z2) % p */
	TEE_BigIntAddMod(z3, z1, z2, p);
	/* z3 = ((z3 * z3 - z1z1 - z2z2) * h) % p */
	TEE_BigIntSquareMod(z3, z3, p);
	TEE_BigIntSubMod(z3, z3, z1z1, p);
	TEE_BigIntSubMod(z3, z3, z2z2, p);
	TEE_BigIntMulMod(z3, z3, h, p);

	/*
	 * Handle the case that one of the points is the point at infinity,
	 * i.e., z1=0 or z2=0.
	 */
	z1_is_zero = is_zero(z1);
	z2_is_zero = is_zero(z2);
	conditional_copy(x3, x2, number_size, z1_is_zero);
	conditional_copy(y3, y2, number_size, z1_is_zero);
	conditional_copy(z3, z2, number_size, z1_is_zero);
	conditional_copy(x3, x1, number_size, z2_is_zero);
	conditional_copy(y3, y1, number_size, z2_is_zero);
	conditional_copy(z3, z1, number_size, z2_is_zero);
}

static void scalar_multiplication_jacobi(TEE_BigInt *x3, TEE_BigInt *y3,
					 TEE_BigInt *z3, const TEE_BigInt *x1,
					 const TEE_BigInt *y1,
					 const TEE_BigInt *z1,
					 const uint8_t *scalar,
					 size_t scalar_size,
					 const TEE_BigInt *a,
					 const TEE_BigInt *p)
{
	size_t number_size = TEE_BigIntSizeInU32(TEE_BigIntGetBitCount(p));
	TEE_BigInt tmp_buffer[2 * 3 * number_size];
	TEE_BigInt pre_x[16][number_size];
	TEE_BigInt pre_y[16][number_size];
	TEE_BigInt pre_z[16][number_size];
	TEE_BigInt *tmp1 = NULL;
	TEE_BigInt *tmp2 = NULL;
	TEE_BigInt *t = NULL;
	size_t k = 0;
	int w = 0;

#ifdef DEBUG_OUTPUT_TEE_MATH
	printf("scalar_multiplication_jacobi\n");
	printf("    x1 = 0x");
	printf_bigint(x1);
	printf("\n    y1 = 0x");
	printf_bigint(y1);
	printf("\n    z1 = 0x");
	printf_bigint(z1);
	printf("\n    s = 0x");
	for (size_t k = 0; k < scalar_size; ++k) {
		printf("%.2x", scalar[k]);
	}
	printf("\n");
#endif
	if (scalar_size == 0) {
		TEE_BigIntConvertFromS32(x3, 1);
		TEE_BigIntConvertFromS32(y3, 1);
		TEE_BigIntConvertFromS32(z3, 0);
		return;
	}

	for (k = 0; k < 16; ++k) {
		BIGINT_INIT(pre_x[k]);
		BIGINT_INIT(pre_y[k]);
		BIGINT_INIT(pre_z[k]);
	}

	TEE_BigIntConvertFromS32(pre_x[0], 1);
	TEE_BigIntConvertFromS32(pre_y[0], 1);
	TEE_BigIntConvertFromS32(pre_z[0], 0);
	TEE_BigIntAssign(pre_x[1], x1);
	TEE_BigIntAssign(pre_y[1], y1);
	TEE_BigIntAssign(pre_z[1], z1);
	double_point_jacobi(pre_x[2], pre_y[2], pre_z[2], pre_x[1], pre_y[1],
			    pre_z[1], a, p);
	double_point_jacobi(pre_x[4], pre_y[4], pre_z[4], pre_x[2], pre_y[2],
			    pre_z[2], a, p);
	double_point_jacobi(pre_x[8], pre_y[8], pre_z[8], pre_x[4], pre_y[4],
			    pre_z[4], a, p);
	add_points_jacobi(pre_x[3], pre_y[3], pre_z[3], pre_x[1], pre_y[1],
			  pre_z[1], pre_x[2], pre_y[2], pre_z[2], p);
	add_points_jacobi(pre_x[5], pre_y[5], pre_z[5], pre_x[1], pre_y[1],
			  pre_z[1], pre_x[4], pre_y[4], pre_z[4], p);
	double_point_jacobi(pre_x[6], pre_y[6], pre_z[6], pre_x[3], pre_y[3],
			    pre_z[3], a, p);
	add_points_jacobi(pre_x[7], pre_y[7], pre_z[7], pre_x[1], pre_y[1],
			  pre_z[1], pre_x[6], pre_y[6], pre_z[6], p);
	add_points_jacobi(pre_x[9], pre_y[9], pre_z[9], pre_x[1], pre_y[1],
			  pre_z[1], pre_x[8], pre_y[8], pre_z[8], p);
	double_point_jacobi(pre_x[10], pre_y[10], pre_z[10], pre_x[5], pre_y[5],
			    pre_z[5], a, p);
	add_points_jacobi(pre_x[11], pre_y[11], pre_z[11], pre_x[1], pre_y[1],
			  pre_z[1], pre_x[10], pre_y[10], pre_z[10], p);
	double_point_jacobi(pre_x[12], pre_y[12], pre_z[12], pre_x[6], pre_y[6],
			    pre_z[6], a, p);
	add_points_jacobi(pre_x[13], pre_y[13], pre_z[13], pre_x[1], pre_y[1],
			  pre_z[1], pre_x[12], pre_y[12], pre_z[12], p);
	double_point_jacobi(pre_x[14], pre_y[14], pre_z[14], pre_x[7], pre_y[7],
			    pre_z[7], a, p);
	add_points_jacobi(pre_x[15], pre_y[15], pre_z[15], pre_x[1], pre_y[1],
			  pre_z[1], pre_x[14], pre_y[14], pre_z[14], p);

	for (k = 0; k < 6; k++)
		TEE_BigIntInit(tmp_buffer + k * number_size, number_size);
	tmp1 = tmp_buffer;
	tmp2 = tmp_buffer + 3 * number_size;
	w = scalar[0] >> 4;
	TEE_BigIntAssign(tmp1, pre_x[w]);
	TEE_BigIntAssign(tmp1 + number_size, pre_y[w]);
	TEE_BigIntAssign(tmp1 + 2 * number_size, pre_z[w]);

	/* Double four times, then add the appropriate pre-computed multiple. */
	for (k = 1; k < 2 * scalar_size; ++k) {
		double_point_jacobi(tmp2, tmp2 + number_size,
				    tmp2 + 2 * number_size, tmp1,
				    tmp1 + number_size, tmp1 + 2 * number_size,
				    a, p);
		double_point_jacobi(tmp1, tmp1 + number_size,
				    tmp1 + 2 * number_size, tmp2,
				    tmp2 + number_size, tmp2 + 2 * number_size,
				    a, p);
		double_point_jacobi(tmp2, tmp2 + number_size,
				    tmp2 + 2 * number_size, tmp1,
				    tmp1 + number_size, tmp1 + 2 * number_size,
				    a, p);
		double_point_jacobi(tmp1, tmp1 + number_size,
				    tmp1 + 2 * number_size, tmp2,
				    tmp2 + number_size, tmp2 + 2 * number_size,
				    a, p);
		w = scalar[k >> 1];
		if (k & 1) {
			w &= 0xf;
		} else {
			w >>= 4;
		}
		add_points_jacobi(tmp2, tmp2 + number_size,
				  tmp2 + 2 * number_size, tmp1,
				  tmp1 + number_size, tmp1 + 2 * number_size,
				  pre_x[w], pre_y[w], pre_z[w], p);
		/* Swap tmp1, tmp2. */
		t = tmp1;
		tmp1 = tmp2;
		tmp2 = t;
	}
	TEE_BigIntAssign(x3, tmp1);
	TEE_BigIntAssign(y3, tmp1 + number_size);
	TEE_BigIntAssign(z3, tmp1 + 2 * number_size);

#ifdef DEBUG_OUTPUT_TEE_MATH
	printf("    x3 = 0x");
	printf_bigint(x3);
	printf("\n    y3 = 0x");
	printf_bigint(y3);
	printf("\n    z3 = 0x");
	printf_bigint(z3);
	printf("\n");
#endif
}

static void jacobi_to_affine(TEE_BigInt *x3, TEE_BigInt *y3,
			     const TEE_BigInt *x1, const TEE_BigInt *y1,
			     const TEE_BigInt *z1, const TEE_BigInt *p)
{
	const size_t p_bitcount = TEE_BigIntGetBitCount(p);
	const size_t number_size = TEE_BigIntSizeInU32(p_bitcount);
	TEE_BigInt zi[number_size];
	TEE_BigInt pm2[number_size];
	TEE_BigIntFMMContext fmm_ctx[TEE_BigIntFMMContextSizeInU32(p_bitcount)];

	BIGINT_INIT(zi);
	BIGINT_INIT(pm2);
	if (TEE_BigIntInitFMMContext1(fmm_ctx, ARRAY_SIZE(fmm_ctx), p))
		TEE_Panic(0);

	TEE_BigIntConvertFromS32(pm2, 2);
	TEE_BigIntSub(pm2, p, pm2);		   /* pm2 = p - 2 */
	TEE_BigIntExpMod(zi, z1, pm2, p, fmm_ctx); /* Use Fermat for inversion*/
	TEE_BigIntMulMod(pm2, zi, zi, p);	   /* pm2 = zi^2 */
	TEE_BigIntMulMod(x3, x1, pm2, p);
	TEE_BigIntMulMod(pm2, pm2, zi, p);	   /* pm2 = zi^3 */
	TEE_BigIntMulMod(y3, y1, pm2, p);
}

LIB_EXPORT BOOL BnEccModMult(bigPoint R, pointConst S, bigConst d, bigCurve E)
{
	const size_t prime_len = bigint_len_from_bn(E->prime);
	TEE_BigInt tee_a[bigint_len_from_bn(E->a)];
	BYTE buffer[bn_size_in_bytes(E->prime) + 1];
	TEE_BigInt tee_p[prime_len];
	TEE_BigInt tee_x1[prime_len];
	TEE_BigInt tee_y1[prime_len];
	TEE_BigInt tee_z1[prime_len];
	TEE_BigInt tee_x3[prime_len];
	TEE_BigInt tee_y3[prime_len];
	TEE_BigInt tee_z3[prime_len];
	NUMBYTES size = 0;

	if (!S)
		S = CurveGetG(AccessCurveData(E));

	BIGINT_INIT(tee_x3);
	BIGINT_INIT(tee_y3);
	BIGINT_INIT(tee_z3);

	if (!BIGINT_INIT_FROM_BN(tee_p, E->prime) ||
	    !BIGINT_INIT_FROM_BN(tee_a, E->a) ||
	    !BIGINT_INIT_FROM_BN(tee_x1, S->x) ||
	    !BIGINT_INIT_FROM_BN(tee_y1, S->y) ||
	    !BIGINT_INIT_FROM_BN(tee_z1, S->z))
		return FALSE;

	size = bn_size_in_bytes(d);
	if (!BnToBytes(d, buffer, &size))
		return FALSE;
	scalar_multiplication_jacobi(tee_x3, tee_y3, tee_z3, tee_x1, tee_y1,
				     tee_z1, buffer, size, tee_a, tee_p);
	jacobi_to_affine(tee_x1, tee_y1, tee_x3, tee_y3, tee_z3, tee_p);

	if (!bigint_to_bignum(tee_x1, R->x) ||
	    !bigint_to_bignum(tee_y1, R->y) ||
	    !BnFromBytes(R->z, &(const BYTE){1}, 1))
		return FALSE;
	return TRUE;
}

LIB_EXPORT BOOL BnEccModMult2(bigPoint R, pointConst S, bigConst d,
			      pointConst Q, bigConst u, bigCurve E)
{
	size_t prime_len = bigint_len_from_bn(E->prime);
	size_t a_len = bigint_len_from_bn(E->a);
	BYTE buffer[bn_size_in_bytes(E->prime) + 1];
	TEE_BigInt tee_p[prime_len];
	TEE_BigInt tee_x1[prime_len];
	TEE_BigInt tee_y1[prime_len];
	TEE_BigInt tee_z1[prime_len];
	TEE_BigInt tee_x2[prime_len];
	TEE_BigInt tee_y2[prime_len];
	TEE_BigInt tee_z2[prime_len];
	TEE_BigInt tee_x3[prime_len];
	TEE_BigInt tee_y3[prime_len];
	TEE_BigInt tee_z3[prime_len];
	TEE_BigInt tee_a[a_len];
	NUMBYTES size = 0;

	BIGINT_INIT(tee_z2);
	BIGINT_INIT(tee_x3);
	BIGINT_INIT(tee_y3);
	BIGINT_INIT(tee_z3);
	if (!BIGINT_INIT_FROM_BN(tee_p, E->prime) ||
	    !BIGINT_INIT_FROM_BN(tee_a, E->a) ||
	    !BIGINT_INIT_FROM_BN(tee_x1, S->x) ||
	    !BIGINT_INIT_FROM_BN(tee_y1, S->y) ||
	    !BIGINT_INIT_FROM_BN(tee_z1, S->z) ||
	    !BIGINT_INIT_FROM_BN(tee_x2, Q->x) ||
	    !BIGINT_INIT_FROM_BN(tee_y2, Q->y))
		return FALSE;

	TEE_BigIntConvertFromS32(tee_z2, 1);

	size = bn_size_in_bytes(d);
	BnToBytes(d, buffer, &size);

	/*
	 * TODO Use a more efficient algorithm for multiple scalar
	 * multiplication.
	 */
	scalar_multiplication_jacobi(tee_x3, tee_y3, tee_z3, tee_x1, tee_y1,
				     tee_z1, buffer, size, tee_a, tee_p);
	size = bn_size_in_bytes(u);
	BnToBytes(u, buffer, &size);
	scalar_multiplication_jacobi(tee_x1, tee_y1, tee_z1, tee_x2, tee_y2,
				     tee_z2, buffer, size, tee_a, tee_p);
	add_points_jacobi(tee_x2, tee_y2, tee_z2, tee_x1, tee_y1, tee_z1,
			  tee_x3, tee_y3, tee_z3, tee_p);
	jacobi_to_affine(tee_x1, tee_y1, tee_x2, tee_y2, tee_z2, tee_p);

	if (!bigint_to_bignum(tee_x1, R->x) ||
	    !bigint_to_bignum(tee_y1, R->y) ||
	    !BnFromBytes(R->z, &(const BYTE){1}, 1))
		return FALSE;
	return TRUE;
}
#endif
