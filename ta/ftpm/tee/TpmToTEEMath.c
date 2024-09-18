/* SPDX-License-Identifier: BSD-2-Clause */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 * All rights reserved.
 */

#include "Tpm.h"

#ifdef MATH_LIB_TEE

#  include <tee_internal_api.h>

#  ifdef DEBUG_OUTPUT_TEE_MATH
#    include <stdio.h>
#    define DEBUG_PRINT_RESULT(f) printf("    " #f " returns %" PRIx32 "\n", f)
void printf_bigint(const TEE_BigInt* bigint)
{
    size_t buffer_len = 1024;
    uint8_t buffer[buffer_len];
    if(TEE_BigIntConvertToOctetString(buffer, &buffer_len, bigint) == TEE_SUCCESS)
    {
        if(buffer_len != 0)
        {
            for(size_t k = 0; k < buffer_len; ++k)
            {
                printf("%.2x", buffer[k]);
            }
        } else {
            printf("0");
        }
    } else {
        printf("ERROR!\n");
    }
}
#  else
#    define DEBUG_PRINT_RESULT(f) f
#  endif

/// @todo Internal representation of big integers in the TEE is implementation
/// defined. If we used the fact that we know how OP-TEE represents big integers
/// internally, then we could directly convert between the TPM representation
/// and the TEE representation rather than go through representation as a byte
/// string.
/// @brief Return the maximum size of to bigNum in crypt_uword_t
/// @param a
/// @param b
/// @return max(BnGetSize(a), BnGetSize(b))
static inline crypt_uword_t max_size(bigConst a, bigConst b)
{
    return BnGetSize(a) > BnGetSize(b) ? BnGetSize(a) : BnGetSize(b);
}

/// @brief Return the minimum size of to bigNum in crypt_uword_t
/// @param a
/// @param b
/// @return min(BnGetSize(a), BnGetSize(b))
static inline crypt_uword_t min_size(bigConst a, bigConst b)
{
    return BnGetSize(a) < BnGetSize(b) ? BnGetSize(a) : BnGetSize(b);
}

/// @brief Return the size of a bigNum in bit (rounded up to the nearest multiple of 8*sizeof(crypt_uword_t)).
/// @param a a bigNum
/// @return Size of a in bit rounded up to the nearest multiple of 8*sizeof(crypt_uword_t)
static inline size_t BnGetSizeInBit(bigConst a)
{
    return 8 * sizeof(crypt_uword_t) * BnGetSize(a);
}

/// @brief Return the size of a bigNum in bytes (rounded up to the nearest multiple of )
/// @param a 
/// @return 
static inline size_t BnGetSizeInBytes(bigConst a)
{
    return sizeof(crypt_uword_t) * BnGetSize(a);
}

LIB_EXPORT BOOL BnDiv(
    bigNum quotient, bigNum remainder, bigConst dividend, bigConst divisor)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("BnDiv\n");
#  endif
    const NUMBYTES buffer_size = sizeof(crypt_uword_t) * max_size(dividend, divisor);
    BYTE           buffer[buffer_size];

    size_t         len = TEE_BigIntSizeInU32(BnGetSizeInBit(dividend));
    TEE_BigInt     tee_dividend[len];
    TEE_BigIntInit(tee_dividend, len);
    TEE_BigInt tee_quotient[len];  /// Yes, this may be too much.
    TEE_BigIntInit(tee_quotient, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(divisor));
    TEE_BigInt tee_divisor[TEE_BigIntSizeInU32(BnGetSizeInBit(divisor))];
    TEE_BigIntInit(tee_divisor, len);
    TEE_BigInt tee_remainder[len];
    TEE_BigIntInit(tee_remainder, len);

    NUMBYTES size = BnGetSizeInBytes(dividend);
    BnToBytes(dividend, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_dividend,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.

    size = BnGetSizeInBytes(divisor);
    BnToBytes(divisor, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_divisor,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("    TEE_BigIntGetBitCount(tee_divisor) returns %" PRIu32 "\n",
           TEE_BigIntGetBitCount(tee_divisor));
#  endif

    TEE_BigIntDiv(tee_quotient, tee_remainder, tee_dividend, tee_divisor);

    if(quotient != 0)
    {
        size_t tee_size = buffer_size;
        DEBUG_PRINT_RESULT(
            TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_quotient));
        VERIFY(BnFromBytes(quotient, buffer, tee_size));
    }

    if(remainder != 0)
    {
        size_t tee_size = buffer_size;
        DEBUG_PRINT_RESULT(
            TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_remainder));
        VERIFY(BnFromBytes(remainder, buffer, tee_size));
    }
    return TRUE;
Error:
    return FALSE;
}

LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("BnMult\n");
#  endif
    const NUMBYTES buffer_size =
        sizeof(crypt_uword_t) * (BnGetSize(multiplicand) + BnGetSize(multiplier));
    BYTE       buffer[buffer_size];

    size_t     len = TEE_BigIntSizeInU32(BnGetSizeInBit(multiplicand));
    TEE_BigInt tee_multiplicand[len];
    TEE_BigIntInit(tee_multiplicand, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(multiplier));
    TEE_BigInt tee_multiplier[len];
    TEE_BigIntInit(tee_multiplier, len);

    len = TEE_BigIntSizeInU32(8 * buffer_size);
    TEE_BigInt tee_result[len];
    TEE_BigIntInit(tee_result, len);

    NUMBYTES size = BnGetSizeInBytes(multiplicand);
    BnToBytes(multiplicand, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_multiplicand,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(multiplier);
    BnToBytes(multiplier, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_multiplier,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.

    TEE_BigIntMul(tee_result, tee_multiplicand, tee_multiplier);

    size_t tee_size = buffer_size;
    TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_result);
    VERIFY(BnFromBytes(result, buffer, tee_size));
    return TRUE;
Error:
    return FALSE;
}

LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("BnModInverse\n");
#  endif
    const NUMBYTES buffer_size = sizeof(crypt_uword_t) * max_size(modulus, number);
    BYTE           buffer[buffer_size];

    size_t         len = TEE_BigIntSizeInU32(BnGetSizeInBit(modulus));
    TEE_BigInt     tee_modulus[len];
    TEE_BigIntInit(tee_modulus, len);
    TEE_BigInt tee_result[len];
    TEE_BigIntInit(tee_result, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(number));
    TEE_BigInt tee_number[len];
    TEE_BigIntInit(tee_number, len);

    NUMBYTES size = BnGetSizeInBytes(modulus);
    BnToBytes(modulus, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_modulus,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(number);
    BnToBytes(number, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_number,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.

    TEE_BigIntMod(
        tee_number, tee_number, tee_modulus);  // Just in case number >= modulus.
    TEE_BigIntInvMod(tee_result, tee_number, tee_modulus);

    size_t tee_size = buffer_size;
    TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_result);
    VERIFY(BnFromBytes(result, buffer, tee_size));
    return TRUE;
Error:
    return FALSE;
}

LIB_EXPORT BOOL BnModMult(bigNum result, bigConst op1, bigConst op2, bigConst modulus)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("BnModMult\n");
#  endif
    const NUMBYTES buffer_size = sizeof(crypt_uword_t)
                                 * (BnGetSize(modulus) > max_size(op1, op2)
                                        ? BnGetSize(modulus)
                                        : max_size(op1, op2));
    BYTE       buffer[buffer_size];

    size_t     len = TEE_BigIntSizeInU32(BnGetSizeInBit(modulus));
    TEE_BigInt tee_modulus[len];
    TEE_BigIntInit(tee_modulus, len);
    TEE_BigInt tee_result[len];
    TEE_BigIntInit(tee_result, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(op1));
    TEE_BigInt tee_op1[len];
    TEE_BigIntInit(tee_op1, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(op2));
    TEE_BigInt tee_op2[len];
    TEE_BigIntInit(tee_op2, len);

    NUMBYTES size = BnGetSizeInBytes(modulus);
    BnToBytes(modulus, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_modulus,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(op1);
    BnToBytes(op1, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_op1, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(op2);
    BnToBytes(op2, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_op2, buffer, size, 0);  /// @todo Check that all numbers are non-negative.

    TEE_BigIntMod(tee_op1, tee_op1, tee_modulus);
    TEE_BigIntMod(tee_op2, tee_op2, tee_modulus);
    TEE_BigIntMulMod(tee_result, tee_op1, tee_op2, tee_modulus);

    size_t tee_size = buffer_size;
    TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_result);
    VERIFY(BnFromBytes(result, buffer, tee_size));
    return TRUE;
Error:
    return FALSE;
}

LIB_EXPORT BOOL BnModExp(bigNum   result,    // OUT: the result
                         bigConst number,    // IN: number to exponentiate
                         bigConst exponent,  // IN:
                         bigConst modulus    // IN:
)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("BnModExp\n");
#  endif
    const NUMBYTES buffer_size = sizeof(crypt_uword_t)
                                 * (BnGetSize(modulus) > max_size(number, exponent)
                                        ? BnGetSize(modulus)
                                        : max_size(number, exponent));
    BYTE       buffer[buffer_size];

    size_t     len = TEE_BigIntSizeInU32(BnGetSizeInBit(modulus));
    TEE_BigInt tee_modulus[len];
    TEE_BigIntInit(tee_modulus, len);
    TEE_BigInt tee_result[len];
    TEE_BigIntInit(tee_result, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(number));
    TEE_BigInt tee_number[len];
    TEE_BigIntInit(tee_number, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(exponent));
    TEE_BigInt tee_exponent[len];
    TEE_BigIntInit(tee_exponent, len);

    NUMBYTES size = BnGetSizeInBytes(modulus);
    BnToBytes(modulus, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_modulus,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(number);
    BnToBytes(number, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_number,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(exponent);
    BnToBytes(exponent, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_exponent,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.

    TEE_BigIntMod(tee_number, tee_number, tee_modulus);
    const size_t fmm_ctx_size =
        TEE_BigIntFMMContextSizeInU32(BnGetSizeInBit(modulus));
    uint32_t fmm_ctx[fmm_ctx_size];
    DEBUG_PRINT_RESULT(TEE_BigIntInitFMMContext1(
        (TEE_BigIntFMMContext*)fmm_ctx, fmm_ctx_size, tee_modulus));
    DEBUG_PRINT_RESULT(TEE_BigIntExpMod(tee_result,
                                        tee_number,
                                        tee_exponent,
                                        tee_modulus,
                                        (TEE_BigIntFMMContext*)fmm_ctx));

    size_t tee_size = buffer_size;
    DEBUG_PRINT_RESULT(TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_result));
    VERIFY(BnFromBytes(result, buffer, tee_size));
    return TRUE;
Error:
    return FALSE;
}

LIB_EXPORT BOOL BnGcd(bigNum   gcd,      // OUT: the common divisor
                      bigConst number1,  // IN:
                      bigConst number2   // IN:
)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("BnGcd\n");
#  endif
    const NUMBYTES buffer_size = sizeof(crypt_uword_t) * max_size(number1, number2);
    BYTE           buffer[buffer_size];

    size_t         len = TEE_BigIntSizeInU32(BnGetSizeInBit(number1));
    TEE_BigInt     tee_number1[len];
    TEE_BigIntInit(tee_number1, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(number1));
    TEE_BigInt tee_number2[len];
    TEE_BigIntInit(tee_number2, len);

    len = TEE_BigIntSizeInU32(8 * sizeof(crypt_uword_t) * min_size(number1, number2));
    TEE_BigInt tee_gcd[len];
    TEE_BigIntInit(tee_gcd, len);

    NUMBYTES size = BnGetSizeInBytes(number1);
    BnToBytes(number1, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_number1,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(number2);
    BnToBytes(number2, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_number2,
        buffer,
        size,
        0);  /// @todo Check that all numbers are non-negative.

    TEE_BigIntComputeExtendedGcd(tee_gcd, 0, 0, tee_number1, tee_number2);

    size_t tee_size = buffer_size;
    TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_gcd);
    VERIFY(BnFromBytes(gcd, buffer, tee_size));
    return TRUE;
Error:
    return FALSE;
}

/**
 * This is an implementation of https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
*/
static void double_point_jacobi(TEE_BigInt*       x3,
                                TEE_BigInt*       y3,
                                TEE_BigInt*       z3,
                                const TEE_BigInt* x1,
                                const TEE_BigInt* y1,
                                const TEE_BigInt* z1,
                                const TEE_BigInt* a,
                                const TEE_BigInt* p)
{
    size_t     number_size = TEE_BigIntSizeInU32(TEE_BigIntGetBitCount(p));

    TEE_BigInt xx[number_size];
    TEE_BigIntInit(xx, number_size);
    // xx = x1^2
    TEE_BigIntSquareMod(xx, x1, p);
    TEE_BigInt yy[number_size];
    TEE_BigIntInit(yy, number_size);
    // yy = y1^2
    TEE_BigIntSquareMod(yy, y1, p);
    TEE_BigInt yyyy[number_size];
    TEE_BigIntInit(yyyy, number_size);
    // yyyy = yy^2
    TEE_BigIntSquareMod(yyyy, yy, p);
    TEE_BigInt zz[number_size];
    TEE_BigIntInit(zz, number_size);
    // zz = z1^2
    TEE_BigIntSquareMod(zz, z1, p);
    TEE_BigInt s[number_size];
    TEE_BigIntInit(s, number_size);
    // s = 2*((x1 + yy)^2 - xx - yyyy)
    TEE_BigIntAddMod(s, x1, yy, p);
    TEE_BigIntSquareMod(s, s, p);
    TEE_BigIntSubMod(s, s, xx, p);
    TEE_BigIntSubMod(s, s, yyyy, p);
    TEE_BigIntAddMod(s, s, s, p);
    TEE_BigInt m[number_size];
    TEE_BigIntInit(m, number_size);
    // m = 3*xx + a + zz^2
    TEE_BigIntSquareMod(m, zz, p);
    TEE_BigIntMulMod(m, m, a, p);
    TEE_BigIntAddMod(m, m, xx, p);
    TEE_BigIntAddMod(m, m, xx, p);
    TEE_BigIntAddMod(m, m, xx, p);
    // x3 = m^2 - 2*s
    TEE_BigIntSquareMod(x3, m, p);
    TEE_BigIntSubMod(x3, x3, s, p);
    TEE_BigIntSubMod(x3, x3, s, p);
    // y3 = m * (x - x3) - 8*yyyy
    TEE_BigIntSubMod(y3, s, x3, p);
    TEE_BigIntMulMod(y3, y3, m, p);
    TEE_BigIntAddMod(z3, yyyy, yyyy, p);
    TEE_BigIntAddMod(z3, z3, z3, p);
    TEE_BigIntAddMod(z3, z3, z3, p);
    TEE_BigIntSubMod(y3, y3, z3, p);
    // z3 = (y1 + z1)^2 - yy -zz
    TEE_BigIntAddMod(z3, y1, z1, p);
    TEE_BigIntSquareMod(z3, z3, p);
    TEE_BigIntSubMod(z3, z3, yy, p);
    TEE_BigIntSubMod(z3, z3, zz, p);
}

/// @brief Return 0xffffffff if a TEE_BigInt is zero, 0 otherwise
/// @param z TEE_BigInt to test
/// @return 0xffffffff if z is zer0 and0 otherwise
static uint32_t is_zero(TEE_BigInt* z)
{
    uint32_t result = (uint32_t)TEE_BigIntCmpS32(z, 0);
    result--;
    result &= result >> 16;
    result &= result >> 8;
    result &= result >> 4;
    result &= result >> 2;
    result &= result >> 1;
    result = -result;
    return result;
}

/// @brief Copy src over dst if mask is 0xffffffff, do not if mask is 0.
/// @todo This requires dst and src to have exactly the same size
/// @param dst 
/// @param src 
/// @param len size of dst and src in uint32_t
/// @param mask 
static void conditional_copy(TEE_BigInt* dst, const TEE_BigInt* src, size_t len, uint32_t mask)
{
    for(size_t k = 0; k < len; ++k)
    {
        dst[k] = ((~mask) & dst[k]) | (mask & src[k]);
    }
}
/**
 * This is an explicit implementation of https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl.
 * output areas must not overlap with input areas
*/
static void add_points_jacobi(TEE_BigInt*       x3,
                              TEE_BigInt*       y3,
                              TEE_BigInt*       z3,
                              const TEE_BigInt* x1,
                              const TEE_BigInt* y1,
                              const TEE_BigInt* z1,
                              const TEE_BigInt* x2,
                              const TEE_BigInt* y2,
                              const TEE_BigInt* z2,
                              const TEE_BigInt* p)
{
    size_t     number_size = TEE_BigIntSizeInU32(TEE_BigIntGetBitCount(p));

    TEE_BigInt z1z1[number_size];
    TEE_BigIntInit(z1z1, number_size);
    // z1z1 = (z1 * z1) % p
    TEE_BigIntSquareMod(z1z1, z1, p);
    TEE_BigInt z2z2[number_size];
    TEE_BigIntInit(z2z2, number_size);
    // z2z2 = (z2 * z2) % p
    TEE_BigIntSquareMod(z2z2, z2, p);
    TEE_BigInt u1[number_size];
    TEE_BigIntInit(u1, number_size);
    // u1 = (x1 * z2z2) % p
    TEE_BigIntMulMod(u1, x1, z2z2, p);
    TEE_BigInt u2[number_size];
    TEE_BigIntInit(u2, number_size);
    // u2 = (x2 * z1z1) % p
    TEE_BigIntMulMod(u2, x2, z1z1, p);
    //s1 = (y1 * z2 * z2z2) % p
    TEE_BigInt s1[number_size];
    TEE_BigIntInit(s1, number_size);
    TEE_BigIntMulMod(s1, y1, z2, p);
    TEE_BigIntMulMod(s1, s1, z2z2, p);
    TEE_BigInt s2[number_size];
    TEE_BigIntInit(s2, number_size);
    // s2 = (y2 * z1 * z1z1) % p
    TEE_BigIntMulMod(s2, y2, z1, p);
    TEE_BigIntMulMod(s2, s2, z1z1, p);
    TEE_BigInt h[number_size];
    TEE_BigIntInit(h, number_size);
    // h = (u2 - u1) % p
    TEE_BigIntSubMod(h, u2, u1, p);
    TEE_BigInt i[number_size];
    TEE_BigIntInit(i, number_size);
    // i = (2 * h) % p
    TEE_BigIntAddMod(i, h, h, p);
    // i = (i * i) % p
    TEE_BigIntSquareMod(i, i, p);
    TEE_BigInt j[number_size];
    TEE_BigIntInit(j, number_size);
    // j = (h * i) % p
    TEE_BigIntMulMod(j, h, i, p);
    TEE_BigInt r[number_size];
    TEE_BigIntInit(r, number_size);
    // r = (2 * (s2 - s1)) % p
    TEE_BigIntSubMod(r, s2, s1, p);
    TEE_BigIntAddMod(r, r, r, p);
    TEE_BigInt v[number_size];
    TEE_BigIntInit(v, number_size);
    // v = (u1 * i) % p
    TEE_BigIntMulMod(v, u1, i, p);
    // x3 = (r * r - j - 2 * v) % p
    TEE_BigIntSquareMod(x3, r, p);
    TEE_BigIntSubMod(x3, x3, j, p);
    TEE_BigIntSubMod(x3, x3, v, p);
    TEE_BigIntSubMod(x3, x3, v, p);
    // y3 = (r * (v - x3) - 2 * s1 * j) % p
    TEE_BigIntSubMod(y3, v, x3, p);
    TEE_BigIntMulMod(y3, y3, r, p);
    TEE_BigIntMulMod(z3, s1, j, p);
    TEE_BigIntSubMod(y3, y3, z3, p);
    TEE_BigIntSubMod(y3, y3, z3, p);
    // z3 = (z1 + z2) % p
    TEE_BigIntAddMod(z3, z1, z2, p);
    // z3 = ((z3 * z3 - z1z1 - z2z2) * h) % p
    TEE_BigIntSquareMod(z3, z3, p);
    TEE_BigIntSubMod(z3, z3, z1z1, p);
    TEE_BigIntSubMod(z3, z3, z2z2, p);
    TEE_BigIntMulMod(z3, z3, h, p);

    // Handle the case that one of the points is the point at infinity, i.e., z1=0 or z2=0.
    uint32_t z1_is_zero = is_zero(z1);
    uint32_t z2_is_zero = is_zero(z2);
    conditional_copy(x3, x2, number_size, z1_is_zero);
    conditional_copy(y3, y2, number_size, z1_is_zero);
    conditional_copy(z3, z2, number_size, z1_is_zero);
    conditional_copy(x3, x1, number_size, z2_is_zero);
    conditional_copy(y3, y1, number_size, z2_is_zero);
    conditional_copy(z3, z1, number_size, z2_is_zero);
}

static void scalar_multiplication_jacobi(TEE_BigInt*       x3,
                                         TEE_BigInt*       y3,
                                         TEE_BigInt*       z3,
                                         const TEE_BigInt* x1,
                                         const TEE_BigInt* y1,
                                         const TEE_BigInt* z1,
                                         const uint8_t*    scalar,
                                         size_t            scalar_size,
                                         const TEE_BigInt* a,
                                         const TEE_BigInt* p)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("scalar_multiplication_jacobi\n");
    printf("    x1 = 0x");
    printf_bigint(x1);
    printf("\n    y1 = 0x");
    printf_bigint(y1);
    printf("\n    z1 = 0x");
    printf_bigint(z1);
    printf("\n    s = 0x");
    for(size_t k = 0; k < scalar_size; ++k)
    {
        printf("%.2x", scalar[k]);
    }
    printf("\n");
#  endif
    if(scalar_size == 0)
    {
        TEE_BigIntConvertFromS32(x3, 1);
        TEE_BigIntConvertFromS32(y3, 1);
        TEE_BigIntConvertFromS32(z3, 0);
        return;
    }
// Macros to access x, y, z coordinates of point k in the buffer of pre-computed points.
#  define PRE_X(k) (precomputed + (k) * 3 * number_size)
#  define PRE_Y(k) (precomputed + (k) * 3 * number_size + number_size)
#  define PRE_Z(k) (precomputed + (k) * 3 * number_size + 2 * number_size)

    size_t number_size = TEE_BigIntSizeInU32(TEE_BigIntGetBitCount(p));
    // Pre-compute multiples 0, 1, 2, ... 15 times the point.
    TEE_BigInt precomputed[16 * 3 * number_size];
    for(uint_fast8_t k = 0; k < 3 * 16; ++k)
    {
        TEE_BigIntInit(precomputed + k * number_size, number_size);
    }
    TEE_BigIntConvertFromS32(PRE_X(0), 1);
    TEE_BigIntConvertFromS32(PRE_Y(0), 1);
    TEE_BigIntConvertFromS32(PRE_Z(0), 0);
    TEE_BigIntAssign(PRE_X(1), x1);
    TEE_BigIntAssign(PRE_Y(1), y1);
    TEE_BigIntAssign(PRE_Z(1), z1);
    double_point_jacobi(
        PRE_X(2), PRE_Y(2), PRE_Z(2), PRE_X(1), PRE_Y(1), PRE_Z(1), a, p);
    double_point_jacobi(
        PRE_X(4), PRE_Y(4), PRE_Z(4), PRE_X(2), PRE_Y(2), PRE_Z(2), a, p);
    double_point_jacobi(
        PRE_X(8), PRE_Y(8), PRE_Z(8), PRE_X(4), PRE_Y(4), PRE_Z(4), a, p);
    add_points_jacobi(PRE_X(3),
                      PRE_Y(3),
                      PRE_Z(3),
                      PRE_X(1),
                      PRE_Y(1),
                      PRE_Z(1),
                      PRE_X(2),
                      PRE_Y(2),
                      PRE_Z(2),
                      p);
    add_points_jacobi(PRE_X(5),
                      PRE_Y(5),
                      PRE_Z(5),
                      PRE_X(1),
                      PRE_Y(1),
                      PRE_Z(1),
                      PRE_X(4),
                      PRE_Y(4),
                      PRE_Z(4),
                      p);
    double_point_jacobi(
        PRE_X(6), PRE_Y(6), PRE_Z(6), PRE_X(3), PRE_Y(3), PRE_Z(3), a, p);
    add_points_jacobi(PRE_X(7),
                      PRE_Y(7),
                      PRE_Z(7),
                      PRE_X(1),
                      PRE_Y(1),
                      PRE_Z(1),
                      PRE_X(6),
                      PRE_Y(6),
                      PRE_Z(6),
                      p);
    add_points_jacobi(PRE_X(9),
                      PRE_Y(9),
                      PRE_Z(9),
                      PRE_X(1),
                      PRE_Y(1),
                      PRE_Z(1),
                      PRE_X(8),
                      PRE_Y(8),
                      PRE_Z(8),
                      p);
    double_point_jacobi(
        PRE_X(10), PRE_Y(10), PRE_Z(10), PRE_X(5), PRE_Y(5), PRE_Z(5), a, p);
    add_points_jacobi(PRE_X(11),
                      PRE_Y(11),
                      PRE_Z(11),
                      PRE_X(1),
                      PRE_Y(1),
                      PRE_Z(1),
                      PRE_X(10),
                      PRE_Y(10),
                      PRE_Z(10),
                      p);
    double_point_jacobi(
        PRE_X(12), PRE_Y(12), PRE_Z(12), PRE_X(6), PRE_Y(6), PRE_Z(6), a, p);
    add_points_jacobi(PRE_X(13),
                      PRE_Y(13),
                      PRE_Z(13),
                      PRE_X(1),
                      PRE_Y(1),
                      PRE_Z(1),
                      PRE_X(12),
                      PRE_Y(12),
                      PRE_Z(12),
                      p);
    double_point_jacobi(
        PRE_X(14), PRE_Y(14), PRE_Z(14), PRE_X(7), PRE_Y(7), PRE_Z(7), a, p);
    add_points_jacobi(PRE_X(15),
                      PRE_Y(15),
                      PRE_Z(15),
                      PRE_X(1),
                      PRE_Y(1),
                      PRE_Z(1),
                      PRE_X(14),
                      PRE_Y(14),
                      PRE_Z(14),
                      p);

    TEE_BigInt tmp_buffer[2 * 3 * number_size];
    for(uint_fast8_t k = 0; k < 6; ++k)
    {
        TEE_BigIntInit(tmp_buffer + k * number_size, number_size);
    }
    TEE_BigInt* tmp1 = tmp_buffer;
    TEE_BigInt* tmp2 = tmp_buffer + 3 * number_size;
    TEE_BigInt* t;
    int         w = scalar[0] >> 4;
    TEE_BigIntAssign(tmp1, PRE_X(w));
    TEE_BigIntAssign(tmp1 + number_size, PRE_Y(w));
    TEE_BigIntAssign(tmp1 + 2 * number_size, PRE_Z(w));

    // Double four times, then add the appropriate pre-computed multiple.
    for(int k = 1; k < 2 * scalar_size; ++k)
    {
        double_point_jacobi(tmp2,
                            tmp2 + number_size,
                            tmp2 + 2 * number_size,
                            tmp1,
                            tmp1 + number_size,
                            tmp1 + 2 * number_size,
                            a,
                            p);
        double_point_jacobi(tmp1,
                            tmp1 + number_size,
                            tmp1 + 2 * number_size,
                            tmp2,
                            tmp2 + number_size,
                            tmp2 + 2 * number_size,
                            a,
                            p);
        double_point_jacobi(tmp2,
                            tmp2 + number_size,
                            tmp2 + 2 * number_size,
                            tmp1,
                            tmp1 + number_size,
                            tmp1 + 2 * number_size,
                            a,
                            p);
        double_point_jacobi(tmp1,
                            tmp1 + number_size,
                            tmp1 + 2 * number_size,
                            tmp2,
                            tmp2 + number_size,
                            tmp2 + 2 * number_size,
                            a,
                            p);
        w = scalar[k >> 1];
        if(k & 1)
        {
            w &= 0xf;
        }
        else
        {
            w >>= 4;
        }
        add_points_jacobi(tmp2,
                        tmp2 + number_size,
                        tmp2 + 2 * number_size,
                        tmp1,
                        tmp1 + number_size,
                        tmp1 + 2 * number_size,
                        PRE_X(w),
                        PRE_Y(w),
                        PRE_Z(w),
                        p);
        // Swap tmp1, tmp2.
        t    = tmp1;
        tmp1 = tmp2;
        tmp2 = t;
    }
    TEE_BigIntAssign(x3, tmp1);
    TEE_BigIntAssign(y3, tmp1 + number_size);
    TEE_BigIntAssign(z3, tmp1 + 2 * number_size);

#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("    x3 = 0x");
    printf_bigint(x3);
    printf("\n    y3 = 0x");
    printf_bigint(y3);
    printf("\n    z3 = 0x");
    printf_bigint(z3);
    printf("\n");
#  endif
}

static void jacobi_to_affine(TEE_BigInt*       x3,
                             TEE_BigInt*       y3,
                             const TEE_BigInt* x1,
                             const TEE_BigInt* y1,
                             const TEE_BigInt* z1,
                             const TEE_BigInt* p)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("jacobi_to_affine\n");
#  endif
    size_t     number_size = TEE_BigIntSizeInU32(TEE_BigIntGetBitCount(p));
    TEE_BigInt zi[number_size];
    TEE_BigIntInit(zi, number_size);
    TEE_BigInt pm2[number_size];
    TEE_BigIntInit(pm2, number_size);

    const size_t fmm_ctx_size =
        TEE_BigIntFMMContextSizeInU32(TEE_BigIntGetBitCount(p));
    uint32_t fmm_ctx[fmm_ctx_size];
    TEE_BigIntInitFMMContext1((TEE_BigIntFMMContext*)fmm_ctx, fmm_ctx_size, p);

    TEE_BigIntConvertFromS32(pm2, 2);
    TEE_BigIntSub(pm2, p, pm2);  // pm2 <- p-2
    TEE_BigIntExpMod(
        zi, z1, pm2, p, (TEE_BigIntFMMContext*)fmm_ctx);  // Use Fermat for inversion.
    TEE_BigIntMulMod(pm2, zi, zi, p);                     // pm2 <- zi^2
    TEE_BigIntMulMod(x3, x1, pm2, p);
    TEE_BigIntMulMod(pm2, pm2, zi, p);  // pm2 <- zi^3
    TEE_BigIntMulMod(y3, y1, pm2, p);
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("    return\n");
#  endif
}

LIB_EXPORT BOOL BnEccModMult(bigPoint   R,  // OUT: computed point
                             pointConst S,  // IN: point to multiply by 'd'
                             bigConst   d,  // IN: scalar for [d]S
                             bigCurve   E)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("BnEccModMult(%p, %p, %p, %p)\n", R, S, d, E);
#  endif

    if(S == 0)
    {
        S = CurveGetG(AccessCurveData(E));
    }

    // We assume that everything is sane and coordinates are < p and the
    // scalar is at most one word longer than p.
    const NUMBYTES buffer_size = sizeof(crypt_uword_t) * (BnGetSize(E->prime) + 1);
    BYTE           buffer[buffer_size];

    size_t         len = TEE_BigIntSizeInU32(BnGetSizeInBit(E->prime));
    TEE_BigInt     tee_p[len];
    TEE_BigIntInit(tee_p, len);
    TEE_BigInt tee_x1[len];
    TEE_BigIntInit(tee_x1, len);
    TEE_BigInt tee_y1[len];
    TEE_BigIntInit(tee_y1, len);
    TEE_BigInt tee_z1[len];
    TEE_BigIntInit(tee_z1, len);
    TEE_BigInt tee_x3[len];
    TEE_BigIntInit(tee_x3, len);
    TEE_BigInt tee_y3[len];
    TEE_BigIntInit(tee_y3, len);
    TEE_BigInt tee_z3[len];
    TEE_BigIntInit(tee_z3, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(E->a));
    TEE_BigInt tee_a[len];
    TEE_BigIntInit(tee_a, len);

    NUMBYTES size = BnGetSizeInBytes(E->prime);
    BnToBytes(E->prime, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_p, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(E->a);
    BnToBytes(E->a, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_a, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(S->x);
    BnToBytes(S->x, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_x1, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(S->y);
    BnToBytes(S->y, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_y1, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    TEE_BigIntConvertFromS32(tee_z1, 1);
    size = BnGetSizeInBytes(d);
    BnToBytes(d, buffer, &size);

    scalar_multiplication_jacobi(
        tee_x3, tee_y3, tee_z3, tee_x1, tee_y1, tee_z1, buffer, size, tee_a, tee_p);
    jacobi_to_affine(tee_x1, tee_y1, tee_x3, tee_y3, tee_z3, tee_p);

    size_t tee_size = buffer_size;
    TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_x1);
    VERIFY(BnFromBytes(R->x, buffer, tee_size));
    tee_size = buffer_size;
    TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_y1);
    VERIFY(BnFromBytes(R->y, buffer, tee_size));
    buffer[0] = 1;
    VERIFY(BnFromBytes(R->z, buffer, 1));
    return TRUE;
Error:
    return FALSE;
}

LIB_EXPORT BOOL BnEccModMult2(bigPoint   R,  // OUT: computed point
                              pointConst S,  // IN: optional point
                              bigConst   d,  // IN: scalar for [d]S or [d]G
                              pointConst Q,  // IN: second point
                              bigConst   u,  // IN: second scalar
                              bigCurve   E   // IN: curve
)
{
#  ifdef DEBUG_OUTPUT_TEE_MATH
    printf("BnEccModMult2\n");
#  endif
    // We assume that everything is sane and coordinates are < p and the
    // scalar is at most one word longer than p.
    const NUMBYTES buffer_size = sizeof(crypt_uword_t) * (BnGetSize(E->prime) + 1);
    BYTE           buffer[buffer_size];

    size_t         len = TEE_BigIntSizeInU32(BnGetSizeInBit(E->prime));
    TEE_BigInt     tee_p[len];
    TEE_BigIntInit(tee_p, len);
    TEE_BigInt tee_x1[len];
    TEE_BigIntInit(tee_x1, len);
    TEE_BigInt tee_y1[len];
    TEE_BigIntInit(tee_y1, len);
    TEE_BigInt tee_z1[len];
    TEE_BigIntInit(tee_z1, len);
    TEE_BigInt tee_x2[len];
    TEE_BigIntInit(tee_x2, len);
    TEE_BigInt tee_y2[len];
    TEE_BigIntInit(tee_y2, len);
    TEE_BigInt tee_z2[len];
    TEE_BigIntInit(tee_z2, len);
    TEE_BigInt tee_x3[len];
    TEE_BigIntInit(tee_x3, len);
    TEE_BigInt tee_y3[len];
    TEE_BigIntInit(tee_y3, len);
    TEE_BigInt tee_z3[len];
    TEE_BigIntInit(tee_z3, len);

    len = TEE_BigIntSizeInU32(BnGetSizeInBit(E->a));
    TEE_BigInt tee_a[len];
    TEE_BigIntInit(tee_a, len);

    NUMBYTES size = BnGetSizeInBytes(E->prime);
    BnToBytes(E->prime, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_p, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(E->a);
    BnToBytes(E->a, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_a, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(S->x);
    BnToBytes(S->x, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_x1, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(S->y);
    BnToBytes(S->y, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_y1, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    TEE_BigIntConvertFromS32(tee_z1, 1);
    size = BnGetSizeInBytes(d);
    BnToBytes(d, buffer, &size);
    size = BnGetSizeInBytes(Q->x);
    BnToBytes(Q->x, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_x2, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    size = BnGetSizeInBytes(Q->y);
    BnToBytes(Q->y, buffer, &size);
    TEE_BigIntConvertFromOctetString(
        tee_y2, buffer, size, 0);  /// @todo Check that all numbers are non-negative.
    TEE_BigIntConvertFromS32(tee_z2, 1);
    size = BnGetSizeInBytes(d);
    BnToBytes(d, buffer, &size);

    /// @todo Use a more efficient algorithm for multiple scalar multiplication.
    scalar_multiplication_jacobi(
        tee_x3, tee_y3, tee_z3, tee_x1, tee_y1, tee_z1, buffer, size, tee_a, tee_p);
    size = BnGetSizeInBytes(u);
    BnToBytes(u, buffer, &size);
    scalar_multiplication_jacobi(
        tee_x1, tee_y1, tee_z1, tee_x2, tee_y2, tee_z2, buffer, size, tee_a, tee_p);
    add_points_jacobi(tee_x2,
                      tee_y2,
                      tee_z2,
                      tee_x1,
                      tee_y1,
                      tee_z1,
                      tee_x3,
                      tee_y3,
                      tee_z3,
                      tee_p);
    jacobi_to_affine(tee_x1, tee_y1, tee_x2, tee_y2, tee_z2, tee_p);

    size_t tee_size = buffer_size;
    TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_x1);
    VERIFY(BnFromBytes(R->x, buffer, tee_size));
    tee_size = buffer_size;
    TEE_BigIntConvertToOctetString(buffer, &tee_size, tee_y1);
    VERIFY(BnFromBytes(R->y, buffer, tee_size));
    buffer[0] = 1;
    VERIFY(BnFromBytes(R->z, buffer, 1));
    return TRUE;
Error:
    return FALSE;
}
#endif
