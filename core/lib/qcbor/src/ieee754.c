// SPDX-License-Identifier: BSD-3-Clause
/* ==========================================================================
 * ieee754.c -- floating-point conversion between half, double & single-precision
 *
 * Copyright (c) 2018-2024, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created on 7/23/18
 * ========================================================================== */

/*
 * Include before QCBOR_DISABLE_PREFERRED_FLOAT is checked as
 * QCBOR_DISABLE_PREFERRED_FLOAT might be defined in qcbor/qcbor_common.h
 */
#include "qcbor/qcbor_common.h"

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

#include "ieee754.h"
#include <string.h> /* For memcpy() */


/*
 * This code has long lines and is easier to read because of
 * them. Some coding guidelines prefer 80 column lines (can they not
 * afford big displays?).
 *
 * This code works solely using shifts and masks and thus has no
 * dependency on any math libraries. It can even work if the CPU
 * doesn't have any floating-point support, though that isn't the most
 * useful thing to do.
 *
 * The memcpy() dependency is only for CopyFloatToUint32() and friends
 * which only is needed to avoid type punning when converting the
 * actual float bits to an unsigned value so the bit shifts and masks
 * can work.
 *
 * The references used to write this code:
 *
 *  IEEE 754-2008, particularly section 3.6 and 6.2.1
 *
 *  https://en.wikipedia.org/wiki/IEEE_754 and subordinate pages
 *
 *  https://stackoverflow.com/questions/19800415/why-does-ieee-754-reserve-so-many-nan-values
 *
 *  https://stackoverflow.com/questions/46073295/implicit-type-promotion-rules
 *
 *  https://stackoverflow.com/questions/589575/what-does-the-c-standard-state-the-size-of-int-long-type-to-be
 *
 * IEEE754_FloatToDouble(uint32_t uFloat) was created but is not
 * needed. It can be retrieved from github history if needed.
 */




/* ----- Half Precsion ----------- */
#define HALF_NUM_SIGNIFICAND_BITS (10)
#define HALF_NUM_EXPONENT_BITS    (5)
#define HALF_NUM_SIGN_BITS        (1)

#define HALF_SIGNIFICAND_SHIFT    (0)
#define HALF_EXPONENT_SHIFT       (HALF_NUM_SIGNIFICAND_BITS)
#define HALF_SIGN_SHIFT           (HALF_NUM_SIGNIFICAND_BITS + HALF_NUM_EXPONENT_BITS)

#define HALF_SIGNIFICAND_MASK     (0x3ffU) // The lower 10 bits
#define HALF_EXPONENT_MASK        (0x1fU << HALF_EXPONENT_SHIFT) // 0x7c00 5 bits of exponent
#define HALF_SIGN_MASK            (0x01U << HALF_SIGN_SHIFT) // 0x8000 1 bit of sign
#define HALF_QUIET_NAN_BIT        (0x01U << (HALF_NUM_SIGNIFICAND_BITS-1)) // 0x0200

/* Biased    Biased    Unbiased   Use
 *  0x00       0        -15       0 and subnormal
 *  0x01       1        -14       Smallest normal exponent
 *  0x1e      30         15       Largest normal exponent
 *  0x1F      31         16       NaN and Infinity  */
#define HALF_EXPONENT_BIAS        (15)
#define HALF_EXPONENT_MAX         (HALF_EXPONENT_BIAS)    //  15 Unbiased
#define HALF_EXPONENT_MIN         (-HALF_EXPONENT_BIAS+1) // -14 Unbiased
#define HALF_EXPONENT_ZERO        (-HALF_EXPONENT_BIAS)   // -15 Unbiased
#define HALF_EXPONENT_INF_OR_NAN  (HALF_EXPONENT_BIAS+1)  //  16 Unbiased


/* ------ Single-Precision -------- */
#define SINGLE_NUM_SIGNIFICAND_BITS (23)
#define SINGLE_NUM_EXPONENT_BITS    (8)
#define SINGLE_NUM_SIGN_BITS        (1)

#define SINGLE_SIGNIFICAND_SHIFT    (0)
#define SINGLE_EXPONENT_SHIFT       (SINGLE_NUM_SIGNIFICAND_BITS)
#define SINGLE_SIGN_SHIFT           (SINGLE_NUM_SIGNIFICAND_BITS + SINGLE_NUM_EXPONENT_BITS)

#define SINGLE_SIGNIFICAND_MASK     (0x7fffffU) // The lower 23 bits
#define SINGLE_EXPONENT_MASK        (0xffU << SINGLE_EXPONENT_SHIFT) // 8 bits of exponent
#define SINGLE_SIGN_MASK            (0x01U << SINGLE_SIGN_SHIFT) // 1 bit of sign
#define SINGLE_QUIET_NAN_BIT        (0x01U << (SINGLE_NUM_SIGNIFICAND_BITS-1))

/* Biased  Biased   Unbiased  Use
 *  0x0000     0     -127      0 and subnormal
 *  0x0001     1     -126      Smallest normal exponent
 *  0x7f     127        0      1
 *  0xfe     254      127      Largest normal exponent
 *  0xff     255      128      NaN and Infinity  */
#define SINGLE_EXPONENT_BIAS        (127)
#define SINGLE_EXPONENT_MAX         (SINGLE_EXPONENT_BIAS)
#define SINGLE_EXPONENT_MIN         (-SINGLE_EXPONENT_BIAS+1)
#define SINGLE_EXPONENT_ZERO        (-SINGLE_EXPONENT_BIAS)
#define SINGLE_EXPONENT_INF_OR_NAN  (SINGLE_EXPONENT_BIAS+1)


/* --------- Double-Precision ---------- */
#define DOUBLE_NUM_SIGNIFICAND_BITS (52)
#define DOUBLE_NUM_EXPONENT_BITS    (11)
#define DOUBLE_NUM_SIGN_BITS        (1)

#define DOUBLE_SIGNIFICAND_SHIFT    (0)
#define DOUBLE_EXPONENT_SHIFT       (DOUBLE_NUM_SIGNIFICAND_BITS)
#define DOUBLE_SIGN_SHIFT           (DOUBLE_NUM_SIGNIFICAND_BITS + DOUBLE_NUM_EXPONENT_BITS)

#define DOUBLE_SIGNIFICAND_MASK     (0xfffffffffffffULL) // The lower 52 bits
#define DOUBLE_EXPONENT_MASK        (0x7ffULL << DOUBLE_EXPONENT_SHIFT) // 11 bits of exponent
#define DOUBLE_SIGN_MASK            (0x01ULL << DOUBLE_SIGN_SHIFT) // 1 bit of sign
#define DOUBLE_QUIET_NAN_BIT        (0x01ULL << (DOUBLE_NUM_SIGNIFICAND_BITS-1))


/* Biased      Biased   Unbiased  Use
 * 0x00000000     0     -1023     0 and subnormal
 * 0x00000001     1     -1022     Smallest normal exponent
 * 0x000007fe  2046      1023     Largest normal exponent
 * 0x000007ff  2047      1024     NaN and Infinity  */
#define DOUBLE_EXPONENT_BIAS        (1023)
#define DOUBLE_EXPONENT_MAX         (DOUBLE_EXPONENT_BIAS)
#define DOUBLE_EXPONENT_MIN         (-DOUBLE_EXPONENT_BIAS+1)
#define DOUBLE_EXPONENT_ZERO        (-DOUBLE_EXPONENT_BIAS)
#define DOUBLE_EXPONENT_INF_OR_NAN  (DOUBLE_EXPONENT_BIAS+1)




/*
 * Convenient functions to avoid type punning, compiler warnings and
 * such. The optimizer reduces them to a simple assignment. This is a
 * crusty corner of C. It shouldn't be this hard.
 *
 * These are also in UsefulBuf.h under a different name. They are copied
 * here to avoid a dependency on UsefulBuf.h. There is no object code
 * size impact because these always optimze down to a simple assignment.
 */
static inline uint32_t
CopyFloatToUint32(float f)
{
   uint32_t u32;
   memcpy(&u32, &f, sizeof(uint32_t));
   return u32;
}

static inline uint64_t
CopyDoubleToUint64(double d)
{
   uint64_t u64;
   memcpy(&u64, &d, sizeof(uint64_t));
   return u64;
}

static inline double
CopyUint64ToDouble(uint64_t u64)
{
   double d;
   memcpy(&d, &u64, sizeof(uint64_t));
   return d;
}

static inline float
CopyUint32ToSingle(uint32_t u32)
{
   float f;
   memcpy(&f, &u32, sizeof(uint32_t));
   return f;
}




/**
 * @brief Assemble sign, significand and exponent into single precision float.
 *
 * @param[in] uDoubleSign              0 if positive, 1 if negative
 * @pararm[in] uDoubleSignificand      Bits of the significand
 * @param[in] nDoubleUnBiasedExponent  Exponent
 *
 * This returns the bits for a single-precision float, a binary64
 * as specified in IEEE754.
 */
static double
IEEE754_AssembleDouble(uint64_t uDoubleSign,
                       uint64_t uDoubleSignificand,
                       int64_t  nDoubleUnBiasedExponent)
{
   uint64_t uDoubleBiasedExponent;

   uDoubleBiasedExponent = (uint64_t)(nDoubleUnBiasedExponent + DOUBLE_EXPONENT_BIAS);

   return CopyUint64ToDouble(uDoubleSignificand |
                             (uDoubleBiasedExponent << DOUBLE_EXPONENT_SHIFT) |
                             (uDoubleSign << DOUBLE_SIGN_SHIFT));
}


double
IEEE754_HalfToDouble(uint16_t uHalfPrecision)
{
   uint64_t uDoubleSignificand;
   int64_t  nDoubleUnBiasedExponent;
   double   dResult;

   /* Pull out the three parts of the half-precision float.  Do all
    * the work in 64 bits because that is what the end result is.  It
    * may give smaller code size and will keep static analyzers
    * happier.
    */
   const uint64_t uHalfSignificand      = uHalfPrecision & HALF_SIGNIFICAND_MASK;
   const uint64_t uHalfBiasedExponent   = (uHalfPrecision & HALF_EXPONENT_MASK) >> HALF_EXPONENT_SHIFT;
   const int64_t  nHalfUnBiasedExponent = (int64_t)uHalfBiasedExponent - HALF_EXPONENT_BIAS;
   const uint64_t uHalfSign             = (uHalfPrecision & HALF_SIGN_MASK) >> HALF_SIGN_SHIFT;

   if(nHalfUnBiasedExponent == HALF_EXPONENT_ZERO) {
      /* 0 or subnormal */
      if(uHalfSignificand) {
         /* --- SUBNORMAL --- */
         /* A half-precision subnormal can always be converted to a
          * normal double-precision float because the ranges line up.
          * The exponent of a subnormal starts out at the min exponent
          * for a normal. As the sub normal significand bits are
          * shifted, left to normalize, the exponent is
          * decremented. Shifting continues until fully normalized.
          */
          nDoubleUnBiasedExponent = HALF_EXPONENT_MIN;
          uDoubleSignificand      = uHalfSignificand;
          do {
             uDoubleSignificand <<= 1;
             nDoubleUnBiasedExponent--;
          } while ((uDoubleSignificand & (1ULL << HALF_NUM_SIGNIFICAND_BITS)) == 0);
          /* A normal has an implied 1 in the most significant
           * position that a subnormal doesn't. */
          uDoubleSignificand -= 1ULL << HALF_NUM_SIGNIFICAND_BITS;
          /* Must shift into place for a double significand */
          uDoubleSignificand <<= DOUBLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS;

          dResult = IEEE754_AssembleDouble(uHalfSign,
                                           uDoubleSignificand,
                                           nDoubleUnBiasedExponent);
      } else {
         /* --- ZERO --- */
         dResult = IEEE754_AssembleDouble(uHalfSign,
                                          0,
                                          DOUBLE_EXPONENT_ZERO);
      }
   } else if(nHalfUnBiasedExponent == HALF_EXPONENT_INF_OR_NAN) {
      /* NaN or Inifinity */
      if(uHalfSignificand) {
         /* --- NaN --- */
         /* Half-precision payloads always fit into double precision
          * payloads. They are shifted left the same as a normal
          * number significand.
          */
         uDoubleSignificand = uHalfSignificand << (DOUBLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);
         dResult = IEEE754_AssembleDouble(uHalfSign,
                                          uDoubleSignificand,
                                          DOUBLE_EXPONENT_INF_OR_NAN);
      } else {
         /* --- INFINITY --- */
         dResult = IEEE754_AssembleDouble(uHalfSign,
                                          0,
                                          DOUBLE_EXPONENT_INF_OR_NAN);
      }
   } else {
      /* --- NORMAL NUMBER --- */
      uDoubleSignificand = uHalfSignificand << (DOUBLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);
      dResult = IEEE754_AssembleDouble(uHalfSign,
                                       uDoubleSignificand,
                                       nHalfUnBiasedExponent);
   }

   return dResult;
}


/**
 * @brief Assemble sign, significand and exponent into single precision float.
 *
 * @param[in] uHalfSign              0 if positive, 1 if negative
 * @pararm[in] uHalfSignificand      Bits of the significand
 * @param[in] nHalfUnBiasedExponent  Exponent
 *
 * This returns the bits for a single-precision float, a binary32 as
 * specified in IEEE754. It is returned as a uint64_t rather than a
 * uint32_t or a float for convenience of usage.
 */
static uint32_t
IEEE754_AssembleHalf(uint32_t uHalfSign,
                     uint32_t uHalfSignificand,
                     int32_t nHalfUnBiasedExponent)
{
   uint32_t uHalfUnbiasedExponent;

   uHalfUnbiasedExponent = (uint32_t)(nHalfUnBiasedExponent + HALF_EXPONENT_BIAS);

   return uHalfSignificand |
          (uHalfUnbiasedExponent << HALF_EXPONENT_SHIFT) |
          (uHalfSign << HALF_SIGN_SHIFT);
}


/*  Public function; see ieee754.h */
IEEE754_union
IEEE754_SingleToHalf(float f)
{
   IEEE754_union result;
   uint32_t      uDroppedBits;
   int32_t       nExponentDifference;
   int32_t       nShiftAmount;
   uint32_t      uHalfSignificand;

   /* Pull the three parts out of the double-precision float Most work
    * is done with uint32_t which helps avoid integer promotions and
    * static analyzer complaints.
    */
   const uint32_t uSingle                 = CopyFloatToUint32(f);
   const uint32_t uSingleBiasedExponent   = (uSingle & SINGLE_EXPONENT_MASK) >> SINGLE_EXPONENT_SHIFT;
   const int32_t  nSingleUnbiasedExponent = (int32_t)uSingleBiasedExponent - SINGLE_EXPONENT_BIAS;
   const uint32_t uSingleSignificand      = uSingle & SINGLE_SIGNIFICAND_MASK;
   const uint32_t uSingleSign             = (uSingle & SINGLE_SIGN_MASK) >> SINGLE_SIGN_SHIFT;

   if(nSingleUnbiasedExponent == SINGLE_EXPONENT_ZERO) {
      if(uSingleSignificand == 0) {
         /* --- IS ZERO --- */
         result.uSize  = IEEE754_UNION_IS_HALF;
         result.uValue = IEEE754_AssembleHalf(uSingleSign,
                                              0,
                                              HALF_EXPONENT_ZERO);
      } else {
         /* --- IS SINGLE SUBNORMAL --- */
         /* The largest single subnormal is slightly less than the
          * largest single normal which is 2^-149 or
          * 2.2040517676619426e-38.  The smallest half subnormal is
          * 2^-14 or 5.9604644775390625E-8.  There is no overlap so
          * single subnormals can't be converted to halfs of any sort.
          */
         result.uSize   = IEEE754_UNION_IS_SINGLE;
         result.uValue  = uSingle;
      }
   } else if(nSingleUnbiasedExponent == SINGLE_EXPONENT_INF_OR_NAN) {
      if(uSingleSignificand == 0) {
         /* ---- IS INFINITY ---- */
         result.uSize  = IEEE754_UNION_IS_HALF;
         result.uValue = IEEE754_AssembleHalf(uSingleSign, 0, HALF_EXPONENT_INF_OR_NAN);
      } else {
         /* The NaN can only be converted if no payload bits are lost
          * per RFC 8949 section 4.1 that defines Preferred
          * Serializaton. Note that Deterministically Encode CBOR in
          * section 4.2 allows for some variation of this rule, but at
          * the moment this implementation is of Preferred
          * Serialization, not CDE. As of December 2023, we are also
          * expecting an update to CDE. This code may need to be
          * updated for CDE.
          */
         uDroppedBits = uSingleSignificand & (SINGLE_SIGNIFICAND_MASK >> HALF_NUM_SIGNIFICAND_BITS);
         if(uDroppedBits == 0) {
            /* --- IS CONVERTABLE NAN --- */
            uHalfSignificand = uSingleSignificand >> (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);
            result.uSize  = IEEE754_UNION_IS_HALF;
            result.uValue = IEEE754_AssembleHalf(uSingleSign,
                                                 uHalfSignificand,
                                                 HALF_EXPONENT_INF_OR_NAN);

         } else {
            /* --- IS UNCONVERTABLE NAN --- */
            result.uSize   = IEEE754_UNION_IS_SINGLE;
            result.uValue  = uSingle;
         }
      }
   } else {
      /* ---- REGULAR NUMBER ---- */
      /* A regular single can be converted to a regular half if the
       * single's exponent is in the smaller range of a half and if no
       * precision is lost in the significand.
       */
      if(nSingleUnbiasedExponent >= HALF_EXPONENT_MIN &&
         nSingleUnbiasedExponent <= HALF_EXPONENT_MAX &&
        (uSingleSignificand & (SINGLE_SIGNIFICAND_MASK >> HALF_NUM_SIGNIFICAND_BITS)) == 0) {
         uHalfSignificand = uSingleSignificand >> (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);

         /* --- CONVERT TO HALF NORMAL --- */
         result.uSize  = IEEE754_UNION_IS_HALF;
         result.uValue = IEEE754_AssembleHalf(uSingleSign,
                                              uHalfSignificand,
                                              nSingleUnbiasedExponent);
      } else {
         /* Unable to convert to a half normal. See if it can be
          * converted to a half subnormal. To do that, the exponent
          * must be in range and no precision can be lost in the
          * signficand.
          *
          * This is more complicated because the number is not
          * normalized.  The signficand must be shifted proprotionally
          * to the exponent and 1 must be added in.  See
          * https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Exponent_encoding
          *
          * Exponents -14 to -24 map to a shift of 0 to 10 of the
          * significand.  The largest value of a half subnormal has an
          * exponent of -14. Subnormals are not normalized like
          * normals meaning they lose precision as the numbers get
          * smaller. Normals don't lose precision because the exponent
          * allows all the bits of the significand to be significant.
          */
         /* The exponent of the largest possible half-precision
          * subnormal is HALF_EXPONENT_MIN (-14).  Exponents larger
          * than this are normal and handled above. We're going to
          * shift the significand right by at least this amount.
          */
         nExponentDifference = -(nSingleUnbiasedExponent - HALF_EXPONENT_MIN);

         /* In addition to the shift based on the exponent's value,
          * the single significand has to be shifted right to fit into
          * a half-precision significand */
         nShiftAmount = nExponentDifference + (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);

         /* Must add 1 in to the possible significand because there is
          * an implied 1 for normal values and not for subnormal
          * values. See equations here:
          * https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Exponent_encoding
          */
         uHalfSignificand = (uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;

         /* If only zero bits get shifted out, this can be converted
          * to subnormal */
         if(nSingleUnbiasedExponent < HALF_EXPONENT_MIN &&
            nSingleUnbiasedExponent >= HALF_EXPONENT_MIN - HALF_NUM_SIGNIFICAND_BITS &&
            uHalfSignificand << nShiftAmount == uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) {
            /* --- CONVERTABLE TO HALF SUBNORMAL --- */
            result.uSize  = IEEE754_UNION_IS_HALF;
            result.uValue = IEEE754_AssembleHalf(uSingleSign,
                                                 uHalfSignificand,
                                                 HALF_EXPONENT_ZERO);
         } else {
            /* --- DO NOT CONVERT --- */
            result.uSize   = IEEE754_UNION_IS_SINGLE;
            result.uValue  = uSingle;
         }
      }
   }

   return result;
}


/**
 * @brief Assemble sign, significand and exponent into single precision float.
 *
 * @param[in] uSingleSign              0 if positive, 1 if negative
 * @pararm[in] uSingleSignificand      Bits of the significand
 * @param[in] nSingleUnBiasedExponent  Exponent
 *
 * This returns the bits for a single-precision float, a binary32 as
 * specified in IEEE754. It is returned as a uint64_t rather than a
 * uint32_t or a float for convenience of usage.
 */
static uint64_t
IEEE754_AssembleSingle(uint64_t uSingleSign,
                       uint64_t uSingleSignificand,
                       int64_t  nSingleUnBiasedExponent)
{
   uint64_t uSingleBiasedExponent;

   uSingleBiasedExponent = (uint64_t)(nSingleUnBiasedExponent + SINGLE_EXPONENT_BIAS);

   return uSingleSignificand |
          (uSingleBiasedExponent << SINGLE_EXPONENT_SHIFT) |
          (uSingleSign << SINGLE_SIGN_SHIFT);
}


/**
 * @brief Convert a double-precision float to single-precision.
 *
 * @param[in] d  The value to convert.
 *
 * @returns Either unconverted value or value converted to single-precision.
 *
 * This always succeeds. If the value cannot be converted without the
 * loss of precision, it is not converted.
 *
 * This handles all subnormals and NaN payloads.
 */
static IEEE754_union
IEEE754_DoubleToSingle(double d)
{
   IEEE754_union Result;
   int64_t       nExponentDifference;
   int64_t       nShiftAmount;
   uint64_t      uSingleSignificand;
   uint64_t      uDroppedBits;


   /* Pull the three parts out of the double-precision float. Most
    * work is done with uint64_t which helps avoid integer promotions
    * and static analyzer complaints.
    */
   const uint64_t uDouble                 = CopyDoubleToUint64(d);
   const uint64_t uDoubleBiasedExponent   = (uDouble & DOUBLE_EXPONENT_MASK) >> DOUBLE_EXPONENT_SHIFT;
   const int64_t  nDoubleUnbiasedExponent = (int64_t)uDoubleBiasedExponent - DOUBLE_EXPONENT_BIAS;
   const uint64_t uDoubleSign             = (uDouble & DOUBLE_SIGN_MASK) >> DOUBLE_SIGN_SHIFT;
   const uint64_t uDoubleSignificand      = uDouble & DOUBLE_SIGNIFICAND_MASK;


    if(nDoubleUnbiasedExponent == DOUBLE_EXPONENT_ZERO) {
        if(uDoubleSignificand == 0) {
            /* --- IS ZERO --- */
            Result.uSize  = IEEE754_UNION_IS_SINGLE;
            Result.uValue = IEEE754_AssembleSingle(uDoubleSign,
                                                   0,
                                                   SINGLE_EXPONENT_ZERO);
        } else {
            /* --- IS DOUBLE SUBNORMAL --- */
            /* The largest double subnormal is slightly less than the
             * largest double normal which is 2^-1022 or
             * 2.2250738585072014e-308.  The smallest single subnormal
             * is 2^-149 or 1.401298464324817e-45.  There is no
             * overlap so double subnormals can't be converted to
             * singles of any sort.
             */
            Result.uSize   = IEEE754_UNION_IS_DOUBLE;
            Result.uValue  = uDouble;
         }
    } else if(nDoubleUnbiasedExponent == DOUBLE_EXPONENT_INF_OR_NAN) {
         if(uDoubleSignificand == 0) {
             /* ---- IS INFINITY ---- */
             Result.uSize  = IEEE754_UNION_IS_SINGLE;
             Result.uValue = IEEE754_AssembleSingle(uDoubleSign,
                                                    0,
                                                    SINGLE_EXPONENT_INF_OR_NAN);
         } else {
             /* The NaN can only be converted if no payload bits are
              * lost per RFC 8949 section 4.1 that defines Preferred
              * Serializaton. Note that Deterministically Encode CBOR
              * in section 4.2 allows for some variation of this rule,
              * but at the moment this implementation is of Preferred
              * Serialization, not CDE. As of December 2023, we are
              * also expecting an update to CDE. This code may need to
              * be updated for CDE.
              */
             uDroppedBits = uDoubleSignificand & (DOUBLE_SIGNIFICAND_MASK >> SINGLE_NUM_SIGNIFICAND_BITS);
             if(uDroppedBits == 0) {
                /* --- IS CONVERTABLE NAN --- */
                uSingleSignificand = uDoubleSignificand >> (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS);
                Result.uSize  = IEEE754_UNION_IS_SINGLE;
                Result.uValue = IEEE754_AssembleSingle(uDoubleSign,
                                                       uSingleSignificand,
                                                       SINGLE_EXPONENT_INF_OR_NAN);
            } else {
               /* --- IS UNCONVERTABLE NAN --- */
               Result.uSize   = IEEE754_UNION_IS_DOUBLE;
               Result.uValue  = uDouble;
            }
         }
    } else {
        /* ---- REGULAR NUMBER ---- */
        /* A regular double can be converted to a regular single if
         * the double's exponent is in the smaller range of a single
         * and if no precision is lost in the significand.
         */
        uDroppedBits = uDoubleSignificand & (DOUBLE_SIGNIFICAND_MASK >> SINGLE_NUM_SIGNIFICAND_BITS);
        if(nDoubleUnbiasedExponent >= SINGLE_EXPONENT_MIN &&
           nDoubleUnbiasedExponent <= SINGLE_EXPONENT_MAX &&
           uDroppedBits == 0) {
            /* --- IS CONVERTABLE TO SINGLE --- */
            uSingleSignificand = uDoubleSignificand >> (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS);
            Result.uSize  = IEEE754_UNION_IS_SINGLE;
            Result.uValue = IEEE754_AssembleSingle(uDoubleSign,
                                                   uSingleSignificand,
                                                   nDoubleUnbiasedExponent);
        } else {
            /* Unable to convert to a single normal. See if it can be
             * converted to a single subnormal. To do that, the
             * exponent must be in range and no precision can be lost
             * in the signficand.
             *
             * This is more complicated because the number is not
             * normalized.  The signficand must be shifted
             * proprotionally to the exponent and 1 must be added
             * in. See
             * https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Exponent_encoding
             */
            nExponentDifference = -(nDoubleUnbiasedExponent - SINGLE_EXPONENT_MIN);
            nShiftAmount        = nExponentDifference + (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS);
            uSingleSignificand  = (uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;

            if(nDoubleUnbiasedExponent < SINGLE_EXPONENT_MIN &&
               nDoubleUnbiasedExponent >= SINGLE_EXPONENT_MIN - SINGLE_NUM_SIGNIFICAND_BITS &&
               uSingleSignificand << nShiftAmount == uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) {
               /* --- IS CONVERTABLE TO SINGLE SUBNORMAL --- */
               Result.uSize  = IEEE754_UNION_IS_SINGLE;
               Result.uValue = IEEE754_AssembleSingle(uDoubleSign,
                                                      uSingleSignificand,
                                                      SINGLE_EXPONENT_ZERO);
            } else {
               /* --- CAN NOT BE CONVERTED --- */
               Result.uSize   = IEEE754_UNION_IS_DOUBLE;
               Result.uValue  = uDouble;
            }
        }
    }

    return Result;
}


/* Public function; see ieee754.h */
IEEE754_union
IEEE754_DoubleToSmaller(double d, int bAllowHalfPrecision)
{
   IEEE754_union result;

   result = IEEE754_DoubleToSingle(d);

   if(result.uSize == IEEE754_UNION_IS_SINGLE && bAllowHalfPrecision) {
      /* Cast to uint32_t is OK, because value was just successfully
       * converted to single. */
      float uSingle = CopyUint32ToSingle((uint32_t)result.uValue);
      result = IEEE754_SingleToHalf(uSingle);
   }

   return result;
}


#else /* QCBOR_DISABLE_PREFERRED_FLOAT */

int ieee754_dummy_place_holder;

#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
