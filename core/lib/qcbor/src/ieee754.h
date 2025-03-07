// SPDX-License-Identifier: BSD-3-Clause
/* ==========================================================================
 * ieee754.h -- Conversion between half, double & single-precision floats
 *
 * Copyright (c) 2018-2024, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created on 7/23/18
 * ========================================================================== */

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

#ifndef ieee754_h
#define ieee754_h

#include <stdint.h>


/** @file ieee754.h
 *
 * This implements floating-point conversion between half, single and
 * double precision floating-point numbers, in particular convesion to
 * smaller representation (e.g., double to single) that does not lose
 * precision for CBOR preferred serialization.
 *
 * This implementation works entirely with shifts and masks and does
 * not require any floating-point HW or library.
 *
 * This conforms to IEEE 754-2008, but note that it doesn't specify
 * conversions, just the encodings.
 *
 * This is complete, supporting +/- infinity, +/- zero, subnormals and
 * NaN payloads. NaN payloads are converted to smaller by dropping the
 * right most bits if they are zero and shifting to the right. If the
 * rightmost bits are not zero the conversion is not performed. When
 * converting from smaller to larger, the payload is shifted left and
 * zero-padded. This is what is specified by CBOR preferred
 * serialization and what modern HW conversion instructions do. CBOR
 * CDE handling for NaN is not clearly specified, but upcoming
 * documents may clarify this.
 *
 * There is no special handling of silent and quiet NaNs. It probably
 * isn't necessary to transmit these special NaNs as there purpose is
 * more for propgating errors up through some calculation. In many
 * cases the handlng of the NaN payload will work for silent and quiet
 * NaNs.
 *
 * A previous version of this was usable as a general library for
 * conversion. This version is reduced to what is needed for CBOR.
 */


/**
 * @brief Convert half-precision float to double-precision float.
 *
 * @param[in] uHalfPrecision   Half-prevision number to convert.
 *
 * @returns double-presion value.
 *
 * This is a lossless conversion because every half-precision value
 * can be represented as a double. There is no error condition.
 *
 * There is no half-precision type in C, so it is represented here as
 * a @c uint16_t. The bits of @c uHalfPrecision are as described for
 * half-precision by IEEE 754.
 */
double
IEEE754_HalfToDouble(uint16_t uHalfPrecision);


/** Holds a floating-point value that could be half, single or
 * double-precision.  The value is in a @c uint64_t that may be copied
 * to a float or double.  Simply casting uValue will usually work but
 * may generate compiler or static analyzer warnings. Using
 * UsefulBufUtil_CopyUint64ToDouble() or
 * UsefulBufUtil_CopyUint32ToFloat() will not (and will not generate
 * any extra code).
 */
typedef struct {
   enum {IEEE754_UNION_IS_HALF   = 2,
         IEEE754_UNION_IS_SINGLE = 4,
         IEEE754_UNION_IS_DOUBLE = 8,
   } uSize; /* Size of uValue */
   uint64_t uValue;
} IEEE754_union;


/**
 * @brief Convert a double to either single or half-precision.
 *
 * @param[in] d                    The value to convert.
 * @param[in] bAllowHalfPrecision  If true, convert to either half or
 *                                 single precision.
 *
 * @returns Unconverted value, or value converted to single or half-precision.
 *
 * This always succeeds. If the value cannot be converted without the
 * loss of precision, it is not converted.
 *
 * This handles all subnormals and NaN payloads.
 */
IEEE754_union
IEEE754_DoubleToSmaller(double d, int bAllowHalfPrecision);


/**
 * @brief Convert a single-precision float to half-precision.
 *
 * @param[in] f  The value to convert.
 *
 * @returns Either unconverted value or value converted to half-precision.
 *
 * This always succeeds. If the value cannot be converted without the
 * loss of precision, it is not converted.
 *
 * This handles all subnormals and NaN payloads.
 */
IEEE754_union
IEEE754_SingleToHalf(float f);


#endif /* ieee754_h */

#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
