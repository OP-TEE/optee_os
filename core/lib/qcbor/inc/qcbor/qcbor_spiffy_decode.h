// SPDX-License-Identifier: BSD-3-Clause
/* ==========================================================================
 * qcbor_spiffy_decode.h -- higher-level easier-to-use CBOR decoding.
 *
 * Copyright (c) 2020-2024, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Forked from qcbor_decode.h on 7/23/2020
 * ========================================================================== */
#ifndef qcbor_spiffy_decode_h
#define qcbor_spiffy_decode_h


#include "qcbor/qcbor_decode.h"


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif


/**
 * @file qcbor_spiffy_decode.h
 *
 * @anchor SpiffyDecode
 * # Spiffy Decode
 *
 * This section discusses spiffy decoding assuming familiarity with
 * the general description of decoding in the
 * @ref BasicDecode section.
 *
 * Spiffy decode is extra decode features over and above the @ref
 * BasicDecode features that generally are easier to use, mirror the
 * encoding functions better and can result in smaller code size for
 * larger and more complex CBOR protocols.  In particular, spiffy
 * decode facilitates getting the next data item of a specific type,
 * setting an error if it is not of that type. It facilitates
 * explicitly entering and exiting arrays and maps. It facilates
 * fetching items by label from a map including duplicate label
 * detection.
 *
 * Encoded CBOR can be viewed to have a tree structure where the leaf
 * nodes are non-aggregate types like integers and strings and the
 * intermediate nodes are either arrays or maps. Fundamentally, all
 * decoding is a pre-order traversal of the tree. Calling
 * QCBORDecode_GetNext() repeatedly will perform this.
 *
 * This pre-order traversal gives natural decoding of arrays where the
 * array members are taken in order, but does not give natural decoding
 * of maps where access by label is usually preferred.  Using the
 * QCBORDecode_EnterMap() and QCBORDecode_GetXxxxInMapX() methods like
 * QCBORDecode_GetInt64InMapN(), map items can be accessed by
 * label. QCBORDecode_EnterMap() bounds decoding to a particular
 * map. QCBORDecode_GetXxxxInMapX() methods allows decoding the item of
 * a particular label in the particular map. This can be used with
 * nested maps by using QCBORDecode_EnterMapFromMapX().
 *
 * When QCBORDecode_EnterMap() is called, pre-order traversal
 * continues to work. There is a cursor that is run over the tree with
 * calls to QCBORDecode_GetNext(). Attempts to use
 * QCBORDecode_GetNext() beyond the end of the map will give the
 * @ref QCBOR_ERR_NO_MORE_ITEMS error.
 *
 * Use of the traversal cursor can be mixed with the fetching of items
 * by label with some caveats. When a non-aggregate item like an
 * integer or string is fetched by label, the traversal cursor is
 * unaffected so the mixing can be done freely.  When an aggregate
 * item is entered by label (by QCBORDecode_EnterMapFromMapN() and
 * similar), the traversal cursor is set to the item after the
 * subordinate aggregate item when it is exited. This will not matter
 * to many use cases. Use cases that mix can be sure to separate
 * traversal by the cursor from fetching by label.
 * QCBORDecode_Rewind() may be useful to reset the traversal cursor
 * after fetching aggregate items by label.
 *
 * (This behavior was incorrectly documented in QCBOR 1.2 and prior
 * which described aggregate and non-aggregate as behaving the same.
 * Rather than changing to make aggregate and non-aggregate
 * consistent, the behavior is retained and documented because 1) it
 * is usable as is, 2) a change would bring backward compatibility
 * issues, 3) the change would increase the decode context size and
 * code size.  In QCBOR 1.3 test cases were added to validate the
 * behavior. No problems were uncovered.)
 *
 * QCBORDecode_EnterArray() can be used to narrow the traversal to the
 * extent of the array.
 *
 * All the QCBORDecode_GetXxxxInMapX() methods support duplicate label
 * detection and will result in an error if the map has duplicate
 * labels.
 *
 * All the QCBORDecode_GetXxxxInMapX() methods are implemented by
 * performing the pre-order traversal of the map to find the labeled
 * item everytime it is called. It doesn't build up a hash table, a
 * binary search tree or some other efficiently searchable structure
 * internally. For small maps this is fine and for high-speed CPUs
 * this is fine, but for large, perhaps deeply nested, maps on slow
 * CPUs, it may have performance issues (these have not be
 * quantified). One way ease this is to use
 * QCBORDecode_GetItemsInMap() which allows decoding of a list of
 * items expected in an map in one traveral.
 *
 * @anchor Tag-Usage
 * ## Tag Usage
 *
 * Data types beyond the basic CBOR types of numbers, strings, maps and
 * arrays are called tags. The main registry of these new types is in
 * the IANA CBOR tags registry. These new types may be simple such a
 * number that is to be interpreted as a date, or of moderate complexity
 * such as defining a decimal fraction that is an array containing a
 * mantissa and exponent, or complex such as format for signing and
 * encryption.
 *
 * When a tag occurs in a protocol it is encoded as an integer tag
 * number plus the content of the tag.
 *
 * The content format of a tag may also be "borrowed". For example, a
 * protocol definition may say that a particular data item is an epoch
 * date just like tag 1, but not actually tag 1. In practice the
 * difference is the presence or absence of the integer tag number in
 * the encoded CBOR.
 *
 * The decoding functions for these new types takes a tag requirement
 * parameter to say whether the item is a tag, is just borrowing the
 * content format and is not a tag, or whether either is OK.
 *
 * If the parameter indicates the item must be a tag (@ref
 * QCBOR_TAG_REQUIREMENT_TAG), then @ref QCBOR_ERR_UNEXPECTED_TYPE is
 * set if it is not one of the expected tag types. To decode correctly
 * the contents of the tag must also be of the correct type. For
 * example, to decode an epoch date tag the content must be an integer
 * or floating-point value.
 *
 * If the parameter indicates it should not be a tag
 * (@ref  QCBOR_TAG_REQUIREMENT_NOT_A_TAG), then
 *  @ref QCBOR_ERR_UNEXPECTED_TYPE set if it is a tag or the type of the
 * encoded CBOR is not what is expected.  In the example of an epoch
 * date, the data type must be an integer or floating-point value. This
 * is the case where the content format of a tag is borrowed.
 *
 * The parameter can also indicate that either a tag or no tag is
 * allowed ( @ref QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG ).  A good protocol
 * design should however be clear and choose one or the other and not
 * need this option. This is a way to implement "be liberal in what you
 * accept", however these days that is less in favor. See
 * https://tools.ietf.org/id/draft-thomson-postel-was-wrong-03.html.
 *
 * Map searching works with indefinite length strings. A string
 * allocator must be set up the same as for any handling of indefinite
 * length strings.  However, It currently over-allocates memory from the
 * string pool and thus requires a much larger string pool than it
 * should. The over-allocation happens every time a map is searched by
 * label.  (This may be corrected in the future).
 */




/** The data item must be a tag of the expected type. It is an error
 *  if it is not. For example when calling QCBORDecode_GetEpochDate(),
 *  the data item must be an @ref CBOR_TAG_DATE_EPOCH tag.  See
 *  @ref Tag-Usage. */
#define QCBOR_TAG_REQUIREMENT_TAG 0

/** The data item must be of the type expected for content data type
 *  being fetched. It is an error if it is not. For example, when
 *  calling QCBORDecode_GetEpochDate() and it must not be an @ref
 *  CBOR_TAG_DATE_EPOCH tag. See @ref Tag-Usage. */
#define QCBOR_TAG_REQUIREMENT_NOT_A_TAG  1

/** Either of the above two are allowed. This allows implementation of
 *  being liberal in what you receive, but it is better if CBOR-based
 *  protocols pick one and stick to and not required the reciever to
 *  take either. See @ref Tag-Usage. */
#define QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG 2

/** Add this into the above value if other tags not processed by QCBOR
 *  are to be allowed to surround the data item. See @ref Tag-Usage. */
#define QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS 0x80




/** Conversion will proceed if the CBOR item to be decoded is an
 *  integer or either type 0 (unsigned) or type 1 (negative). */
#define QCBOR_CONVERT_TYPE_XINT64           0x01
/** Conversion will proceed if the CBOR item to be decoded is either
 *  double, single or half-precision floating-point (major type 7). */
#define QCBOR_CONVERT_TYPE_FLOAT            0x02
/** Conversion will proceed if the CBOR item to be decoded is a big
 *  number, positive or negative (tag 2 or tag 3). */
#define QCBOR_CONVERT_TYPE_BIG_NUM          0x04
/** Conversion will proceed if the CBOR item to be decoded is a
 *  decimal fraction (tag 4). */
#define QCBOR_CONVERT_TYPE_DECIMAL_FRACTION 0x08
/** Conversion will proceed if the CBOR item to be decoded is a big
 *  float (tag 5). */
#define QCBOR_CONVERT_TYPE_BIGFLOAT         0x10




/**
 * @brief Decode next item into a signed 64-bit integer.
 *
 * @param[in] pCtx      The decode context.
 * @param[out] pnValue  The returned 64-bit signed integer.
 *
 * The CBOR data item to decode must be a positive or negative integer
 * (CBOR major type 0 or 1). If not @ref QCBOR_ERR_UNEXPECTED_TYPE is set.
 *
 * If the CBOR integer is either too large or too small to fit in an
 * int64_t, the error @ref QCBOR_ERR_INT_OVERFLOW or
 * @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW is set.  Note that type 0
 * unsigned integers can be larger than will fit in an int64_t and
 * type 1 negative integers can be smaller than will fit in an
 * int64_t.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetUInt64(), QCBORDecode_GetInt64Convert(),
 * QCBORDecode_GetInt64ConvertAll() and QCBORDecode_GetDoubleConvert()
 */
static void
QCBORDecode_GetInt64(QCBORDecodeContext *pCtx,
                     int64_t            *pnValue);

static void
QCBORDecode_GetInt64InMapN(QCBORDecodeContext *pCtx,
                           int64_t             nLabel,
                           int64_t            *pnValue);

static void
QCBORDecode_GetInt64InMapSZ(QCBORDecodeContext *pCtx,
                            const char         *szLabel,
                            int64_t            *pnValue);


/**
 * @brief Decode next item into a signed 64-bit integer with basic conversions.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] pnValue       The returned 64-bit signed integer.
 *
 * @c uConvertTypes controls what conversions this will perform and
 * thus what CBOR types will be decoded.  @c uConvertType is a bit map
 * listing the conversions to be allowed. This function supports
 * @ref QCBOR_CONVERT_TYPE_XINT64 and @ref QCBOR_CONVERT_TYPE_FLOAT
 * conversions.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * If the CBOR data type can never be convered by this function or the
 * conversion was not selected in @c uConversionTypes
 * @ref QCBOR_ERR_UNEXPECTED_TYPE is set.
 *
 * When converting floating-point values, the integer is rounded to
 * the nearest integer using llround(). By default, floating-point
 * suport is enabled for QCBOR.
 *
 * If floating-point HW use is disabled this will set
 * @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision number is
 * encountered. If half-precision support is disabled, this will set
 * @ref QCBOR_ERR_HALF_PRECISION_DISABLED if a half-precision number
 * is encountered.
 *
 * If floating-point usage is disabled this will set
 * @ref QCBOR_ERR_ALL_FLOAT_DISABLED if a floating point value is
 * encountered.
 *
 * See also QCBORDecode_GetInt64ConvertAll() which will perform the
 * same conversions as this and a lot more at the cost of adding more
 * object code to your executable.
 */
static void
QCBORDecode_GetInt64Convert(QCBORDecodeContext *pCtx,
                            uint32_t            uConvertTypes,
                            int64_t            *pnValue);

static void
QCBORDecode_GetInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                  int64_t             nLabel,
                                  uint32_t            uConvertTypes,
                                  int64_t            *pnValue);

static void
QCBORDecode_GetInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                   const char         *szLabel,
                                   uint32_t            uConvertTypes,
                                   int64_t            *pnValue);


/**
 * @brief Decode next item into a signed 64-bit integer with conversions.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] pnValue       The returned 64-bit signed integer.
 *
 * This is the same as QCBORDecode_GetInt64Convert() but additionally
 * supports conversion from positive and negative bignums, decimal
 * fractions and big floats, including decimal fractions and big floats
 * that use bignums. The conversion types supported are
 * @ref QCBOR_CONVERT_TYPE_XINT64, @ref QCBOR_CONVERT_TYPE_FLOAT,
 * @ref QCBOR_CONVERT_TYPE_BIG_NUM,
 * @ref QCBOR_CONVERT_TYPE_DECIMAL_FRACTION and
 * @ref QCBOR_CONVERT_TYPE_BIGFLOAT.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * Note that most these types can support numbers much larger that can
 * be represented by in a 64-bit integer, so
 * @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW may often be encountered.
 *
 * When converting bignums and decimal fractions,
 * @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW will be set if the result
 * is below 1, unless the mantissa is zero, in which case the
 * coversion is successful and the value of 0 is returned.
 *
 * See also QCBORDecode_GetInt64ConvertAll() which does some of these
 * conversions, but links in much less object code. See also
 * QCBORDecode_GetUInt64ConvertAll().
 *
 * This relies on CBOR tags to identify big numbers, decimal fractions
 * and big floats. It will not attempt to decode non-tag CBOR that might
 * be one of these.  (If QCBOR_DISABLE_TAGS is set, this is effectively
 * the same as QCBORDecode_GetInt64Convert() because all the additional
 * number types this decodes are tags).
 */
void
QCBORDecode_GetInt64ConvertAll(QCBORDecodeContext *pCtx,
                               uint32_t            uConvertTypes,
                               int64_t            *pnValue);

void
QCBORDecode_GetInt64ConvertAllInMapN(QCBORDecodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint32_t            uConvertTypes,
                                     int64_t            *pnValue);

void
QCBORDecode_GetInt64ConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                      const char         *szLabel,
                                      uint32_t            uConvertTypes,
                                      int64_t            *pnValue);


/**
 * @brief Decode next item into an unsigned 64-bit integer.
 *
 * @param[in] pCtx      The decode context.
 * @param[out] puValue  The returned 64-bit unsigned integer.
 *
 * This is the same as QCBORDecode_GetInt64(), but returns an unsigned integer
 * and thus can only decode CBOR positive integers.
 * @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION is set if the input is a negative
 * integer.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetUInt64Convert() and QCBORDecode_GetUInt64ConvertAll().
 */
static void
QCBORDecode_GetUInt64(QCBORDecodeContext *pCtx,
                      uint64_t           *puValue);

static void
QCBORDecode_GetUInt64InMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            uint64_t           *puValue);

static void
QCBORDecode_GetUInt64InMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             uint64_t           *puValue);


/**
 * @brief Decode next item as an unsigned 64-bit integer with basic conversions.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] puValue       The returned 64-bit unsigned integer.
 *
 * This is the same as QCBORDecode_GetInt64Convert(), but returns an
 * unsigned integer and thus sets @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION
 * if the value to be decoded is negatve.
 *
 * If floating-point HW use is disabled this will set
 * @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision number is
 * encountered. If half-precision support is disabled, this will set
 * @ref QCBOR_ERR_HALF_PRECISION_DISABLED if a half-precision number
 * is encountered.
 *
 * If floating-point usage is disabled this will set
 * @ref QCBOR_ERR_ALL_FLOAT_DISABLED if a floating point value is
 * encountered.
 *
 * See also QCBORDecode_GetUInt64Convert() and
 * QCBORDecode_GetUInt64ConvertAll().
 */
static void
QCBORDecode_GetUInt64Convert(QCBORDecodeContext *pCtx,
                             uint32_t            uConvertTypes,
                             uint64_t           *puValue);

static void
QCBORDecode_GetUInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                   int64_t             nLabel,
                                   uint32_t            uConvertTypes,
                                   uint64_t           *puValue);

static void
QCBORDecode_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                    const char         *szLabel,
                                    uint32_t            uConvertTypes,
                                    uint64_t           *puValue);


/**
 * @brief Decode next item into an unsigned 64-bit integer with conversions
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] puValue       The returned 64-bit unsigned integer.
 *
 * This is the same as QCBORDecode_GetInt64ConvertAll(), but returns
 * an unsigned integer and thus sets @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION
 * if the value to be decoded is negatve.
 *
 * See also QCBORDecode_GetUInt64() and QCBORDecode_GetUInt64Convert().
 */
void
QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext *pCtx,
                                uint32_t            uConvertTypes,
                                uint64_t           *puValue);

void
QCBORDecode_GetUInt64ConvertAllInMapN(QCBORDecodeContext *pCtx,
                                      int64_t             nLabel,
                                      uint32_t            uConvertTypes,
                                      uint64_t           *puValue);

void
QCBORDecode_GetUInt64ConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                       const char         *szLabel,
                                       uint32_t            uConvertTypes,
                                       uint64_t           *puValue);




/**
 * @brief Decode the next item as a byte string
 *
 * @param[in] pCtx     The decode context.
 * @param[out] pBytes  The decoded byte string.
 *
 * The CBOR item to decode must be a byte string, CBOR type 2.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * If the CBOR item to decode is not a byte string, the
 * @ref QCBOR_ERR_UNEXPECTED_TYPE error is set.
 */
static void
QCBORDecode_GetByteString(QCBORDecodeContext *pCtx,
                          UsefulBufC         *pBytes);

static void
QCBORDecode_GetByteStringInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                UsefulBufC         *pBytes);

static void
QCBORDecode_GetByteStringInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 UsefulBufC         *pBytes);


/**
 * @brief Decode the next item as a text string.
 *
 * @param[in] pCtx    The decode context.
 * @param[out] pText  The decoded byte string.
 *
 * The CBOR item to decode must be a text string, CBOR type 3.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 * It the CBOR item to decode is not a text string, the
 * @ref QCBOR_ERR_UNEXPECTED_TYPE error is set.
 *
 * This does no translation of line endings. See QCBOREncode_AddText()
 * for a discussion of line endings in CBOR.
 */
static void
QCBORDecode_GetTextString(QCBORDecodeContext *pCtx,
                          UsefulBufC         *pText);

static void
QCBORDecode_GetTextStringInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                UsefulBufC         *pText);

static void
QCBORDecode_GetTextStringInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 UsefulBufC         *pText);




#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/**
 * @brief Decode next item into a double floating-point value.
 *
 * @param[in] pCtx     The decode context.
 * @param[out] pValue  The returned floating-point value.
 *
 * The CBOR data item to decode must be a half-precision,
 * single-precision or double-precision floating-point value. If not
 * @ref QCBOR_ERR_UNEXPECTED_TYPE is set.
 *
 * If floating-point HW use is disabled this will set
 * @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision number is
 * encountered. If half-precision support is disabled, this will set
 * @ref QCBOR_ERR_HALF_PRECISION_DISABLED if a half-precision number
 * is encountered.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetDoubleConvert() and
 * QCBORDecode_GetDoubleConvertAll().
 */
static void
QCBORDecode_GetDouble(QCBORDecodeContext *pCtx,
                      double             *pValue);

static void
QCBORDecode_GetDoubleInMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            double             *pdValue);

static void
QCBORDecode_GetDoubleInMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             double             *pdValue);


/**
 * @brief Decode next item into a double floating-point with basic conversion.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] pdValue       The returned floating-point value.
 *
 * This will decode CBOR integer and floating-point numbers, returning
 * them as a double floating-point number. This function supports

 * @ref QCBOR_CONVERT_TYPE_XINT64 and @ref QCBOR_CONVERT_TYPE_FLOAT
 * conversions. If the encoded CBOR is not one of the requested types
 * or a type not supported by this function, @ref QCBOR_ERR_UNEXPECTED_TYPE
 * is set.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * If floating-point HW use is disabled this will set
 * @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision number is
 * encountered. If half-precision support is disabled, this will set
 * @ref QCBOR_ERR_HALF_PRECISION_DISABLED if a half-precision number is
 * encountered.
 *
 * Positive and negative integers can always be converted to
 * floating-point, so this will never error on CBOR major type 0 or 1.
 *
 * Note that a large 64-bit integer can have more precision (64 bits)
 * than even a double floating-point (52 bits) value, so there is loss
 * of precision in some conversions.
 *
 * See also QCBORDecode_GetDouble() and QCBORDecode_GetDoubleConvertAll().
 */
static void
QCBORDecode_GetDoubleConvert(QCBORDecodeContext *pCtx,
                             uint32_t            uConvertTypes,
                             double             *pdValue);

static void
QCBORDecode_GetDoubleConvertInMapN(QCBORDecodeContext *pCtx,
                                   int64_t             nLabel,
                                   uint32_t            uConvertTypes,
                                   double             *pdValue);

static void
QCBORDecode_GetDoubleConvertInMapSZ(QCBORDecodeContext *pCtx,
                                    const char         *szLabel,
                                    uint32_t            uConvertTypes,
                                    double             *pdValue);


/**
 * @brief Decode next item as a double floating-point value with conversion.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] pdValue       The returned floating-point value.
 *
 * This is the same as QCBORDecode_GetDoubleConvert() but supports
 * many more conversions at the cost of linking in more object
 * code. The conversion types supported are @ref QCBOR_CONVERT_TYPE_XINT64,
 * @ref QCBOR_CONVERT_TYPE_FLOAT, @ref QCBOR_CONVERT_TYPE_BIG_NUM,
 * @ref QCBOR_CONVERT_TYPE_DECIMAL_FRACTION and
 * @ref QCBOR_CONVERT_TYPE_BIGFLOAT.
 *
 * Big numbers, decimal fractions and big floats that are too small or
 * too large to be reprented as a double floating-point number will be
 * returned as plus or minus zero or infinity rather than setting an
 * under or overflow error.
 *
 * There is often loss of precision in the conversion.
 *
 * See also QCBORDecode_GetDoubleConvert() and QCBORDecode_GetDoubleConvert().
 */
void
QCBORDecode_GetDoubleConvertAll(QCBORDecodeContext *pCtx,
                                uint32_t            uConvertTypes,
                                double             *pdValue);

void
QCBORDecode_GetDoubleConvertAllInMapN(QCBORDecodeContext *pCtx,
                                      int64_t             nLabel,
                                      uint32_t            uConvertTypes,
                                      double             *pdValue);

void
QCBORDecode_GetDoubleConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                       const char         *szLabel,
                                       uint32_t            uConvertTypes,
                                       double             *pdValue);
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */




/**
 * @brief Enter an array for decoding in bounded mode.
 *
 * @param[in] pCtx    The decode context.
 * @param[out] pItem  The optionally returned QCBORItem that has the
 *                    label and tags for the array. May be @c NULL (and
 *                    usually is).
 *
 * This enters an array for decoding in bounded mode. The items in
 * the array are decoded in order the same as when not in bounded mode,
 * but the decoding will not proceed past the end or the array.
 *
 * The typical way to iterate over items in an array is to call
 * QCBORDecode_VGetNext() until QCBORDecode_GetError() returns
 * @ref QCBOR_ERR_NO_MORE_ITEMS. Other methods like QCBORDecode_GetInt64(),
 * QCBORDecode_GetBignum() and such may also called until
 * QCBORDecode_GetError() doesn't return QCBOR_SUCCESS.
 *
 * Another option is to get the array item count from
 * @c pItem->val.uCount, but note that that will not work with
 * indefinte-length arrays, where as QCBORDecode_GetError() will.
 *
 * Nested decoding of arrays may be handled by calling
 * QCBORDecode_EnterArray() or by using QCBORDecode_VGetNext() to
 * descend into and back out of the nested array.
 *
 * QCBORDecode_Rewind() can be called to restart decoding from the
 * first item in the array.
 *
 * When all decoding in an array is complete, QCBORDecode_ExitArray() must
 * be called. It is a decoding error to not have a corresponding call
 * to QCBORDecode_ExitArray() for every call to QCBORDecode_EnterArray().
 * If not, @ref QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN will be returned when
 * QCBORDecode_Finish() is called.
 *
 * After QCBORDecode_ExitArray() is called the traversal cusor is at
 * the item right after the array. This is true whether or not all
 * items in the array were consumed. QCBORDecode_ExitArray() can even
 * be called right after QCBORDecode_EnterArray() as a way to skip
 * over an array and all its contents.
 *
 * This works the same for definite and indefinite length arrays.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * If attempting to enter a data item that is not an array
 * @ref QCBOR_ERR_UNEXPECTED_TYPE wil be set.
 *
 * Nested arrays and maps may be entered to a depth of
 * @ref QCBOR_MAX_ARRAY_NESTING.
 *
 * See also QCBORDecode_ExitArray(), QCBORDecode_EnterMap(),
 * QCBORDecode_EnterBstrWrapped() and QCBORDecode_GetArray().
 */
static void
QCBORDecode_EnterArray(QCBORDecodeContext *pCtx, QCBORItem *pItem);

void
QCBORDecode_EnterArrayFromMapN(QCBORDecodeContext *pMe, int64_t uLabel);

void
QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char *szLabel);


/**
 * @brief Exit an array that has been enetered.
 *
 * @param[in] pCtx  The decode context.
 *
 * An array must have been entered for this to succeed.
 *
 * The items in the array that was entered do not have to have been
 * consumed for this to succeed.
 *
 * This sets the traversal cursor to the item after the
 * array that was exited.
 *
 * This will result in an error if any item in the array is not well
 * formed (since all items in the array must be decoded to find its
 * end), or there are not enough items in the array.
 */
static void
QCBORDecode_ExitArray(QCBORDecodeContext *pCtx);



/**
 * @brief Get the encoded bytes that make up an array.
 *
 * @param[in] pCtx           The decode context.
 * @param[out] pItem         Place to return the item.
 * @param[out] pEncodedCBOR  Place to return pointer and length of the array.
 *
 * The next item to decode must be an array.
 *
 * The encoded bytes of the array will be returned. They can be
 * decoded by another decoder instance.
 *
 * @c pItem will have the label and tags for the array. It is filled
 * in the same as if QCBORDecode_GetNext() were called on the array item. In
 * particular, the array count will be filled in for definite-length
 * arrays and set to @c UINT16_MAX for indefinite-length arrays.
 *
 * This works on both definite and indefinite length arrays (unless
 * indefinite length array decoding has been disabled).
 *
 * The pointer returned is to the data item that opens the array. The
 * length in bytes includes it and all the member data items. If the array
 * occurs in another map and thus has a label, the label is not included
 * in what is returned.
 *
 * If the array is preceeded by tags, those encoded tags are included
 * in the encoded CBOR that is returned.
 *
 * QCBORDecode_GetArray() consumes the entire array and leaves the
 * traversal cursor at the item after the array.
 * QCBORDecode_GetArrayFromMapN() and QCBORDecode_GetArrayFromMapSZ()
 * don't affect the traversal cursor.
 *
 * This traverses the whole array and every subordinate array or map in
 * it. This is necessary to determine the length of the array.
 *
 * This will fail if any item in the array is not well-formed.
 *
 * This uses a few hundred bytes of stack, more than most methods.
 *
 * See also QCBORDecode_EnterArray().
 */
static void
QCBORDecode_GetArray(QCBORDecodeContext *pCtx,
                     QCBORItem          *pItem,
                     UsefulBufC         *pEncodedCBOR);

static void
QCBORDecode_GetArrayFromMapN(QCBORDecodeContext *pCtx,
                             int64_t             nLabel,
                             QCBORItem          *pItem,
                             UsefulBufC         *pEncodedCBOR);

static void
QCBORDecode_GetArrayFromMapSZ(QCBORDecodeContext *pCtx,
                              const char         *szLabel,
                              QCBORItem          *pItem,
                              UsefulBufC         *pEncodedCBOR);


/**
 * @brief Enter a map for decoding and searching.
 *
 * @param[in] pCtx    The decode context.
 * @param[out] pItem  The optionally returned QCBORItem that has the
 *                    label and tags for the map. May be @c NULL (and
 *                    usually is).
 *
 * The next item in the CBOR input must be map or this sets an error.
 *
 * This puts the decoder in bounded mode which narrows decoding to the
 * map entered and enables getting items by label.
 *
 * All items in the map must be well-formed to be able to search it by
 * label because a full traversal is done for each search. If not, the
 * search will retun an error for the item that is not well-formed.
 * This will be the first non-well-formed item which may not be the
 * item with the label that is the target of the search.
 *
 * Nested maps can be decoded like this by entering each map in turn.
 *
 * Call QCBORDecode_ExitMap() to exit the current map decoding
 * level. When all map decoding layers are exited then bounded mode is
 * fully exited.
 *
 * While in bounded mode, QCBORDecode_GetNext() works as usual on the
 * map and the traversal cursor is maintained. It starts out
 * at the first item in the map just entered. Attempts to get items
 * off the end of the map will give error @ref QCBOR_ERR_NO_MORE_ITEMS
 * rather going to the next item after the map as it would when not in
 * bounded mode.
 *
 * It is possible to mix use of the traversal cursor with the fetching
 * of items in a map by label with the caveat that fetching
 * non-aggregate items by label behaves differently from entering subordinate
 * aggregate items by label.  See dicussion in @ref SpiffyDecode.
 *
 * Exiting leaves the traversal cursor at the data item following the
 * last entry in the map or at the end of the input CBOR if there
 * nothing after the map.
 *
 * Entering and Exiting a map is a way to skip over an entire map and
 * its contents. After QCBORDecode_ExitMap(), the traversal
 * cursor will be at the first item after the map.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_EnterArray() and
 * QCBORDecode_EnterBstrWrapped().  Entering and exiting any nested
 * combination of maps, arrays and bstr-wrapped CBOR is supported up
 * to the maximum of @ref QCBOR_MAX_ARRAY_NESTING.
 *
 * See also QCBORDecode_GetMap().
 */
static void
QCBORDecode_EnterMap(QCBORDecodeContext *pCtx, QCBORItem *pItem);

void
QCBORDecode_EnterMapFromMapN(QCBORDecodeContext *pCtx, int64_t nLabel);

void
QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pCtx, const char *szLabel);


/**
 * @brief Exit a map that has been enetered.
 *
 * @param[in] pCtx  The decode context.
 *
 * A map must have been entered for this to succeed.
 *
 * The items in the map that was entered do not have to have been
 * consumed for this to succeed.
 *
 * This sets the traversal cursor to the item after the map
 * that was exited.
 *
 * This will result in an error if any item in the map is not well
 * formed (since all items in the map must be decoded to find its
 * end), or there are not enough items in the map.
 */
static void
QCBORDecode_ExitMap(QCBORDecodeContext *pCtx);


/**
 * @brief Get the bytes that make up a map.
 *
 * @param[in] pCtx           The decode context.
 * @param[out] pItem         Place to return the item.
 * @param[out] pEncodedCBOR  Place to return pointer and length of the map.
 *
 * The next item to decode must be a map.
 *
 * The encoded bytes of the map will be returned. They can be
 * decoded by another decoder instance.
 *
 *  @c pItem will have the label and tags for the array. It is filled
 * in the same as if QCBORDecode_GetNext() were called on the map item. In
 * particular, the map count will be filled in for definite-length
 * maps and set to @c UINT16_MAX for indefinite-length maps.
 *
 * This works on both definite and indefinite length maps (unless
 * indefinite length map decoding has been disabled).
 *
 * The pointer returned is to the data item that opens the map. The
 * length in bytes includes it and all the member data items. If the map
 * occurs in another map and thus has a label, the label is not included
 * in what is returned.
 *
 * If the map is preceeded by tags, those encoded tags are included in
 * the encoded CBOR that is returned.
 *
 * QCBORDecode_GetMap() consumes the entire array and leaves the
 * traversal cursor at the item after the map.
 * QCBORDecode_GetMapFromMapN() and QCBORDecode_GetMapFromMapSZ()
 * don't affect the traversal cursor.
 *
 * This traverses the whole map and every subordinate array or map in
 * it. This is necessary to determine the length of the map. The
 * traversal cursor is left at the first item after the map.
 *
 * This will fail if any item in the map is not well-formed.
 *
 * This uses a few hundred bytes of stack, more than most methods.
 *
 * See also QCBORDecode_EnterMap().
 */
static void
QCBORDecode_GetMap(QCBORDecodeContext *pCtx,
                   QCBORItem          *pItem,
                   UsefulBufC         *pEncodedCBOR);

static void
QCBORDecode_GetMapFromMapN(QCBORDecodeContext *pCtx,
                           int64_t             nLabel,
                           QCBORItem          *pItem,
                           UsefulBufC         *pEncodedCBOR);

static void
QCBORDecode_GetMapFromMapSZ(QCBORDecodeContext *pCtx,
                            const char         *szLabel,
                            QCBORItem          *pItem,
                            UsefulBufC         *pEncodedCBOR);


/**
 * @brief Reset traversal cursor to start of map, array, byte-string
 *        wrapped CBOR or start of input.
 *
 * @param[in] pCtx  The decode context.
 *
 * If an array, map or wrapping byte string has been entered this sets
 * the traversal cursor to its beginning. If several arrays, maps or
 * byte strings have been entered, this sets the traversal cursor to
 * the beginning of the one most recently entered.
 *
 * If no map or array has been entered, this resets the traversal
 * cursor to the beginning of the input CBOR.
 *
 * This also resets the error state.
 */
void
QCBORDecode_Rewind(QCBORDecodeContext *pCtx);


/**
 * @brief Get an item in map by label and type.
 *
 * @param[in] pCtx    The decode context.
 * @param[in] nLabel  The integer label.
 * @param[in] uQcborType  The QCBOR type. One of @c QCBOR_TYPE_XXX.
 * @param[out] pItem  The returned item.
 *
 * A map must have been entered to use this. If not
 * @ref QCBOR_ERR_MAP_NOT_ENTERED is set.
 *
 * The map is searched for an item of the requested label and type.
 * @ref QCBOR_TYPE_ANY can be given to search for the label without
 * matching the type.
 *
 * This will always search the entire map. This will always perform
 * duplicate label detection, setting @ref QCBOR_ERR_DUPLICATE_LABEL
 * if there is more than one occurance of the label being searched
 * for.
 *
 * Duplicate label detection is performed for the item being sought
 * and only for the item being sought.
 *
 * This performs a full decode of every item in the map being
 * searched which involves a full traversal of every item. For maps
 * with little nesting, this is of little consequence, but may be of
 * consequence for large deeply nested CBOR structures on slow CPUs.
 *
 * The position of the traversal cursor is not changed.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetItemsInMap() for error discussion.
 */
void
QCBORDecode_GetItemInMapN(QCBORDecodeContext *pCtx,
                          int64_t             nLabel,
                          uint8_t             uQcborType,
                          QCBORItem          *pItem);

void
QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pCtx,
                           const char         *szLabel,
                           uint8_t             uQcborType,
                           QCBORItem          *pItem);


/**
 * @brief Get a group of labeled items all at once from a map
 *
 * @param[in] pCtx           The decode context.
 * @param[in,out] pItemList  On input, the items to search for. On output,
 *                           the returne *d items.
 *
 * This gets several labeled items out of a map.
 *
 * @c pItemList is an array of items terminated by an item with @c
 * uLabelType @ref QCBOR_TYPE_NONE.
 *
 * On input the labels to search for are in the @c uLabelType and
 * label fields in the items in @c pItemList.
 *
 * Also on input are the requested QCBOR types in the field
 * @c uDataType.  To match any type, searching just by label,
 * @c uDataType can be @ref QCBOR_TYPE_ANY.
 *
 * This is a CPU-efficient way to decode a bunch of items in a map. It
 * is more efficient than scanning each individually because the map
 * only needs to be traversed once.
 *
 * This will return maps and arrays that are in the map, but provides
 * no way to descend into and decode them. Use
 * QCBORDecode_EnterMapinMapN(), QCBORDecode_EnterArrayInMapN() and
 * such to descend into and process maps and arrays.
 *
 * The position of the traversal cursor is not changed.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * The following errors are set:
 *
 * @ref QCBOR_ERR_MAP_NOT_ENTERED when calling this without previousl
 * calling QCBORDecode_EnterMap() or other methods to enter a map.
 *
 * @ref QCBOR_ERR_DUPLICATE_LABEL when one of the labels being searched
 * for is duplicate.
 *
 * @ref QCBOR_ERR_HIT_END or other errors classifed as not-well-formed
 * by QCBORDecode_IsNotWellFormed() as it is not possible to traverse
 * maps that have any non-well formed items.
 *
 * @ref QCBOR_ERR_UNEXPECTED_TYPE when the type of an item found by
 * matching a label is not the type requested.
 *
 * @ref QCBOR_ERR_ARRAY_NESTING_TOO_DEEP and other implementation
 * limit errors as it is not possible to travere a map beyond the
 * limits of the implementation.
 *
 * The error may occur on items that are not being searched for.  For
 * example, it is impossible to traverse over a map that has an array in
 * it that is not closed or over array and map nesting deeper than this
 * implementation can track.
 *
 * See also QCBORDecode_GetItemInMapN().
 */
void
QCBORDecode_GetItemsInMap(QCBORDecodeContext *pCtx, QCBORItem *pItemList);


/**
 * @brief Per-item callback for map searching.
 *
 * @param[in] pCallbackCtx  Pointer to the caller-defined context for the callback.
 * @param[in] pItem         The item from the map.
 *
 * The error set is intended for QCBOR errors, not general protocol
 * decoding errors. If this sets other than @ref QCBOR_SUCCESS, the
 * search will stop and the value it returns will be set in
 * QCBORDecode_GetItemsInMapWithCallback(). The special error,
 * @ref QCBOR_ERR_CALLBACK_FAIL, can be returned to indicate some
 * protocol processing error that is not a CBOR error. The specific
 * details of the protocol processing error can be returned the call
 * back context.
 */
typedef QCBORError (*QCBORItemCallback)(void            *pCallbackCtx,
                                        const QCBORItem *pItem);


/**
 * @brief Get a group of labeled items all at once from a map with a callback.
 *
 * @param[in] pCtx              The decode context.
 * @param[in,out] pItemList     On input, the items to search for. On output,
 *                              the returne *d items.
 * @param[in,out] pCallbackCtx  Pointer to a context structure for
 *                              @ref QCBORItemCallback
 * @param[in] pfCB              Pointer to function of type
 *                              @ref QCBORItemCallback that is called on
 *                              unmatched items.
 *
 * This searchs a map like QCBORDecode_GetItemsInMap(), but calls a
 * callback on items not matched rather than ignoring them. If @c
 * pItemList is empty, the call back will be called on every item in the
 * map.
 *
 * Like QCBORDecode_GetItemsInMap(), this only matches and calls back on
 * the items at the top level of the map entered. Items in nested
 * maps and arrays are skipped over and not candidate for matching or the
 * callback.
 *
 * See QCBORItemCallback() for error handling.
 */
void
QCBORDecode_GetItemsInMapWithCallback(QCBORDecodeContext *pCtx,
                                      QCBORItem          *pItemList,
                                      void               *pCallbackCtx,
                                      QCBORItemCallback   pfCB);




/**
 * @brief Decode the next item as a Boolean.
 *
 * @param[in] pCtx     The decode context.
 * @param[out] pbBool  The decoded byte string.
 *
 * The CBOR item to decode must be either the CBOR simple value (CBOR
 * type 7) @c true or @c false.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview". If
 * the CBOR item to decode is not true or false the @ref
 * QCBOR_ERR_UNEXPECTED_TYPE error is set.
*/
void
QCBORDecode_GetBool(QCBORDecodeContext *pCtx, bool *pbBool);

void
QCBORDecode_GetBoolInMapN(QCBORDecodeContext *pCtx,
                          int64_t             nLabel,
                          bool               *pbBool);

void
QCBORDecode_GetBoolInMapSZ(QCBORDecodeContext *pCtx,
                           const char         *szLabel,
                           bool               *pbBool);


/**
 * @brief Decode the next item as a null.
 *
 * @param[in] pCtx  The decode context.
 *
 * The CBOR item to decode must be the CBOR simple value (CBOR type 7)
 * @c null. The reason to call this is to see if an error is returned
 * or not indicating whether the item is a CBOR null. If it is not
 * then the @ref QCBOR_ERR_UNEXPECTED_TYPE error is set.
 */
static void
QCBORDecode_GetNull(QCBORDecodeContext *pCtx);

static void
QCBORDecode_GetNullInMapN(QCBORDecodeContext *pCtx,
                          int64_t             nLabel);

static void
QCBORDecode_GetNullInMapSZ(QCBORDecodeContext *pCtx,
                           const char         *szLabel);


/**
 * @brief Decode the next item as a CBOR "undefined" item.
 *
 * @param[in] pCtx  The decode context.
 *
 * The CBOR item to decode must be the CBOR simple value (CBOR type 7)
 * @c undefined. The reason to call this is to see if an error is
 * returned or not indicating whether the item is a CBOR undefed
 * item. If it is not then the @ref QCBOR_ERR_UNEXPECTED_TYPE error is
 * set.
 */
static void
QCBORDecode_GetUndefined(QCBORDecodeContext *pCtx);

static void
QCBORDecode_GetUndefinedInMapN(QCBORDecodeContext *pCtx,
                               int64_t             nLabel);

static void
QCBORDecode_GetUndefinedInMapSZ(QCBORDecodeContext *pCtx,
                                const char         *szLabel);


/**
 * @brief Decode the next item as a CBOR simple value.
 *
 * @param[in] pCtx            The decode context.
 * @param[out] puSimpleValue  The simplle value returned.
 *
 * The purpose of this is to get a CBOR simple value other than a
 * Boolean, NULL or "undefined", but this works on all simple
 * values. See QCBOREncode_AddSimple() for more details on simple
 * values in general.
 *
 * See QCBORDecode_GetBool(), QCBORDecode_GetNull(),
 * QCBORDecode_GetUndefined() for the preferred way of getting those
 * simple values.
 */
void
QCBORDecode_GetSimple(QCBORDecodeContext *pCtx, uint8_t *puSimpleValue);

void
QCBORDecode_GetSimpleInMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            uint8_t            *puSimpleValue);

void
QCBORDecode_GetSimpleInMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             uint8_t            *puSimpleValue);




/**
 * @brief Decode the next item as a date string.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pDateString     The decoded date.
 *
 * This decodes the standard CBOR date/time string tag, integer tag
 * number of 0, or encoded CBOR that is not a tag, but borrows the
 * date string content format.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_DATE_STRING, QCBOREncode_AddDateString() and
 * @ref QCBOR_TYPE_DATE_STRING.
 */
static void
QCBORDecode_GetDateString(QCBORDecodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pDateString);

static void
QCBORDecode_GetDateStringInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC         *pDateString);

static void
QCBORDecode_GetDateStringInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pDateString);


/**
 * @brief Decode the next item as a date-only string.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pDateString     The decoded date.
 *
 * This decodes the CBOR date-only string tag, integer tag number of
 * 1004, or encoded CBOR that is not a tag, but borrows the date-only
 * string content format. An example of the format is "1985-04-12".
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_DAYS_STRING, QCBOREncode_AddDaysString() and
 * @ref QCBOR_TYPE_DAYS_STRING.
 */
static void
QCBORDecode_GetDaysString(QCBORDecodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pDateString);

static void
QCBORDecode_GetDaysStringInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC         *pDateString);

static void
QCBORDecode_GetDaysStringInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pDateString);


/**
 * @brief Decode the next item as an epoch date.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pnTime          The decoded epoch date.
 *
 * This decodes the standard CBOR epoch date/time tag, integer tag
 * number of 1. This will also decode any integer or floating-point
 * number as an epoch date (a tag 1 epoch date is just an integer or
 * floating-point number).
 *
 * This will set @ref QCBOR_ERR_DATE_OVERFLOW if the input integer
 * will not fit in an @c int64_t. Note that an @c int64_t can
 * represent a range of over 500 billion years with one second
 * resolution.
 *
 * Floating-point dates are always returned as an @c int64_t. The
 * fractional part is discarded.
 *
 * If the input is a floating-point date and the QCBOR library is
 * compiled with some or all floating-point features disabled, the
 * following errors will be set.  If the input is half-precision and
 * half-precision is disabled @ref QCBOR_ERR_HALF_PRECISION_DISABLED
 * is set. This function needs hardware floating-point to convert the
 * floating-point value to an integer so if HW floating point is
 * disabled @ref QCBOR_ERR_HW_FLOAT_DISABLED is set. If all
 * floating-point is disabled then @ref QCBOR_ERR_ALL_FLOAT_DISABLED
 * is set.  A previous version of this function would return
 * @ref QCBOR_ERR_FLOAT_DATE_DISABLED in some, but not all, cases when
 * floating-point decoding was disabled.
 *
 * Floating-point dates that are plus infinity, minus infinity or NaN
 * (not-a-number) will result in the @ref QCBOR_ERR_DATE_OVERFLOW
 * error.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_DATE_EPOCH, QCBOREncode_AddDateEpoch() and
 * @ref QCBOR_TYPE_DATE_EPOCH.
*/
void
QCBORDecode_GetEpochDate(QCBORDecodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         int64_t            *pnTime);

void
QCBORDecode_GetEpochDateInMapN(QCBORDecodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnTime);

void
QCBORDecode_GetEpochDateInMapSZ(QCBORDecodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnTime);


/**
 * @brief Decode the next item as an days-count epoch date.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pnDays          The decoded epoch date.
 *
 * This decodes the CBOR epoch date tag, integer tag number of 100, or
 * encoded CBOR that is not a tag, but borrows the content format. The
 * date is the number of days (not number of seconds) before or after
 * Jan 1, 1970.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_DAYS_EPOCH, QCBOREncode_AddTDaysEpoch() and
 * @ref QCBOR_TYPE_DAYS_EPOCH.
*/
void
QCBORDecode_GetEpochDays(QCBORDecodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         int64_t            *pnDays);

void
QCBORDecode_GetEpochDaysInMapN(QCBORDecodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnDays);

void
QCBORDecode_GetEpochDaysInMapSZ(QCBORDecodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnDays);




/**
 * @brief Decode the next item as a big number.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pValue          The returned big number.
 * @param[out] pbIsNegative    Is @c true if the big number is negative. This
 *                             is only valid when @c uTagRequirement is
 *                             @ref QCBOR_TAG_REQUIREMENT_TAG.
 *
 * This decodes a standard CBOR big number, integer tag number of 2 or
 * 3, or encoded CBOR that is not a tag, but borrows the content
 * format.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * The big number is in network byte order. The first byte in @c
 * pValue is the most significant byte. There may be leading zeros.
 *
 * The negative value is computed as -1 - n, where n is the postive
 * big number in @c pValue. There is no standard representation for
 * big numbers, positive or negative in C, so this implementation
 * leaves it up to the caller to apply this computation for negative
 * big numbers.
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * Determination of the sign of the big number depends on the tag
 * requirement of the protocol using the big number. If the protocol
 * requires tagging, @ref QCBOR_TAG_REQUIREMENT_TAG, then the sign
 * indication is in the protocol and @c pbIsNegative indicates the
 * sign. If the protocol doesn't use a tag, @ref QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
 * then the protocol design must have some way of indicating the sign.
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can convert big numbers.
 *
 * See also @ref CBOR_TAG_POS_BIGNUM, @ref CBOR_TAG_NEG_BIGNUM,
 * QCBOREncode_AddPositiveBignum(), QCBOREncode_AddNegativeBignum(),
 * @ref QCBOR_TYPE_POSBIGNUM and @ref QCBOR_TYPE_NEGBIGNUM.
 */
// Improvement: Add function that converts integers and other to big nums
void
QCBORDecode_GetBignum(QCBORDecodeContext *pCtx,
                      uint8_t             uTagRequirement,
                      UsefulBufC         *pValue,
                      bool               *pbIsNegative);

void
QCBORDecode_GetBignumInMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC         *pValue,
                            bool               *pbIsNegative);

void
QCBORDecode_GetBignumInMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             uint8_t             uTagRequirement,
                             UsefulBufC         *pValue,
                             bool               *pbIsNegative);




#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
/**
 * @brief Decode the next item as a decimal fraction.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pnMantissa      The mantissa.
 * @param[out] pnExponent      The base 10 exponent.
 *
 * This decodes a standard CBOR decimal fraction, integer tag number
 * of 4, or encoded CBOR that is not a tag, but borrows the content
 * format.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * The  value of this is computed by:
 *
 *     mantissa * ( 10 ** exponent )
 *
 * In the encoded CBOR, the mantissa and exponent may be of CBOR type
 * 0 (positive integer), type 1 (negative integer), type 2 tag 2
 * (positive big number) or type 2 tag 3 (negative big number). This
 * implementation will attempt to convert all of these to an @c
 * int64_t. If the value won't fit, @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW
 * or @ref QCBOR_ERR_BAD_EXP_AND_MANTISSA will be set.
 *
 * This implementation limits the exponent to between @c INT64_MIN and
 * @c INT64_MAX while CBOR allows the range of @c -UINT64_MAX to
 * @c UINT64_MAX.
 *
 * Various format and type issues will result in
 * @ref QCBOR_ERR_BAD_EXP_AND_MANTISSA being set.
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can convert big numbers.
 *
 * See also @ref CBOR_TAG_DECIMAL_FRACTION,
 * QCBOREncode_AddDecimalFraction(), @ref QCBOR_TYPE_DECIMAL_FRACTION
 * and QCBORDecode_GetDecimalFractionBig().
 *
 * If QCBOR_DISABLE_TAGS is set, the only input this will decode is an
 * array of two integers. It will set an error if the the array is
 * preceded by by a tag number or if the mantissa is a big number.
 */
void
QCBORDecode_GetDecimalFraction(QCBORDecodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               int64_t            *pnMantissa,
                               int64_t            *pnExponent);

void
QCBORDecode_GetDecimalFractionInMapN(QCBORDecodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     int64_t            *pnMantissa,
                                     int64_t            *pnExponent);

void
QCBORDecode_GetDecimalFractionInMapSZ(QCBORDecodeContext *pMe,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      int64_t            *pnMantissa,
                                      int64_t            *pnExponent);


/**
 * @brief Decode the next item as a decimal fraction with a big number mantissa.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[in] MantissaBuffer   The buffer in which to put the mantissa.
 * @param[out] pMantissa       The big num mantissa.
 * @param[out] pbMantissaIsNegative  Is @c true if @c pMantissa is negative.
 * @param[out] pnExponent      The base 10 exponent.
 *
 * This is the same as QCBORDecode_GetDecimalFraction() except the
 * mantissa is returned as a big number.
 *
 * In the encoded CBOR, the mantissa may be a type 0 (positive
 * integer), type 1 (negative integer), type 2 tag 2 (positive big
 * number) or type 2 tag 3 (negative big number). This implementation
 * will convert all these to a big number. The limit to this
 * conversion is the size of @c MantissaBuffer.
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can convert decimal
 * fractions.
 *
 * See also @ref CBOR_TAG_DECIMAL_FRACTION,
 * QCBOREncode_AddDecimalFraction(), @ref QCBOR_TYPE_DECIMAL_FRACTION
 * and QCBORDecode_GetDecimalFraction().
 */
void
QCBORDecode_GetDecimalFractionBig(QCBORDecodeContext *pCtx,
                                  uint8_t             uTagRequirement,
                                  UsefulBuf           MantissaBuffer,
                                  UsefulBufC         *pMantissa,
                                  bool               *pbMantissaIsNegative,
                                  int64_t            *pnExponent);

void
QCBORDecode_GetDecimalFractionBigInMapN(QCBORDecodeContext *pCtx,
                                        int64_t             nLabel,
                                        uint8_t             uTagRequirement,
                                        UsefulBuf           MantissaBuffer,
                                        UsefulBufC         *pbMantissaIsNegative,
                                        bool               *pbIsNegative,
                                        int64_t            *pnExponent);

void
QCBORDecode_GetDecimalFractionBigInMapSZ(QCBORDecodeContext *pCtx,
                                         const char         *szLabel,
                                         uint8_t             uTagRequirement,
                                         UsefulBuf           MantissaBuffer,
                                         UsefulBufC         *pMantissa,
                                         bool               *pbMantissaIsNegative,
                                         int64_t            *pnExponent);


/**
 * @brief Decode the next item as a big float.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pnMantissa      The mantissa.
 * @param[out] pnExponent      The base 2 exponent.
 *
 * This decodes a standard CBOR big float, integer tag number of 5, or
 * encoded CBOR that is not a tag, but borrows the content format.
 *
 * This is the same as QCBORDecode_GetDecimalFraction() with the
 * important distinction that the value is computed by:
 *
 *     mantissa * ( 2 ** exponent )
 *
 * If the mantissa is a tag that is a positive or negative big number,
 * this will attempt to fit it into the int64_t that @c pnMantissa is
 * and set an overflow error if it doesn't fit.
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can convert big floats.
 *
 * See also @ref CBOR_TAG_BIGFLOAT, QCBOREncode_AddBigFloat(), @ref
 * QCBOR_TYPE_BIGFLOAT and QCBORDecode_GetBigFloatBig().
 */
void
QCBORDecode_GetBigFloat(QCBORDecodeContext *pCtx,
                        uint8_t             uTagRequirement,
                        int64_t            *pnMantissa,
                        int64_t            *pnExponent);

void
QCBORDecode_GetBigFloatInMapN(QCBORDecodeContext *pCtx,
                              int64_t             nLabel,
                              uint8_t             uTagRequirement,
                              int64_t            *pnMantissa,
                              int64_t            *pnExponent);

void
QCBORDecode_GetBigFloatInMapSZ(QCBORDecodeContext *pCtx,
                               const char         *szLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnMantissa,
                               int64_t            *pnExponent);


/**
 * @brief Decode the next item as a big float with a big number mantissa.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[in] MantissaBuffer   The buffer in which to put the mantissa.
 * @param[out] pMantissa       The big num mantissa.
 * @param[out] pbMantissaIsNegative  Is @c true if @c pMantissa is negative.
 * @param[out] pnExponent      The base 2 exponent.
 *
 * This is the same as QCBORDecode_GetDecimalFractionBig() with the
 * important distinction that the value is computed by:
 *
 *     mantissa * ( 2 ** exponent )
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can convert big floats.
 *
 * See also @ref CBOR_TAG_BIGFLOAT, QCBOREncode_AddBigFloat(),
 * @ref QCBOR_TYPE_BIGFLOAT and QCBORDecode_GetBigFloat().
 */
void
QCBORDecode_GetBigFloatBig(QCBORDecodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBuf           MantissaBuffer,
                           UsefulBufC         *pMantissa,
                           bool               *pbMantissaIsNegative,
                           int64_t            *pnExponent);

void
QCBORDecode_GetBigFloatBigInMapN(QCBORDecodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBuf           MantissaBuffer,
                                 UsefulBufC         *pMantissa,
                                 bool               *pbMantissaIsNegative,
                                 int64_t            *pnExponent);

void
QCBORDecode_GetBigFloatBigInMapSZ(QCBORDecodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBuf           MantissaBuffer,
                                  UsefulBufC         *pMantissa,
                                  bool               *pbMantissaIsNegative,
                                  int64_t            *pnExponent);
#endif /* #ifndef QCBOR_DISABLE_EXP_AND_MANTISSA */




/**
 * @brief Decode the next item as a URI.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pURI            The decoded URI.
 *
 * This decodes a standard CBOR URI tag, integer tag number of 32, or
 * encoded CBOR that is not a tag, that is a URI encoded in a text
 * string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_URI, QCBOREncode_AddURI() and
 *  @ref QCBOR_TYPE_URI.
 */
static void
QCBORDecode_GetURI(QCBORDecodeContext *pCtx,
                   uint8_t             uTagRequirement,
                   UsefulBufC         *pURI);

static void
QCBORDecode_GetURIInMapN(QCBORDecodeContext *pCtx,
                         int64_t             nLabel,
                         uint8_t             uTagRequirement,
                         UsefulBufC         *pURI);

static void
QCBORDecode_GetURIInMapSZ(QCBORDecodeContext *pCtx,
                          const char *        szLabel,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pURI);


/**
 * @brief Decode the next item as base64 encoded text.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pB64Text        The decoded base64 text.
 *
 * This decodes a standard CBOR base64 tag, integer tag number of 34,
 * or encoded CBOR that is not a tag, that is base64 encoded bytes
 * encoded in a text string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * Note that this does not actually remove the base64 encoding.
 *
 * See also @ref CBOR_TAG_B64, QCBOREncode_AddB64Text() and
 * @ref QCBOR_TYPE_BASE64.
 */
static void
QCBORDecode_GetB64(QCBORDecodeContext *pCtx,
                   uint8_t             uTagRequirement,
                   UsefulBufC         *pB64Text);

static void
QCBORDecode_GetB64InMapN(QCBORDecodeContext *pCtx,
                         int64_t             nLabel,
                         uint8_t             uTagRequirement,
                         UsefulBufC         *pB64Text);

static void
QCBORDecode_GetB64InMapSZ(QCBORDecodeContext *pCtx,
                          const char         *szLabel,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pB64Text);

/**
 * @brief Decode the next item as base64URL encoded text.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pB64Text        The decoded base64 text.
 *
 * This decodes a standard CBOR base64url tag, integer tag number of
 * 33, or encoded CBOR that is not a tag, that is base64url encoded
 * bytes encoded in a text string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * Note that this does not actually remove the base64url encoding.
 *
 * See also @ref CBOR_TAG_B64URL, QCBOREncode_AddB64URLText() and
 * @ref QCBOR_TYPE_BASE64URL.
 */
static void
QCBORDecode_GetB64URL(QCBORDecodeContext *pCtx,
                      uint8_t             uTagRequirement,
                      UsefulBufC         *pB64Text);

static void
QCBORDecode_GetB64URLInMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC         *pB64Text);

static void
QCBORDecode_GetB64URLInMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             uint8_t             uTagRequirement,
                             UsefulBufC         *pB64Text);

/**
 * @brief Decode the next item as a regular expression.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pRegex          The decoded regular expression.
 *
 * This decodes a standard CBOR regex tag, integer tag number of 35,
 * or encoded CBOR that is not a tag, that is a PERL-compatible
 * regular expression encoded in a text string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_REGEX, QCBOREncode_AddRegex() and
 * @ref QCBOR_TYPE_REGEX.
 */
static void
QCBORDecode_GetRegex(QCBORDecodeContext *pCtx,
                     uint8_t             uTagRequirement,
                     UsefulBufC         *pRegex);

static void
QCBORDecode_GetRegexInMapN(QCBORDecodeContext *pCtx,
                           int64_t             nLabel,
                           uint8_t             uTagRequirement,
                           UsefulBufC         *pRegex);

static void
QCBORDecode_GetRegexInMapSZ(QCBORDecodeContext *pCtx,
                            const char *        szLabel,
                            uint8_t             uTagRequirement,
                             UsefulBufC         *pRegex);


/**
 * @brief Decode the next item as a MIME message.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pMessage        The decoded regular expression.
 * @param[out] pbIsTag257      @c true if tag was 257. May be @c NULL.
 *
 * This decodes the standard CBOR MIME and binary MIME tags, integer
 * tag numbers of 36 or 257, or encoded CBOR that is not a tag, that
 * is a MIME message encoded in a text or binary string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * The MIME message itself is not parsed.
 *
 * This decodes both tag 36 and 257. If it is tag 257, pbIsTag257 is
 * @c true. The difference between the two is that tag 36 is utf8 and
 * tag 257 is a byte string that can carry binary MIME. QCBOR
 * processes them exactly the same. Possibly the difference can be
 * ignored.  NULL can be passed to have no value returned.
 *
 * See also @ref CBOR_TAG_MIME, @ref CBOR_TAG_BINARY_MIME,
 * QCBOREncode_AddTMIMEData(), @ref QCBOR_TYPE_MIME and
 * @ref QCBOR_TYPE_BINARY_MIME.
 *
 * This does no translation of line endings. See QCBOREncode_AddText()
 * for a discussion of line endings in CBOR.
 */
static void
QCBORDecode_GetMIMEMessage(QCBORDecodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBufC         *pMessage,
                           bool               *pbIsTag257);

static void
QCBORDecode_GetMIMEMessageInMapN(QCBORDecodeContext *pCtx,
                                 int64_t              nLabel,
                                 uint8_t              uTagRequirement,
                                 UsefulBufC          *pMessage,
                                 bool                *pbIsTag257);


static void
QCBORDecode_GetMIMEMessageInMapSZ(QCBORDecodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC         *pMessage,
                                  bool               *pbIsTag257);

/**
 * @brief Decode the next item as a UUID.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pUUID           The decoded UUID
 *
 * This decodes a standard CBOR UUID tag, integer tag number of 37, or
 * encoded CBOR that is not a tag, that is a UUID encoded in a byte
 * string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_BIN_UUID, QCBOREncode_AddBinaryUUID() and
 * @ref QCBOR_TYPE_UUID.
 */
static void
QCBORDecode_GetBinaryUUID(QCBORDecodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pUUID);

static void
QCBORDecode_GetBinaryUUIDInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC         *pUUID);

static void
QCBORDecode_GetBinaryUUIDInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pUUID);



/**
 * @brief Decode some byte-string wrapped CBOR.
 *
 * @param[in] pCtx    The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pBstr  Pointer and length of byte-string wrapped CBOR (optional).
 *
 * This is for use on some CBOR that has been wrapped in a byte
 * string. There are several ways that this can occur.
 *
 * First is tag 24 and tag 63. Tag 24 wraps a single CBOR data item
 * and 63 a CBOR sequence.  This implementation doesn't distinguish
 * between the two (it would be more code and doesn't seem important).
 *
 * The @ref Tag-Usage discussion on the tag requirement applies here
 * just the same as any other tag.
 *
 * In other cases, CBOR is wrapped in a byte string, but it is
 * identified as CBOR by other means. The contents of a COSE payload
 * are one example of that. They can be identified by the COSE content
 * type, or they can be identified as CBOR indirectly by the protocol
 * that uses COSE. for example, if a blob of CBOR is identified as a
 * CWT, then the COSE payload is CBOR.  To enter into CBOR of this
 * type use the @ref QCBOR_TAG_REQUIREMENT_NOT_A_TAG as the \c
 * uTagRequirement argument.
 *
 * Note that byte string wrapped CBOR can also be decoded by getting
 * the byte string with QCBORDecode_GetItem() or
 * QCBORDecode_GetByteString() and feeding it into another instance of
 * QCBORDecode. Doing it with this function has the advantage of using
 * less memory as another instance of QCBORDecode is not necessary.
 *
 * When the wrapped CBOR is entered with this function, the pre-order
 * traversal and such are bounded to the wrapped
 * CBOR. QCBORDecode_ExitBstrWrapped() must be called to resume
 * processing CBOR outside the wrapped CBOR.
 *
 * This does not work on indefinite-length strings. The
 * error @ref QCBOR_ERR_CANNOT_ENTER_ALLOCATED_STRING will be set.
 *
 * If @c pBstr is not @c NULL the pointer and length of the wrapped
 * CBOR will be returned. This is usually not needed, but sometimes
 * useful, particularly in the case of verifying signed data like the
 * COSE payload. This is usually the pointer and length of the data is
 * that is hashed or MACed.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_ExitBstrWrapped(), QCBORDecode_EnterMap() and
 * QCBORDecode_EnterArray().
 */
void
QCBORDecode_EnterBstrWrapped(QCBORDecodeContext *pCtx,
                             uint8_t             uTagRequirement,
                             UsefulBufC         *pBstr);

void
QCBORDecode_EnterBstrWrappedFromMapN(QCBORDecodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC         *pBstr);

void
QCBORDecode_EnterBstrWrappedFromMapSZ(QCBORDecodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC         *pBstr);


/**
 * @brief Exit some bstr-wrapped CBOR  has been enetered.
 *
 * @param[in] pCtx  The decode context.
 *
 * Bstr-wrapped CBOR must have been entered for this to succeed.
 *
 * The items in the wrapped CBOR that was entered do not have to have
 * been consumed for this to succeed.
 *
 * The this sets the traversal cursor to the item after the
 * byte string that was exited.
 */
void
QCBORDecode_ExitBstrWrapped(QCBORDecodeContext *pCtx);




/* ===========================================================================
   BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================== */


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetUInt64Convert(QCBORDecodeContext *pCtx,
                                     uint32_t            uConvertTypes,
                                     uint64_t           *puValue,
                                     QCBORItem          *pItem);


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetUInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           uint64_t           *puValue,
                                           QCBORItem          *pItem);


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            uint64_t           *puValue,
                                            QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_EnterBoundedMapOrArray(QCBORDecodeContext *pCtx,
                                           uint8_t             uType,
                                           QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_ExitBoundedMapOrArray(QCBORDecodeContext *pCtx,
                                          uint8_t             uType);


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetInt64Convert(QCBORDecodeContext *pCtx,
                                    uint32_t            uConvertTypes,
                                    int64_t            *pnValue,
                                    QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                          int64_t             nLabel,
                                          uint32_t            uConvertTypes,
                                          int64_t            *pnValue,
                                          QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                           const char         *szLabel,
                                           uint32_t            uConvertTypes,
                                           int64_t            *pnValue,
                                           QCBORItem          *pItem);


#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetDoubleConvert(QCBORDecodeContext *pCtx,
                                     uint32_t            uConvertTypes,
                                     double             *pValue,
                                     QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetDoubleConvertInMapN(QCBORDecodeContext *pCtx,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           double             *pdValue,
                                           QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetDoubleConvertInMapSZ(QCBORDecodeContext *pCtx,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            double             *pdValue,
                                            QCBORItem          *pItem);
#endif /* !USEFULBUF_DISABLE_ALL_FLOAT */

#define QCBOR_TAGSPEC_NUM_TYPES 4
/* Semi-private data structure (which might change).
 *
 * See QCBOR_Private_CheckTagRequirement() which uses this to check the
 * type of an item to be decoded as a tag or tag content.
 *
 * Improvement: Carefully understand what compilers do with this,
 * particularly initialization and see if it can be optimized so there
 * is less code and maybe so it can be smaller.
 */
typedef struct {
   /* One of QCBOR_TAGSPEC_MATCH_xxx */
   uint8_t uTagRequirement;
   /* The tagged type translated into QCBOR_TYPE_XXX. Used to match
    * explicit tagging */
   uint8_t uTaggedTypes[QCBOR_TAGSPEC_NUM_TYPES];
   /* The types of the content, which are used to match implicit
    * tagging */
   uint8_t uAllowedContentTypes[QCBOR_TAGSPEC_NUM_TYPES];
} QCBOR_Private_TagSpec;


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetTaggedString(QCBORDecodeContext   *pCtx,
                                    QCBOR_Private_TagSpec TagSpec,
                                    UsefulBufC           *pBstr);


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetTaggedStringInMapN(QCBORDecodeContext   *pCtx,
                                          int64_t               nLabel,
                                          QCBOR_Private_TagSpec TagSpec,
                                          UsefulBufC           *pString);

/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetTaggedStringInMapSZ(QCBORDecodeContext   *pCtx,
                                           const char           *szLabel,
                                           QCBOR_Private_TagSpec TagSpec,
                                           UsefulBufC           *pString);


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
QCBORError
QCBORDecode_Private_GetMIME(uint8_t           uTagRequirement,
                            const QCBORItem  *pItem,
                            UsefulBufC       *pMessage,
                            bool             *pbIsTag257);





static inline void
QCBORDecode_GetUInt64Convert(QCBORDecodeContext *pMe,
                             const uint32_t     uConvertTypes,
                             uint64_t           *puValue)
{
    QCBORItem Item;
    QCBORDecode_Private_GetUInt64Convert(pMe, uConvertTypes, puValue, &Item);
}

static inline void
QCBORDecode_GetUInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                   const int64_t       nLabel,
                                   const uint32_t      uConvertTypes,
                                   uint64_t           *puValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetUInt64ConvertInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              puValue,
                                              &Item);
}

static inline void
QCBORDecode_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    const uint32_t     uConvertTypes,
                                    uint64_t           *puValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetUInt64ConvertInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               puValue,
                                               &Item);
}

static inline void
QCBORDecode_GetUInt64(QCBORDecodeContext *pMe, uint64_t *puValue)
{
    QCBORDecode_GetUInt64Convert(pMe, QCBOR_CONVERT_TYPE_XINT64, puValue);
}

static inline void
QCBORDecode_GetUInt64InMapN(QCBORDecodeContext *pMe,
                            const int64_t       nLabel,
                            uint64_t           *puValue)
{
   QCBORDecode_GetUInt64ConvertInMapN(pMe,
                                      nLabel,
                                      QCBOR_CONVERT_TYPE_XINT64,
                                      puValue);
}

static inline void
QCBORDecode_GetUInt64InMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             uint64_t           *puValue)
{
   QCBORDecode_GetUInt64ConvertInMapSZ(pMe,
                                       szLabel,
                                       QCBOR_CONVERT_TYPE_XINT64,
                                       puValue);
}


static inline void
QCBORDecode_EnterMap(QCBORDecodeContext *pMe, QCBORItem *pItem) {
   QCBORDecode_Private_EnterBoundedMapOrArray(pMe, QCBOR_TYPE_MAP, pItem);
}

static inline void
QCBORDecode_EnterArray(QCBORDecodeContext *pMe, QCBORItem *pItem) {
   QCBORDecode_Private_EnterBoundedMapOrArray(pMe, QCBOR_TYPE_ARRAY, pItem);
}


static inline void
QCBORDecode_ExitArray(QCBORDecodeContext *pMe)
{
   QCBORDecode_Private_ExitBoundedMapOrArray(pMe, QCBOR_TYPE_ARRAY);
}

static inline void
QCBORDecode_ExitMap(QCBORDecodeContext *pMe)
{
   QCBORDecode_Private_ExitBoundedMapOrArray(pMe, QCBOR_TYPE_MAP);
}


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_GetArrayOrMap(QCBORDecodeContext *pCtx,
                                  uint8_t             uType,
                                  QCBORItem          *pItem,
                                  UsefulBufC         *pEncodedCBOR);


/* Semi-private funcion used by public inline functions. See qcbor_decode.c */
void
QCBORDecode_Private_SearchAndGetArrayOrMap(QCBORDecodeContext *pCtx,
                                           QCBORItem          *pTarget,
                                           QCBORItem          *pItem,
                                           UsefulBufC         *pEncodedCBOR);


static inline void
QCBORDecode_GetArray(QCBORDecodeContext *pMe,
                     QCBORItem          *pItem,
                     UsefulBufC         *pEncodedCBOR)
{
   QCBORDecode_Private_GetArrayOrMap(pMe, QCBOR_TYPE_ARRAY, pItem, pEncodedCBOR);
}


static inline void
QCBORDecode_GetArrayFromMapN(QCBORDecodeContext *pMe,
                             int64_t             nLabel,
                             QCBORItem          *pItem,
                             UsefulBufC         *pEncodedCBOR)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndGetArrayOrMap(pMe, OneItemSeach, pItem, pEncodedCBOR);
}


static inline void
QCBORDecode_GetArrayFromMapSZ(QCBORDecodeContext *pMe,
                              const char         *szLabel,
                              QCBORItem          *pItem,
                              UsefulBufC         *pEncodedCBOR)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndGetArrayOrMap(pMe, OneItemSeach, pItem, pEncodedCBOR);
#else
   (void)szLabel;
   (void)pItem;
   (void)pEncodedCBOR;
   pMe->uLastError =  QCBOR_ERR_MAP_LABEL_TYPE;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}

static inline void
QCBORDecode_GetMap(QCBORDecodeContext *pMe,
                   QCBORItem          *pItem,
                   UsefulBufC         *pEncodedCBOR)
{
   QCBORDecode_Private_GetArrayOrMap(pMe, QCBOR_TYPE_MAP, pItem, pEncodedCBOR);
}


static inline void
QCBORDecode_GetMapFromMapN(QCBORDecodeContext *pMe,
                           int64_t             nLabel,
                           QCBORItem          *pItem,
                           UsefulBufC         *pEncodedCBOR)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndGetArrayOrMap(pMe, OneItemSeach, pItem, pEncodedCBOR);
}


static inline void
QCBORDecode_GetMapFromMapSZ(QCBORDecodeContext *pMe,
                            const char         *szLabel,
                            QCBORItem          *pItem,
                            UsefulBufC         *pEncodedCBOR)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndGetArrayOrMap(pMe, OneItemSeach, pItem, pEncodedCBOR);
#else
   (void)szLabel;
   (void)pItem;
   (void)pEncodedCBOR;
   pMe->uLastError =  QCBOR_ERR_MAP_LABEL_TYPE;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}



static inline void
QCBORDecode_GetInt64Convert(QCBORDecodeContext *pMe,
                            const uint32_t      uConvertTypes,
                            int64_t            *pnValue)
{
    QCBORItem Item;
    QCBORDecode_Private_GetInt64Convert(pMe, uConvertTypes, pnValue, &Item);
}

static inline void
QCBORDecode_GetInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                  const int64_t       nLabel,
                                  const uint32_t      uConvertTypes,
                                  int64_t            *pnValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetInt64ConvertInMapN(pMe,
                                             nLabel,
                                             uConvertTypes,
                                             pnValue,
                                             &Item);
}

static inline void
QCBORDecode_GetInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                   const char         *szLabel,
                                   const uint32_t     uConvertTypes,
                                   int64_t            *pnValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetInt64ConvertInMapSZ(pMe,
                                              szLabel,
                                              uConvertTypes,
                                              pnValue,
                                              &Item);
}

static inline void
QCBORDecode_GetInt64(QCBORDecodeContext *pMe, int64_t *pnValue)
{
    QCBORDecode_GetInt64Convert(pMe, QCBOR_CONVERT_TYPE_XINT64, pnValue);
}

static inline void
QCBORDecode_GetInt64InMapN(QCBORDecodeContext *pMe,
                           const int64_t       nLabel,
                           int64_t            *pnValue)
{
   QCBORDecode_GetInt64ConvertInMapN(pMe,
                                     nLabel,
                                     QCBOR_CONVERT_TYPE_XINT64,
                                     pnValue);
}

static inline void
QCBORDecode_GetInt64InMapSZ(QCBORDecodeContext *pMe,
                            const char         *szLabel,
                            int64_t            *pnValue)
{
   QCBORDecode_GetInt64ConvertInMapSZ(pMe,
                                      szLabel,
                                      QCBOR_CONVERT_TYPE_XINT64,
                                      pnValue);
}





#ifndef USEFULBUF_DISABLE_ALL_FLOAT
static inline void
QCBORDecode_GetDoubleConvert(QCBORDecodeContext *pMe,
                             const uint32_t      uConvertTypes,
                             double             *pdValue)
{
   QCBORItem Item;
    QCBORDecode_Private_GetDoubleConvert(pMe, uConvertTypes, pdValue, &Item);
}

static inline void
QCBORDecode_GetDoubleConvertInMapN(QCBORDecodeContext *pMe,
                                   const int64_t       nLabel,
                                   uint32_t            uConvertTypes,
                                   double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetDoubleConvertInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              pdValue,
                                              &Item);
}

static inline void
QCBORDecode_GetDoubleConvertInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    const uint32_t      uConvertTypes,
                                    double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetDoubleConvertInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               pdValue,
                                               &Item);
}

static inline void
QCBORDecode_GetDouble(QCBORDecodeContext *pMe, double *pValue)
{
    QCBORDecode_GetDoubleConvert(pMe, QCBOR_CONVERT_TYPE_FLOAT, pValue);
}

static inline void
QCBORDecode_GetDoubleInMapN(QCBORDecodeContext *pMe,
                            const int64_t       nLabel,
                            double             *pdValue)
{
   QCBORDecode_GetDoubleConvertInMapN(pMe,
                                      nLabel,
                                      QCBOR_CONVERT_TYPE_FLOAT,
                                      pdValue);
}

static inline void
QCBORDecode_GetDoubleInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             double             *pdValue)
{
   QCBORDecode_GetDoubleConvertInMapSZ(pMe,
                                       szLabel,
                                       QCBOR_CONVERT_TYPE_FLOAT,
                                       pdValue);
}
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */





static inline void
QCBORDecode_GetByteString(QCBORDecodeContext *pMe,  UsefulBufC *pValue)
{
   // Complier should make this just a 64-bit integer parameter
   const QCBOR_Private_TagSpec TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pValue);
}

static inline void
QCBORDecode_GetByteStringInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                UsefulBufC         *pBstr)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };
   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pBstr);
}

static inline void
QCBORDecode_GetByteStringInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 UsefulBufC         *pBstr)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pBstr);
}


static inline void
QCBORDecode_GetTextString(QCBORDecodeContext *pMe,  UsefulBufC *pValue)
{
   // Complier should make this just 64-bit integer parameter
   const QCBOR_Private_TagSpec TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pValue);
}

static inline void
QCBORDecode_GetTextStringInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                UsefulBufC         *pText)
{
   // This TagSpec only matches text strings; it also should optimize down
   // to passing a 64-bit integer
   const QCBOR_Private_TagSpec TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pText);
}

static inline void
QCBORDecode_GetTextStringInMapSZ(QCBORDecodeContext *pMe,
                                 const               char *szLabel,
                                 UsefulBufC         *pText)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pText);
}

static inline void
QCBORDecode_GetNull(QCBORDecodeContext *pMe)
{
   QCBORItem item;

   QCBORDecode_VGetNext(pMe, &item);
   if(pMe->uLastError == QCBOR_SUCCESS && item.uDataType != QCBOR_TYPE_NULL) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
}

static inline void
QCBORDecode_GetNullInMapN(QCBORDecodeContext *pMe,
                          const int64_t       nLabel)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_NULL, &Item);
}

static inline void
QCBORDecode_GetNullInMapSZ(QCBORDecodeContext *pMe,
                           const char         *szLabel)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_NULL, &Item);
}

static inline void
QCBORDecode_GetUndefined(QCBORDecodeContext *pMe)
{
   QCBORItem item;

   QCBORDecode_VGetNext(pMe, &item);
   if(pMe->uLastError == QCBOR_SUCCESS && item.uDataType != QCBOR_TYPE_UNDEF) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
}

static inline void
QCBORDecode_GetUndefinedInMapN(QCBORDecodeContext *pMe,
                               const int64_t       nLabel)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_UNDEF, &Item);
}

static inline void
QCBORDecode_GetUndefinedInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_UNDEF, &Item);
}



static inline void
QCBORDecode_GetDateString(QCBORDecodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pValue)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DATE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pValue);
}

static inline void
QCBORDecode_GetDateStringInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTagRequirement,
                                UsefulBufC         *pText)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DATE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pText);
}

static inline void
QCBORDecode_GetDateStringInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pText)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DATE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pText);
}

static inline void
QCBORDecode_GetDaysString(QCBORDecodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pValue)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DAYS_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pValue);
}

static inline void
QCBORDecode_GetDaysStringInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTagRequirement,
                                UsefulBufC         *pText)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DAYS_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pText);
}

static inline void
QCBORDecode_GetDaysStringInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pText)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DAYS_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pText);
}



static inline void
QCBORDecode_GetURI(QCBORDecodeContext *pMe,
                   const uint8_t       uTagRequirement,
                   UsefulBufC         *pUUID)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_URI, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pUUID);
}

static inline void
QCBORDecode_GetURIInMapN(QCBORDecodeContext *pMe,
                         const int64_t       nLabel,
                         const uint8_t       uTagRequirement,
                         UsefulBufC         *pUUID)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_URI, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pUUID);
}

static inline void
QCBORDecode_GetURIInMapSZ(QCBORDecodeContext *pMe,
                          const char         *szLabel,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pUUID)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_URI, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pUUID);
}


static inline void
QCBORDecode_GetB64(QCBORDecodeContext *pMe,
                   const uint8_t       uTagRequirement,
                   UsefulBufC         *pB64Text)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pB64Text);
}

static inline void
QCBORDecode_GetB64InMapN(QCBORDecodeContext *pMe,
                         const int64_t       nLabel,
                         const uint8_t       uTagRequirement,
                         UsefulBufC         *pB64Text)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pB64Text);
}

static inline void
QCBORDecode_GetB64InMapSZ(QCBORDecodeContext *pMe,
                          const char         *szLabel,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pB64Text)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };
   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pB64Text);
}


static inline void
QCBORDecode_GetB64URL(QCBORDecodeContext *pMe,
                      const uint8_t       uTagRequirement,
                      UsefulBufC         *pB64Text)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64URL, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pB64Text);
}

static inline void
QCBORDecode_GetB64URLInMapN(QCBORDecodeContext *pMe,
                            const int64_t       nLabel,
                            const uint8_t       uTagRequirement,
                            UsefulBufC         *pB64Text)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64URL, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pB64Text);
}

static inline void
QCBORDecode_GetB64URLInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             const uint8_t       uTagRequirement,
                             UsefulBufC         *pB64Text)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64URL, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pB64Text);
}


static inline void
QCBORDecode_GetRegex(QCBORDecodeContext *pMe,
                     const uint8_t      uTagRequirement,
                     UsefulBufC         *pRegex)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_REGEX, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pRegex);
}

static inline void
QCBORDecode_GetRegexInMapN(QCBORDecodeContext *pMe,
                           const int64_t       nLabel,
                           const uint8_t       uTagRequirement,
                           UsefulBufC         *pRegex)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_REGEX, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pRegex);
}

static inline void
QCBORDecode_GetRegexInMapSZ(QCBORDecodeContext *pMe,
                            const char *        szLabel,
                            const uint8_t       uTagRequirement,
                            UsefulBufC         *pRegex)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_REGEX, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pRegex);
}


static inline void
QCBORDecode_GetMIMEMessage(QCBORDecodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           UsefulBufC         *pMessage,
                           bool               *pbIsTag257)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state, do nothing */
      return;
   }

   QCBORItem  Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_Private_GetMIME(uTagRequirement,
                                                          &Item,
                                                          pMessage,
                                                          pbIsTag257);
}

static inline void
QCBORDecode_GetMIMEMessageInMapN(QCBORDecodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pMessage,
                                 bool               *pbIsTag257)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)QCBORDecode_Private_GetMIME(uTagRequirement,
                                                             &Item,
                                                             pMessage,
                                                             pbIsTag257);
   }
}

static inline void
QCBORDecode_GetMIMEMessageInMapSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  UsefulBufC         *pMessage,
                                  bool               *pbIsTag257)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)QCBORDecode_Private_GetMIME(uTagRequirement,
                                                             &Item,
                                                             pMessage,
                                                             pbIsTag257);
   }
}


static inline void
QCBORDecode_GetBinaryUUID(QCBORDecodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pUUID)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_UUID, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedString(pMe, TagSpec, pUUID);
}

static inline void
QCBORDecode_GetBinaryUUIDInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTagRequirement,
                                UsefulBufC         *pUUID)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_UUID, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pUUID);
}

static inline void
QCBORDecode_GetBinaryUUIDInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pUUID)
{
   const QCBOR_Private_TagSpec TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_UUID, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pUUID);
}


#ifdef __cplusplus
}
#endif

#endif /* qcbor_spiffy_decode_h */
