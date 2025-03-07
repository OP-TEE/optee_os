// SPDX-License-Identifier: BSD-3-Clause
/* ===========================================================================
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2024, Laurence Lundblade.
 * Copyright (c) 2021, Arm Limited.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors, nor the name "Laurence Lundblade" may be used to
 *       endorse or promote products derived from this software without
 *       specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ========================================================================= */


#ifndef qcbor_encode_h
#define qcbor_encode_h


#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_private.h"
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif


/**
 * @file qcbor_encode.h
 *
 * @anchor Overview
 *
 * # QCBOR Overview
 *
 * This implements CBOR -- Concise Binary Object Representation as
 * defined in [RFC 8949] (https://tools.ietf.org/html/rfc8949). More
 * information is at http://cbor.io.  This is a near-complete implementation of
 * the specification. [RFC 8742] (https://tools.ietf.org/html/rfc8742) CBOR
 * Sequences is also supported. Limitations are listed further down.
 *
 * See @ref Encoding for general discussion on encoding,
 * @ref BasicDecode for general discussion on the basic decode features
 * and @ref SpiffyDecode for general discussion on the easier-to-use
 * decoder functions.
 *
 * CBOR is intentionally designed to be translatable to JSON, but not
 * all CBOR can convert to JSON. See RFC 8949 for more info on how to
 * construct CBOR that is the most JSON friendly.
 *
 * The memory model for encoding and decoding is that encoded CBOR must
 * be in a contiguous buffer in memory.  During encoding the caller must
 * supply an output buffer and if the encoding would go off the end of
 * the buffer an error is returned.  During decoding the caller supplies
 * the encoded CBOR in a contiguous buffer and the decoder returns
 * pointers and lengths into that buffer for strings.
 *
 * This implementation does not require malloc. All data structures
 * passed in/out of the APIs can fit on the stack.
 *
 * Decoding of indefinite-length strings is a special case that requires
 * a "string allocator" to allocate memory into which the segments of
 * the string are coalesced. Without this, decoding will error out if an
 * indefinite-length string is encountered (indefinite-length maps and
 * arrays do not require the string allocator). A simple string
 * allocator called MemPool is built-in and will work if supplied with a
 * block of memory to allocate. The string allocator can optionally use
 * malloc() or some other custom scheme.
 *
 * Here are some terms and definitions:
 *
 * - "Item", "Data Item": An integer or string or such. The basic "thing" that
 * CBOR is about. An array is an item itself that contains some items.
 *
 * - "Array": An ordered sequence of items, the same as JSON.
 *
 * - "Map": A collection of label/value pairs. Each pair is a data
 * item. A JSON "object" is the same as a CBOR "map".
 *
 * - "Label": The data item in a pair in a map that names or identifies
 * the pair, not the value. This implementation refers to it as a
 * "label".  JSON refers to it as the "name". The CBOR RFC refers to it
 * this as a "key".  This implementation chooses label instead because
 * key is too easily confused with a cryptographic key. The COSE
 * standard, which uses CBOR, has also chosen to use the term "label"
 * rather than "key" for this same reason.
 *
 * - "Key": See "Label" above.
 *
 * - "Tag": A data item that is an explicitly labeled new data
 * type made up of the tagging integer and the tag content.
 * See @ref Tags-Overview and @ref Tag-Usage.
 *
 * - "Initial Byte": The first byte of an encoded item. Encoding and
 * decoding of this byte is taken care of by the implementation.
 *
 * - "Additional Info": In addition to the major type, all data items
 * have some other info. This is usually the length of the data but can
 * be several other things. Encoding and decoding of this is taken care
 * of by the implementation.
 *
 * CBOR has two mechanisms for tagging and labeling the data values like
 * integers and strings. For example, an integer that represents
 * someone's birthday in epoch seconds since Jan 1, 1970 could be
 * encoded like this:
 *
 * - First it is CBOR_MAJOR_TYPE_POSITIVE_INT (@ref QCBOR_TYPE_INT64),
 * the primitive positive integer.
 *
 * - Next it has a "tag" @ref CBOR_TAG_DATE_EPOCH indicating the integer
 * represents a date in the form of the number of seconds since Jan 1,
 * 1970.
 *
 * - Last it has a string "label" like "BirthDate" indicating the
 * meaning of the data.
 *
 * The encoded binary looks like this:
 *
 *      a1                      # Map of 1 item
 *         69                   # Indicates text string of 9 bytes
 *           426972746844617465 # The text "BirthDate"
 *        c1                    # Tags next integer as epoch date
 *           1a                 # Indicates a 4-byte integer
 *               580d4172       # unsigned integer date 1477263730
 *
 * Implementors using this API will primarily work with
 * labels. Generally, tags are only needed for making up new data
 * types. This implementation covers most of the data types defined in
 * the RFC using tags. It also, allows for the use of custom tags if
 * necessary.
 *
 * This implementation explicitly supports labels that are text strings
 * and integers. Text strings translate nicely into JSON objects and are
 * very readable.  Integer labels are much less readable but can be very
 * compact. If they are in the range of 0 to 23, they take up only one
 * byte.
 *
 * CBOR allows a label to be any type of data including an array or a
 * map. It is possible to use this API to construct and parse such
 * labels, but it is not explicitly supported.
 *
 * @anchor Encoding
 *
 * ## Encoding
 *
 * A common encoding usage mode is to invoke the encoding twice. First
 * with the output buffer as @ref SizeCalculateUsefulBuf to compute the
 * length of the needed output buffer. The correct sized output buffer
 * is allocated. The encoder is invoked a second time with the allocated
 * output buffer.
 *
 * The double invocation is not required if the maximum output buffer
 * size can be predicted. This is usually possible for simple CBOR
 * structures.
 *
 * If a buffer too small to hold the encoded output is given, the error
 * @ref QCBOR_ERR_BUFFER_TOO_SMALL will be returned. Data will never be
 * written off the end of the output buffer no matter which functions
 * here are called or what parameters are passed to them.
 *
 * The encoding error handling is simple. The only possible errors are
 * trying to encode structures that are too large or too complex. There
 * are no internal malloc calls so there will be no failures for out of
 * memory.  The error state is tracked internally, so there is no need
 * to check for errors when encoding. Only the return code from
 * QCBOREncode_Finish() need be checked as once an error happens, the
 * encoder goes into an error state and calls to it to add more data
 * will do nothing. An error check is not needed after every data item
 * is added.
 *
 * Encoding generally proceeds by calling QCBOREncode_Init(), calling
 * lots of @c QCBOREncode_AddXxx() functions and calling
 * QCBOREncode_Finish(). There are many @c QCBOREncode_AddXxx()
 * functions for various data types. The input buffers need only to be
 * valid during the @c QCBOREncode_AddXxx() calls as the data is copied
 * into the output buffer.
 *
 * There are three `Add` functions for each data type. The first / main
 * one for the type is for adding the data item to an array.  The second
 * one's name ends in `ToMap`, is used for adding data items to maps and
 * takes a string argument that is its label in the map. The third one
 * ends in `ToMapN`, is also used for adding data items to maps, and
 * takes an integer argument that is its label in the map.
 *
 * The simplest aggregate type is an array, which is a simple ordered
 * set of items without labels the same as JSON arrays. Call
 * QCBOREncode_OpenArray() to open a new array, then various @c
 * QCBOREncode_AddXxx() functions to put items in the array and then
 * QCBOREncode_CloseArray(). Nesting to the limit @ref
 * QCBOR_MAX_ARRAY_NESTING is allowed.  All opens must be matched by
 * closes or an encoding error will be returned.
 *
 * The other aggregate type is a map which does use labels. The `Add`
 * functions that end in `ToMap` and `ToMapN` are convenient ways to add
 * labeled data items to a map. You can also call any type of `Add`
 * function once to add a label of any type and then call any type of
 * `Add` again to add its value.
 *
 * Note that when you nest arrays or maps in a map, the nested array or
 * map has a label.
 *
 * Many CBOR-based protocols start with an array or map. This makes them
 * self-delimiting. No external length or end marker is needed to know
 * the end. It is also possible not start this way, in which case this
 * it is usually called a CBOR sequence which is described in
 * [RFC 8742] (https://tools.ietf.org/html/rfc8742). This encoder supports
 * either just by whether the first item added is an array, map or other.
 *
 * If QCBOR is compiled with QCBOR_DISABLE_ENCODE_USAGE_GUARDS defined,
 * the errors QCBOR_ERR_CLOSE_MISMATCH, QCBOR_ERR_ARRAY_TOO_LONG,
 * QCBOR_ERR_TOO_MANY_CLOSES, QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN, and
 * QCBOR_ERR_ENCODE_UNSUPPORTED will never be returned. It is up to the
 * caller to make sure that opened maps, arrays and byte-string wrapping
 * is closed correctly and that QCBOREncode_AddType7() is called
 * correctly.  With this defined, it is easier to make a mistake when
 * authoring the encoding of a protocol that will output not well formed
 * CBOR, but as long as the calling code is correct, it is safe to
 * disable these checks. Bounds checking that prevents security issues
 * in the code is still enforced. This define reduces the size of
 * encoding object code by about 150 bytes.
 *
 * @anchor Tags-Overview
 *
 * ## Tags Overview
 *
 * Any CBOR data item can be made into a tag to add semantics, define a
 * new data type or such. Some tags are fully standardized and some are
 * just registered. Others are not registered and used in a proprietary
 * way.
 *
 * Encoding and decoding of many of the registered tags is fully
 * implemented by QCBOR. It is also possible to encode and decode tags
 * that are not directly supported.  For many use cases the built-in tag
 * support should be adequate.
 *
 * For example, the registered epoch date tag is supported in encoding
 * by QCBOREncode_AddDateEpoch() and in decoding by @ref
 * QCBOR_TYPE_DATE_EPOCH and the @c epochDate member of @ref
 * QCBORItem. This is typical of the built-in tag support. There is an
 * API to encode data for it and a @c QCBOR_TYPE_XXX when it is decoded.
 *
 * Tags are registered in the [IANA CBOR Tags Registry]
 * (https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml). There
 * are roughly three options to create a new tag. First, a public
 * specification can be created and the new tag registered with IANA.
 * This is the most formal. Second, the new tag can be registered with
 * IANA with just a short description rather than a full specification.
 * These tags must be greater than 256. Third, a tag can be used without
 * any IANA registration, though the registry should be checked to see
 * that the new value doesn't collide with one that is registered. The
 * value of these tags must be 256 or larger.
 *
 * See also @ref CBORTags and @ref Tag-Usage
 *
 * The encoding side of tags not built-in is handled by
 * QCBOREncode_AddTag() and is relatively simple. Tag decoding is more
 * complex and mainly handled by QCBORDecode_GetNext(). Decoding of the
 * structure of tagged data not built-in (if there is any) has to be
 * implemented by the caller.
 *
 * @anchor Floating-Point
 *
 * ## Floating-Point
 *
 * By default QCBOR fully supports IEEE 754 floating-point:
 *  - Encode/decode of double, single and half-precision
 *  - CBOR preferred serialization of floating-point
 *  - Floating-point epoch dates
 *
 * For the most part, the type double is used in the interface for
 * floating-point values. In the default configuration, all decoded
 * floating-point values are returned as a double.
 *
 * With CBOR preferred serialization, the encoder outputs the smallest
 * representation of the double or float that preserves precision. Zero,
 * NaN and infinity are always output as a half-precision, each taking
 * just 2 bytes. This reduces the number of bytes needed to encode
 * double and single-precision, especially if zero, NaN and infinity are
 * frequently used.
 *
 * To avoid use of preferred serialization in the standard configuration
 * when encoding, use QCBOREncode_AddDoubleNoPreferred() or
 * QCBOREncode_AddFloatNoPreferred().
 *
 * This implementation of preferred floating-point serialization and
 * half-precision does not depend on the CPU having floating-point HW or
 * the compiler bringing in a (sometimes large) library to compensate
 * for lack of CPU support. This implementation uses shifts and masks
 * rather than floating-point functions.
 *
 * To reduce overall object code by about 900 bytes, define
 * QCBOR_DISABLE_PREFERRED_FLOAT. This will eliminate all support for
 * preferred serialization and half-precision. An error will be returned
 * when attempting to decode half-precision. A float will always be
 * encoded and decoded as 32-bits and a double will always be encoded
 * and decoded as 64 bits.
 *
 * Note that even if QCBOR_DISABLE_PREFERRED_FLOAT is not defined all
 * the float-point encoding object code can be avoided by never calling
 * any functions that encode double or float. Just not calling
 * floating-point functions will reduce object code by about 500 bytes.
 *
 * On CPUs that have no floating-point hardware,
 * QCBOR_DISABLE_FLOAT_HW_USE should be defined in most cases. If it is
 * not, then the compiler will bring in possibly large software
 * libraries to compensate. Defining QCBOR_DISABLE_FLOAT_HW_USE reduces
 * object code size on CPUs with floating-point hardware by a tiny
 * amount and eliminates the need for <math.h>
 *
 * When QCBOR_DISABLE_FLOAT_HW_USE is defined, trying to decoding
 * floating-point dates will give error
 * @ref QCBOR_ERR_FLOAT_DATE_DISABLED and decoded single-precision
 * numbers will be returned as @ref QCBOR_TYPE_FLOAT instead of
 * converting them to double as usual.
 *
 * If both QCBOR_DISABLE_FLOAT_HW_USE and QCBOR_DISABLE_PREFERRED_FLOAT
 * are defined, then the only thing QCBOR can do is encode/decode a C
 * float type as 32-bits and a C double type as 64-bits. Floating-point
 * epoch dates will be unsupported.
 *
 * If USEFULBUF_DISABLE_ALL_FLOAT is defined, then floating point
 * support is completely disabled. Decoding functions return
 * @ref QCBOR_ERR_ALL_FLOAT_DISABLED if a floating point value is
 * encountered during decoding. Functions that are encoding floating
 * point values are not available.
 *
 * ## Limitations
 *
 * Summary limitations:
 * - The entire encoded CBOR must fit into contiguous memory.
 * - Max size of encoded CBOR data is a few bytes less than
 *   @c UINT32_MAX (4GB).
 * - Max array / map nesting level when encoding or decoding is
 *   @ref QCBOR_MAX_ARRAY_NESTING (this is typically 15).
 * - Max items in an array or map when encoding or decoding is
 *   @ref QCBOR_MAX_ITEMS_IN_ARRAY (typically 65,536).
 * - Does not directly support labels in maps other than text strings & integers.
 * - Does not directly support integer labels beyond whats fits in @c int64_t
 *   or @c uint64_t.
 * - Epoch dates limited to @c INT64_MAX (+/- 292 billion years).
 * - Exponents for bigfloats and decimal integers are limited to whats fits in
 *   @c int64_t.
 * - Tags on labels are ignored during decoding.
 * - The maximum tag nesting is @c QCBOR_MAX_TAGS_PER_ITEM (typically 4).
 * - Works only on 32- and 64-bit CPUs.
 * - QCBORDecode_EnterBstrWrapped() doesn't work on indefinite-length strings.
 *
 * The public interface uses @c size_t for all lengths. Internally the
 * implementation uses 32-bit lengths by design to use less memory and
 * fit structures on the stack. This limits the encoded CBOR it can
 * work with to size @c UINT32_MAX (4GB).
 *
 * This implementation requires two's compliment integers. While
 * C doesn't require two's compliment,  <stdint.h> does. Other
 * parts of this implementation may also require two's compliment.
 */


/**
 * The size of the buffer to be passed to QCBOREncode_EncodeHead(). It
 * is one byte larger than sizeof(uint64_t) + 1, the actual maximum
 * size of the head of a CBOR data item because
 * QCBOREncode_EncodeHead() needs one extra byte to work.
 */
#define QCBOR_HEAD_BUFFER_SIZE  (sizeof(uint64_t) + 2)


/**
 * Output the full CBOR tag. See @ref CBORTags, @ref Tag-Usage and
 * @ref Tags-Overview.
 */
#define QCBOR_ENCODE_AS_TAG      0

/**
 * Output only the 'borrowed' content format for the relevant tag.
 * See @ref CBORTags, @ref Tag-Usage and @ref Tags-Overview.
 */
#define QCBOR_ENCODE_AS_BORROWED 1


/**
 * QCBOREncodeContext is the data type that holds context for all the
 * encoding functions. It is less than 200 bytes, so it can go on the
 * stack. The contents are opaque, and the caller should not access
 * internal members.  A context may be re used serially as long as it is
 * re initialized.
 */
typedef struct _QCBOREncodeContext QCBOREncodeContext;


/**
 * Initialize the encoder to prepare to encode some CBOR.
 *
 * @param[in,out]  pCtx     The encoder context to initialize.
 * @param[in]      Storage  The buffer into which the encoded result
 *                          will be written.
 *
 * Call this once at the start of an encoding of some CBOR. Then call
 * the many functions like QCBOREncode_AddInt64() and
 * QCBOREncode_AddText() to add the different data items. Finally,
 * call QCBOREncode_Finish() to get the pointer and length of the
 * encoded result.
 *
 * The primary purpose of this function is to give the pointer and
 * length of the output buffer into which the encoded CBOR will be
 * written. This is done with a @ref UsefulBuf structure, which is
 * just a pointer and length (it is equivalent to two parameters, one
 * a pointer and one a length, but a little prettier).
 *
 * The output buffer can be allocated any way (malloc, stack,
 * static). It is just some memory that QCBOR writes to. The length
 * must be the length of the allocated buffer. QCBOR will never write
 * past that length, but might write up to that length. If the buffer
 * is too small, encoding will go into an error state and not write
 * anything further.
 *
 * If allocating on the stack the convenience macro
 * UsefulBuf_MAKE_STACK_UB() can be used, but its use is not required.
 *
 * Since there is no reallocation or such, the output buffer must be
 * correctly sized when passed in here. It is OK, but wasteful if it
 * is too large. One way to pick the size is to figure out the maximum
 * size that will ever be needed and hard code a buffer of that size.
 *
 * Another way to do it is to have QCBOR calculate it for you. To do
 * this, pass @ref SizeCalculateUsefulBuf for @c Storage.  Then call
 * all the functions to add the CBOR exactly as if encoding for
 * real. Finally, call QCBOREncode_FinishGetSize().  Once the length
 * is obtained, allocate a buffer of that size, call
 * QCBOREncode_Init() again with the real buffer. Call all the add
 * functions again and finally, QCBOREncode_Finish() to obtain the
 * final result. This uses twice the CPU time, but that is usually not
 * an issue.
 *
 * See QCBOREncode_Finish() for how the pointer and length for the
 * encoded CBOR is returned.
 *
 * For practical purposes QCBOR can't output encoded CBOR larger than
 * @c UINT32_MAX (4GB) even on 64-bit CPUs because the internal
 * offsets used to track the start of an array/map are 32 bits to
 * reduce the size of the encoding context.
 *
 * A @ref QCBOREncodeContext can be reused over and over as long as
 * QCBOREncode_Init() is called before each use.
 */
void
QCBOREncode_Init(QCBOREncodeContext *pCtx, UsefulBuf Storage);


/**
 * @brief  Add a signed 64-bit integer to the encoded output.
 *
 * @param[in] pCtx   The encoding context to add the integer to.
 * @param[in] nNum   The integer to add.
 *
 * The integer will be encoded and added to the CBOR output.
 *
 * This function figures out the size and the sign and encodes in the
 * correct minimal CBOR. Specifically, it will select CBOR major type
 * 0 or 1 based on sign and will encode to 1, 2, 4 or 8 bytes
 * depending on the value of the integer. Values less than 24
 * effectively encode to one byte because they are encoded in with the
 * CBOR major type.  This is a neat and efficient characteristic of
 * CBOR that can be taken advantage of when designing CBOR-based
 * protocols. If integers like tags can be kept between -23 and 23
 * they will be encoded in one byte including the major type.
 *
 * If you pass a smaller int, say an @c int16_t or a small value, say
 * 100, the encoding will still be CBOR's most compact that can
 * represent the value.  For example, CBOR always encodes the value 0
 * as one byte, 0x00. The representation as 0x00 includes
 * identification of the type as an integer too as the major type for
 * an integer is 0. See [RFC 8949]
 * (https://tools.ietf.org/html/rfc8949) Appendix A for more examples
 * of CBOR encoding. This compact encoding is also preferred
 * serialization CBOR as per section 34.1 in RFC 8949.
 *
 * There are no functions to add @c int16_t or @c int32_t because they
 * are not necessary because this always encodes to the smallest
 * number of bytes based on the value (If this code is running on a
 * 32-bit machine having a way to add 32-bit integers would reduce
 * code size some).
 *
 * If the encoding context is in an error state, this will do
 * nothing. If an error occurs when adding this integer, the internal
 * error flag will be set, and the error will be returned when
 * QCBOREncode_Finish() is called.
 *
 * See also QCBOREncode_AddUInt64().
 */
void
QCBOREncode_AddInt64(QCBOREncodeContext *pCtx, int64_t nNum);

static void
QCBOREncode_AddInt64ToMap(QCBOREncodeContext *pCtx, const char *szLabel, int64_t uNum);

static void
QCBOREncode_AddInt64ToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, int64_t uNum);


/**
 * @brief  Add an unsigned 64-bit integer to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the integer to.
 * @param[in] uNum  The integer to add.
 *
 * The integer will be encoded and added to the CBOR output.
 *
 * The only reason so use this function is for integers larger than
 * @c INT64_MAX and smaller than @c UINT64_MAX. Otherwise
 * QCBOREncode_AddInt64() will work fine.
 *
 * Error handling is the same as for QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddUInt64(QCBOREncodeContext *pCtx, uint64_t uNum);

static void
QCBOREncode_AddUInt64ToMap(QCBOREncodeContext *pCtx, const char *szLabel, uint64_t uNum);

static void
QCBOREncode_AddUInt64ToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, uint64_t uNum);


/**
 * @brief  Add a UTF-8 text string to the encoded output.
 *
 * @param[in] pCtx   The encoding context to add the text to.
 * @param[in] Text   Pointer and length of text to add.
 *
 * The text passed in must be unencoded UTF-8 according to [RFC 3629]
 * (https://tools.ietf.org/html/rfc3629). There is no NULL
 * termination. The text is added as CBOR major type 3.
 *
 * If called with @c nBytesLen equal to 0, an empty string will be
 * added. When @c nBytesLen is 0, @c pBytes may be @c NULL.
 *
 * Note that the restriction of the buffer length to a @c uint32_t is
 * entirely intentional as this encoder is not capable of encoding
 * lengths greater. This limit to 4GB for a text string should not be
 * a problem.
 *
 * Text lines in Internet protocols (on the wire) are delimited by
 * either a CRLF or just an LF. Officially many protocols specify
 * CRLF, but implementations often work with either. CBOR type 3 text
 * can be either line ending, even a mixture of both.
 *
 * Operating systems usually have a line end convention. Windows uses
 * CRLF. Linux and MacOS use LF. Some applications on a given OS may
 * work with either and some may not.
 *
 * The majority of use cases and CBOR protocols using type 3 text will
 * work with either line ending. However, some use cases or protocols
 * may not work with either in which case translation to and/or from
 * the local line end convention, typically that of the OS, is
 * necessary.
 *
 * QCBOR does no line ending translation for type 3 text when encoding
 * and decoding.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddText(QCBOREncodeContext *pCtx, UsefulBufC Text);

static void
QCBOREncode_AddTextToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Text);

static void
QCBOREncode_AddTextToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC Text);


/**
 * @brief  Add a UTF-8 text string to the encoded output.
 *
 * @param[in] pCtx      The encoding context to add the text to.
 * @param[in] szString  Null-terminated text to add.
 *
 * This works the same as QCBOREncode_AddText().
 */
static void
QCBOREncode_AddSZString(QCBOREncodeContext *pCtx, const char *szString);

static void
QCBOREncode_AddSZStringToMap(QCBOREncodeContext *pCtx, const char *szLabel, const char *szString);

static void
QCBOREncode_AddSZStringToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, const char *szString);


#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/**
 * @brief Add a double-precision floating-point number to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the double to.
 * @param[in] dNum  The double-precision number to add.
 *
 * This encodes and outputs a floating-point number. CBOR major type 7
 * is used.
 *
 * This implements preferred serialization, selectively encoding the
 * double-precision floating-point number as either double-precision,
 * single-precision or half-precision. Infinity, NaN and 0 are always
 * encoded as half-precision. If no precision will be lost in the
 * conversion to half-precision, then it will be converted and
 * encoded. If not and no precision will be lost in conversion to
 * single-precision, then it will be converted and encoded. If not,
 * then no conversion is performed, and it encoded as a
 * double-precision.
 *
 * Half-precision floating-point numbers take up 2 bytes, half that of
 * single-precision, one quarter of double-precision
 *
 * This automatically reduces the size of encoded CBOR, maybe even by
 * four if most of values are 0, infinity or NaN.
 *
 * When decoded, QCBOR will usually return these values as
 * double-precision.
 *
 * It is possible to disable this preferred serialization when compiling
 * QCBOR. In that case, this functions the same as
 * QCBOREncode_AddDoubleNoPreferred().
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddDoubleNoPreferred(), QCBOREncode_AddFloat()
 * and QCBOREncode_AddFloatNoPreferred() and @ref Floating-Point.
 */
static void
QCBOREncode_AddDouble(QCBOREncodeContext *pCtx, double dNum);

static void
QCBOREncode_AddDoubleToMap(QCBOREncodeContext *pCtx, const char *szLabel, double dNum);

static void
QCBOREncode_AddDoubleToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, double dNum);


/**
 * @brief Add a single-precision floating-point number to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the double to.
 * @param[in] fNum  The single-precision number to add.
 *
 * This is identical to QCBOREncode_AddDouble() except the input is
 * single-precision.
 *
 * See also QCBOREncode_AddDouble(), QCBOREncode_AddDoubleNoPreferred(),
 * and QCBOREncode_AddFloatNoPreferred() and @ref Floating-Point.
 */
static void
QCBOREncode_AddFloat(QCBOREncodeContext *pCtx, float fNum);

static void
QCBOREncode_AddFloatToMap(QCBOREncodeContext *pCtx, const char *szLabel, float fNum);

static void
QCBOREncode_AddFloatToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, float dNum);


/**
 * @brief Add a double-precision floating-point number without preferred encoding.
 *
 * @param[in] pCtx  The encoding context to add the double to.
 * @param[in] dNum  The double-precision number to add.
 *
 * This always outputs the number as a 64-bit double-precision.
 * Preferred serialization is not used.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddDouble(), QCBOREncode_AddFloat(), and
 * QCBOREncode_AddFloatNoPreferred() and @ref Floating-Point.
 */
static void
QCBOREncode_AddDoubleNoPreferred(QCBOREncodeContext *pCtx, double dNum);

static void
QCBOREncode_AddDoubleNoPreferredToMap(QCBOREncodeContext *pCtx, const char *szLabel, double dNum);

static void
QCBOREncode_AddDoubleNoPreferredToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, double dNum);


/**
 * @brief Add a single-precision floating-point number without preferred encoding.
 *
 * @param[in] pCtx  The encoding context to add the double to.
 * @param[in] fNum  The single-precision number to add.
 *
 * This always outputs the number as a 32-bit single-precision.
 * Preferred serialization is not used.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddDouble(), QCBOREncode_AddFloat(), and
 * QCBOREncode_AddDoubleNoPreferred() and @ref Floating-Point.
 */
static void
QCBOREncode_AddFloatNoPreferred(QCBOREncodeContext *pCtx, float fNum);

static void
QCBOREncode_AddFloatNoPreferredToMap(QCBOREncodeContext *pCtx, const char *szLabel, float fNum);

static void
QCBOREncode_AddFloatNoPreferredToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, float fNum);
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */


/**
 * @brief Add an optional tag.
 *
 * @param[in] pCtx  The encoding context to add the tag to.
 * @param[in] uTag  The tag to add
 *
 * This outputs a CBOR major type 6 item that tags the next data item
 * that is output usually to indicate it is some new data type.
 *
 * For many of the common standard tags, a function to encode data
 * using it is provided and this is not needed. For example,
 * QCBOREncode_AddDateEpoch() already exists to output integers
 * representing dates with the right tag.
 *
 * The tag is applied to the next data item added to the encoded
 * output. That data item that is to be tagged can be of any major
 * CBOR type. Any number of tags can be added to a data item by
 * calling this multiple times before the data item is added.
 *
 * See @ref Tags-Overview for discussion of creating new non-standard
 * tags. See QCBORDecode_GetNext() for discussion of decoding custom
 * tags.
 */
static void
QCBOREncode_AddTag(QCBOREncodeContext *pCtx, uint64_t uTag);


/**
 * @brief  Add an epoch-based date.
 *
 * @param[in] pCtx             The encoding context to add the date to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] nDate            Number of seconds since 1970-01-01T00:00Z
 *                             in UTC time.
 *
 * As per RFC 8949 this is similar to UNIX/Linux/POSIX dates. This is
 * the most compact way to specify a date and time in CBOR. Note that
 * this is always UTC and does not include the time zone.  Use
 * QCBOREncode_AddDateString() if you want to include the time zone.
 *
 * The preferred integer serialization rules apply here so the date will be
 * encoded in a minimal number of bytes. Until about the year 2106
 * these dates will encode in 6 bytes -- one byte for the tag, one
 * byte for the type and 4 bytes for the integer. After that it will
 * encode to 10 bytes.
 *
 * Negative values are supported for dates before 1970.
 *
 * If you care about leap-seconds and that level of accuracy, make sure
 * the system you are running this code on does it correctly. This code
 * just takes the value passed in.
 *
 * This implementation cannot encode fractional seconds using float or
 * double even though that is allowed by CBOR, but you can encode them
 * if you want to by calling QCBOREncode_AddTag() and QCBOREncode_AddDouble().
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddTDaysEpoch().
 */
static void
QCBOREncode_AddTDateEpoch(QCBOREncodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          int64_t             nDate);

static void
QCBOREncode_AddTDateEpochToMapSZ(QCBOREncodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 int64_t             nDate);

static void
QCBOREncode_AddTDateEpochToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                int64_t             nDate);


static void
QCBOREncode_AddDateEpoch(QCBOREncodeContext *pCtx,
                         int64_t             nDate);

static void
QCBOREncode_AddDateEpochToMap(QCBOREncodeContext *pCtx,
                              const char         *szLabel,
                              int64_t             nDate);

static void
QCBOREncode_AddDateEpochToMapN(QCBOREncodeContext *pCtx,
                               int64_t             nLabel,
                               int64_t             nDate);



/**
 *  @brief  Add an epoch-based day-count date.
 *
 *  @param[in] pCtx             The encoding context to add the date to.
 *  @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                              @ref QCBOR_ENCODE_AS_BORROWED.
 *  @param[in] nDays            Number of days before or after 1970-01-0.
 *
 * This date format is described in
 * [RFC 8943] (https://tools.ietf.org/html/rfc8943).
 *
 * The preferred integer serialization rules apply here so the date
 * will be encoded in a minimal number of bytes. Until about the year
 * 2149 these dates will encode in 4 bytes -- one byte for the tag,
 * one byte for the type and 2 bytes for the integer.
 *
 * See also QCBOREncode_AddTDateEpoch().
 */
static void
QCBOREncode_AddTDaysEpoch(QCBOREncodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          int64_t             nDays);

static void
QCBOREncode_AddTDaysEpochToMapSZ(QCBOREncodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 int64_t             nDays);

static void
QCBOREncode_AddTDaysEpochToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                int64_t             nDays);




/**
 * @brief Add a byte string to the encoded output.
 *
 * @param[in] pCtx   The encoding context to add the bytes to.
 * @param[in] Bytes  Pointer and length of the input data.
 *
 * Simply adds the bytes to the encoded output as CBOR major type 2.
 *
 * If called with @c Bytes.len equal to 0, an empty string will be
 * added. When @c Bytes.len is 0, @c Bytes.ptr may be @c NULL.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddBytes(QCBOREncodeContext *pCtx, UsefulBufC Bytes);

static void
QCBOREncode_AddBytesToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Bytes);

static void
QCBOREncode_AddBytesToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC Bytes);


/**
 * @brief Set up to write a byte string value directly to encoded output.
 *
 * @param[in] pCtx     The encoding context to add the bytes to.
 * @param[out] pPlace  Pointer and length of place to write byte string value.
 *
 * QCBOREncode_AddBytes() is the normal way to encode a byte string.
 * This is for special cases and by passes some of the pointer safety.
 *
 * The purpose of this is to output the bytes that make up a byte
 * string value directly to the QCBOR output buffer so you don't need
 * to have a copy of it in memory. This is particularly useful if the
 * byte string is large, for example, the encrypted payload of a
 * COSE_Encrypt message. The payload encryption algorithm can output
 * directly to the encoded CBOR buffer, perhaps by making it the
 * output buffer for some function (e.g. symmetric encryption) or by
 * multiple writes.
 *
 * The pointer in @c pPlace is where to start writing. Writing is just
 * copying bytes to the location by the pointer in \c pPlace.  Writing
 * past the length in @c pPlace will be writing off the end of the
 * output buffer.
 *
 * If there is no room in the output buffer @ref NULLUsefulBuf will be
 * returned and there is no need to call QCBOREncode_CloseBytes().
 *
 * The byte string must be closed by calling QCBOREncode_CloseBytes().
 *
 * Warning: this bypasses some of the usual checks provided by QCBOR
 * against writing off the end of the encoded output buffer.
 */
void
QCBOREncode_OpenBytes(QCBOREncodeContext *pCtx, UsefulBuf *pPlace);

static void
QCBOREncode_OpenBytesInMapSZ(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             UsefulBuf          *pPlace);

static void
QCBOREncode_OpenBytesInMapN(QCBOREncodeContext *pCtx,
                            int64_t             nLabel,
                            UsefulBuf          *pPlace);


/**
 *  @brief Close out a byte string written directly to encoded output.
 *
 *  @param[in] pCtx      The encoding context to add the bytes to.
 *  @param[out] uAmount  The number of bytes written, the length of the
 *                       byte string.
 *
 * This closes out a call to QCBOREncode_OpenBytes().  This inserts a
 * CBOR header at the front of the byte string value to make it a
 * well-formed byte string.
 *
 * If there was no call to QCBOREncode_OpenBytes() then @ref
 * QCBOR_ERR_TOO_MANY_CLOSES is set.
 */
void
QCBOREncode_CloseBytes(QCBOREncodeContext *pCtx, size_t uAmount);


/**
 * @brief Add a binary UUID to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the UUID to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Bytes            Pointer and length of the binary UUID.
 *
 * A binary UUID as defined in [RFC 4122]
 * (https://tools.ietf.org/html/rfc4122) is added to the output.
 *
 * It is output as CBOR major type 2, a binary string, with tag @ref
 * CBOR_TAG_BIN_UUID indicating the binary string is a UUID.
 */
static void
QCBOREncode_AddTBinaryUUID(QCBOREncodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBufC          Bytes);

static void
QCBOREncode_AddTBinaryUUIDToMapSZ(QCBOREncodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC          Bytes);

static void
QCBOREncode_AddTBinaryUUIDToMapN(QCBOREncodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC          Bytes);


static void
QCBOREncode_AddBinaryUUID(QCBOREncodeContext *pCtx, UsefulBufC Bytes);

static void
QCBOREncode_AddBinaryUUIDToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Bytes);

static void
QCBOREncode_AddBinaryUUIDToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC Bytes);


/**
 * @brief Add a positive big number to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the big number to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Bytes            Pointer and length of the big number.
 *
 * Big numbers are integers larger than 64-bits. Their format is
 * described in [RFC 8949] (https://tools.ietf.org/html/rfc8949).
 *
 * It is output as CBOR major type 2, a binary string, with tag
 * @ref CBOR_TAG_POS_BIGNUM indicating the binary string is a positive
 * big number.
 *
 * Often big numbers are used to represent cryptographic keys,
 * however, COSE which defines representations for keys chose not to
 * use this particular type.
 */
static void
QCBOREncode_AddTPositiveBignum(QCBOREncodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               UsefulBufC          Bytes);

static void
QCBOREncode_AddTPositiveBignumToMapSZ(QCBOREncodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC          Bytes);

static void
QCBOREncode_AddTPositiveBignumToMapN(QCBOREncodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC          Bytes);


static void
QCBOREncode_AddPositiveBignum(QCBOREncodeContext *pCtx,
                             UsefulBufC          Bytes);

static void
QCBOREncode_AddPositiveBignumToMap(QCBOREncodeContext *pCtx,
                                   const char         *szLabel,
                                   UsefulBufC          Bytes);

static void
QCBOREncode_AddPositiveBignumToMapN(QCBOREncodeContext *pCtx,
                                    int64_t             nLabel,
                                    UsefulBufC          Bytes);


/**
 * @brief Add a negative big number to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the big number to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Bytes            Pointer and length of the big number.
 *
 * Big numbers are integers larger than 64-bits. Their format is
 * described in [RFC 8949] (https://tools.ietf.org/html/rfc8949).
 *
 * It is output as CBOR major type 2, a binary string, with tag
 * @ref CBOR_TAG_NEG_BIGNUM indicating the binary string is a negative
 * big number.
 *
 * Often big numbers are used to represent cryptographic keys,
 * however, COSE which defines representations for keys chose not to
 * use this particular type.
 */
static void
QCBOREncode_AddTNegativeBignum(QCBOREncodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               UsefulBufC          Bytes);

static void
QCBOREncode_AddTNegativeBignumToMapSZ(QCBOREncodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC          Bytes);

static void
QCBOREncode_AddTNegativeBignumToMapN(QCBOREncodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC          Bytes);


static void
QCBOREncode_AddNegativeBignum(QCBOREncodeContext *pCtx,
                              UsefulBufC          Bytes);

static void
QCBOREncode_AddNegativeBignumToMap(QCBOREncodeContext *pCtx,
                                   const char         *szLabel,
                                   UsefulBufC          Bytes);

static void
QCBOREncode_AddNegativeBignumToMapN(QCBOREncodeContext *pCtx,
                                    int64_t             nLabel,
                                    UsefulBufC          Bytes);


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
/**
 * @brief Add a decimal fraction to the encoded output.
 *
 * @param[in] pCtx             Encoding context to add the decimal fraction to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] nMantissa        The mantissa.
 * @param[in] nBase10Exponent  The exponent.
 *
 * The value is nMantissa * 10 ^ nBase10Exponent.
 *
 * A decimal fraction is good for exact representation of some values
 * that can't be represented exactly with standard C (IEEE 754)
 * floating-point numbers.  Much larger and much smaller numbers can
 * also be represented than floating-point because of the larger
 * number of bits in the exponent.
 *
 * The decimal fraction is conveyed as two integers, a mantissa and a
 * base-10 scaling factor.
 *
 * For example, 273.15 is represented by the two integers 27315 and -2.
 *
 * The exponent and mantissa have the range from @c INT64_MIN to
 * @c INT64_MAX for both encoding and decoding (CBOR allows
 * @c -UINT64_MAX to @c UINT64_MAX, but this implementation doesn't
 * support this range to reduce code size and interface complexity a
 * little).
 *
 * CBOR Preferred serialization of the integers is used, thus they
 * will be encoded in the smallest number of bytes possible.
 *
 * See also QCBOREncode_AddDecimalFractionBigNum() for a decimal
 * fraction with arbitrarily large precision and
 * QCBOREncode_AddBigFloat().
 *
 * There is no representation of positive or negative infinity or NaN
 * (Not a Number). Use QCBOREncode_AddDouble() to encode them.
 *
 * See @ref expAndMantissa for decoded representation.
 */
static void
QCBOREncode_AddTDecimalFraction(QCBOREncodeContext *pCtx,
                                uint8_t             uTagRequirement,
                                int64_t             nMantissa,
                                int64_t             nBase10Exponent);

static void
QCBOREncode_AddTDecimalFractionToMapSZ(QCBOREncodeContext *pCtx,
                                       const char         *szLabel,
                                       uint8_t             uTagRequirement,
                                       int64_t             nMantissa,
                                       int64_t             nBase10Exponent);

static void
QCBOREncode_AddTDecimalFractionToMapN(QCBOREncodeContext *pCtx,
                                      int64_t             nLabel,
                                      uint8_t             uTagRequirement,
                                      int64_t             nMantissa,
                                      int64_t             nBase10Exponent);


static void
QCBOREncode_AddDecimalFraction(QCBOREncodeContext *pCtx,
                               int64_t             nMantissa,
                               int64_t             nBase10Exponent);

static void
QCBOREncode_AddDecimalFractionToMap(QCBOREncodeContext *pCtx,
                                    const char         *szLabel,
                                    int64_t             nMantissa,
                                    int64_t             nBase10Exponent);

static void
QCBOREncode_AddDecimalFractionToMapN(QCBOREncodeContext *pCtx,
                                     int64_t             nLabel,
                                     int64_t             nMantissa,
                                     int64_t             nBase10Exponent);


/**
 * @brief Add a decimal fraction with a big number mantissa to the encoded output.
 *
 * @param[in] pCtx             Encoding context to add the decimal fraction to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Mantissa         The mantissa.
 * @param[in] bIsNegative      false if mantissa is positive, true if negative.
 * @param[in] nBase10Exponent  The exponent.
 *
 * This is the same as QCBOREncode_AddDecimalFraction() except the
 * mantissa is a big number (See QCBOREncode_AddPositiveBignum())
 * allowing for arbitrarily large precision.
 *
 * See @ref expAndMantissa for decoded representation.
 */
static void
QCBOREncode_AddTDecimalFractionBigNum(QCBOREncodeContext *pCtx,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC          Mantissa,
                                      bool                bIsNegative,
                                      int64_t             nBase10Exponent);

static void
QCBOREncode_AddTDecimalFractionBigNumToMapSZ(QCBOREncodeContext *pCtx,
                                             const char         *szLabel,
                                             uint8_t             uTagRequirement,
                                             UsefulBufC          Mantissa,
                                             bool                bIsNegative,
                                             int64_t             nBase10Exponent);

static void
QCBOREncode_AddTDecimalFractionBigNumToMapN(QCBOREncodeContext *pCtx,
                                            int64_t             nLabel,
                                            uint8_t             uTagRequirement,
                                            UsefulBufC          Mantissa,
                                            bool                bIsNegative,
                                            int64_t             nBase10Exponent);


static void
QCBOREncode_AddDecimalFractionBigNum(QCBOREncodeContext *pCtx,
                                     UsefulBufC          Mantissa,
                                     bool                bIsNegative,
                                     int64_t             nBase10Exponent);

static void
QCBOREncode_AddDecimalFractionBigNumToMapSZ(QCBOREncodeContext *pCtx,
                                            const char         *szLabel,
                                            UsefulBufC          Mantissa,
                                            bool                bIsNegative,
                                            int64_t             nBase10Exponent);

static void
QCBOREncode_AddDecimalFractionBigNumToMapN(QCBOREncodeContext *pCtx,
                                           int64_t             nLabel,
                                           UsefulBufC          Mantissa,
                                           bool                bIsNegative,
                                           int64_t             nBase10Exponent);

/**
 * @brief Add a big floating-point number to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the bigfloat to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] nMantissa        The mantissa.
 * @param[in] nBase2Exponent   The exponent.
 *
 * The value is nMantissa * 2 ^ nBase2Exponent.
 *
 * "Bigfloats", as CBOR terms them, are similar to IEEE floating-point
 * numbers in having a mantissa and base-2 exponent, but they are not
 * supported by hardware or encoded the same. They explicitly use two
 * CBOR-encoded integers to convey the mantissa and exponent, each of
 * which can be 8, 16, 32 or 64 bits. With both the mantissa and
 * exponent 64 bits they can express more precision and a larger range
 * than an IEEE double floating-point number. See
 * QCBOREncode_AddBigFloatBigNum() for even more precision.
 *
 * For example, 1.5 would be represented by a mantissa of 3 and an
 * exponent of -1.
 *
 * The exponent and mantissa have the range from @c INT64_MIN to
 * @c INT64_MAX for both encoding and decoding (CBOR allows @c
 * -UINT64_MAX to @c UINT64_MAX, but this implementation doesn't
 * support this range to reduce code size and interface complexity a
 * little).
 *
 * CBOR preferred serialization of the integers is used, thus they will
 * be encoded in the smallest number of bytes possible.
 *
 * This can also be used to represent floating-point numbers in
 * environments that don't support IEEE 754.
 *
 * See @ref expAndMantissa for decoded representation.
 */
static void
QCBOREncode_AddTBigFloat(QCBOREncodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         int64_t             nMantissa,
                         int64_t             nBase2Exponent);

static void
QCBOREncode_AddTBigFloatToMapSZ(QCBOREncodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t             nMantissa,
                                int64_t             nBase2Exponent);

static void
QCBOREncode_AddTBigFloatToMapN(QCBOREncodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t             nMantissa,
                               int64_t             nBase2Exponent);


static void
QCBOREncode_AddBigFloat(QCBOREncodeContext *pCtx,
                        int64_t             nMantissa,
                        int64_t             nBase2Exponent);

static void
QCBOREncode_AddBigFloatToMap(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             int64_t             nMantissa,
                             int64_t             nBase2Exponent);

static void
QCBOREncode_AddBigFloatToMapN(QCBOREncodeContext *pCtx,
                              int64_t             nLabel,
                              int64_t             nMantissa,
                              int64_t             nBase2Exponent);

/**
 * @brief Add a big floating-point number with a big number mantissa to
 *        the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the bigfloat to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Mantissa         The mantissa.
 * @param[in] bIsNegative      false if mantissa is positive, true if negative.
 * @param[in] nBase2Exponent   The exponent.
 *
 * This is the same as QCBOREncode_AddBigFloat() except the mantissa
 * is a big number (See QCBOREncode_AddPositiveBignum()) allowing for
 * arbitrary precision.
 *
 * See @ref expAndMantissa for decoded representation.
 */
static void
QCBOREncode_AddTBigFloatBigNum(QCBOREncodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               UsefulBufC          Mantissa,
                               bool                bIsNegative,
                               int64_t             nBase2Exponent);

static void
QCBOREncode_AddTBigFloatBigNumToMapSZ(QCBOREncodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC          Mantissa,
                                      bool                bIsNegative,
                                      int64_t             nBase2Exponent);

static void
QCBOREncode_AddTBigFloatBigNumToMapN(QCBOREncodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC          Mantissa,
                                     bool                bIsNegative,
                                     int64_t             nBase2Exponent);


static void
QCBOREncode_AddBigFloatBigNum(QCBOREncodeContext *pCtx,
                              UsefulBufC          Mantissa,
                              bool                bIsNegative,
                              int64_t             nBase2Exponent);

static void
QCBOREncode_AddBigFloatBigNumToMap(QCBOREncodeContext *pCtx,
                                   const char         *szLabel,
                                   UsefulBufC          Mantissa,
                                   bool                bIsNegative,
                                   int64_t             nBase2Exponent);

static void
QCBOREncode_AddBigFloatBigNumToMapN(QCBOREncodeContext *pCtx,
                                    int64_t             nLabel,
                                    UsefulBufC          Mantissa,
                                    bool                bIsNegative,
                                    int64_t             nBase2Exponent);
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */


/**
 * @brief Add a text URI to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the URI to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] URI              Pointer and length of the URI.
 *
 * The format of URI must be per [RFC 3986]
 * (https://tools.ietf.org/html/rfc3986).
 *
 * It is output as CBOR major type 3, a text string, with tag @ref
 * CBOR_TAG_URI indicating the text string is a URI.
 *
 * A URI in a NULL-terminated string, @c szURI, can be easily added with
 * this code:
 *
 *      QCBOREncode_AddURI(pCtx, UsefulBuf_FromSZ(szURI));
 */
static void
QCBOREncode_AddTURI(QCBOREncodeContext *pCtx,
                    uint8_t             uTagRequirement,
                    UsefulBufC          URI);

static void
QCBOREncode_AddTURIToMapSZ(QCBOREncodeContext *pCtx,
                           const char         *szLabel,
                           uint8_t             uTagRequirement,
                           UsefulBufC          URI);

static void
QCBOREncode_AddTURIToMapN(QCBOREncodeContext *pCtx,
                          int64_t             nLabel,
                          uint8_t             uTagRequirement,
                          UsefulBufC          URI);


static void
QCBOREncode_AddURI(QCBOREncodeContext *pCtx,
                   UsefulBufC          URI);

static void
QCBOREncode_AddURIToMap(QCBOREncodeContext *pCtx,
                        const char         *szLabel,
                        UsefulBufC          URI);

static void
QCBOREncode_AddURIToMapN(QCBOREncodeContext *pCtx,
                         int64_t             nLabel,
                         UsefulBufC          URI);


/**
 * @brief Add Base64-encoded text to encoded output.
 *
 * @param[in] pCtx             The encoding context to add the base-64 text to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] B64Text          Pointer and length of the base-64 encoded text.
 *
 * The text content is Base64 encoded data per [RFC 4648]
 * (https://tools.ietf.org/html/rfc4648).
 *
 * It is output as CBOR major type 3, a text string, with tag @ref
 * CBOR_TAG_B64 indicating the text string is Base64 encoded.
 */
static void
QCBOREncode_AddTB64Text(QCBOREncodeContext *pCtx,
                        uint8_t             uTagRequirement,
                                    UsefulBufC          B64Text);

static void
QCBOREncode_AddTB64TextToMapSZ(QCBOREncodeContext *pCtx,
                               const char         *szLabel,
                               uint8_t             uTagRequirement,
                               UsefulBufC          B64Text);

static void
QCBOREncode_AddTB64TextToMapN(QCBOREncodeContext *pCtx,
                              int64_t nLabel,
                              uint8_t uTagRequirement,
                              UsefulBufC B64Text);


static void
QCBOREncode_AddB64Text(QCBOREncodeContext *pCtx,
                       UsefulBufC          B64Text);

static void
QCBOREncode_AddB64TextToMap(QCBOREncodeContext *pCtx,
                            const char         *szLabel,
                            UsefulBufC          B64Text);

static void
QCBOREncode_AddB64TextToMapN(QCBOREncodeContext *pCtx,
                             int64_t             nLabel,
                             UsefulBufC          B64Text);



/**
 * @brief Add base64url encoded data to encoded output.
 *
 * @param[in] pCtx             The encoding context to add the base64url to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] B64Text          Pointer and length of the base64url encoded text.
 *
 * The text content is base64URL encoded text as per [RFC 4648]
 * (https://tools.ietf.org/html/rfc4648).
 *
 * It is output as CBOR major type 3, a text string, with tag
 * @ref CBOR_TAG_B64URL indicating the text string is a Base64url
 * encoded.
 */
static void
QCBOREncode_AddTB64URLText(QCBOREncodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBufC          B64Text);

static void
QCBOREncode_AddTB64URLTextToMapSZ(QCBOREncodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC          B64Text);

static void
QCBOREncode_AddTB64URLTextToMapN(QCBOREncodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC          B64Text);


static void
QCBOREncode_AddB64URLText(QCBOREncodeContext *pCtx,
                          UsefulBufC          B64Text);

static void
QCBOREncode_AddB64URLTextToMap(QCBOREncodeContext *pCtx,
                               const char         *szLabel,
                               UsefulBufC          B64Text);

static void
QCBOREncode_AddB64URLTextToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                UsefulBufC          B64Text);


/**
 * @brief Add Perl Compatible Regular Expression.
 *
 * @param[in] pCtx             Encoding context to add the regular expression to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Regex            Pointer and length of the regular expression.
 *
 * The text content is Perl Compatible Regular
 * Expressions (PCRE) / JavaScript syntax [ECMA262].
 *
 * It is output as CBOR major type 3, a text string, with tag @ref
 * CBOR_TAG_REGEX indicating the text string is a regular expression.
 */
static void
QCBOREncode_AddTRegex(QCBOREncodeContext *pCtx,
                      uint8_t            uTagRequirement,
                      UsefulBufC         Regex);

static void
QCBOREncode_AddTRegexToMapSZ(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             uint8_t             uTagRequirement,
                             UsefulBufC          Regex);

static void
QCBOREncode_AddTRegexToMapN(QCBOREncodeContext *pCtx,
                            int64_t             nLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC          Regex);


static void
QCBOREncode_AddRegex(QCBOREncodeContext *pCtx,
                     UsefulBufC          Regex);

static void
QCBOREncode_AddRegexToMap(QCBOREncodeContext *pCtx,
                          const char         *szLabel,
                          UsefulBufC          Regex);

static void
QCBOREncode_AddRegexToMapN(QCBOREncodeContext *pCtx,
                           int64_t             nLabel,
                           UsefulBufC          Regex);


/**
 * @brief MIME encoded data to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the MIME data to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] MIMEData         Pointer and length of the MIME data.
 *
 * The text content is in MIME format per [RFC 2045]
 * (https://tools.ietf.org/html/rfc2045) including the headers.
 *
 * It is output as CBOR major type 2, a binary string, with tag
 * @ref CBOR_TAG_BINARY_MIME indicating the string is MIME data.  This
 * outputs tag 257, not tag 36, as it can carry any type of MIME
 * binary, 7-bit, 8-bit, quoted-printable and base64 where tag 36
 * cannot.
 *
 * Previous versions of QCBOR, those before spiffy decode, output tag
 * 36. Decoding supports both tag 36 and 257.  (if the old behavior
 * with tag 36 is needed, copy the inline functions below and change
 * the tag number).
 *
 * See also QCBORDecode_GetMIMEMessage() and
 * @ref QCBOR_TYPE_BINARY_MIME.
 *
 * This does no translation of line endings. See QCBOREncode_AddText()
 * for a discussion of line endings in CBOR.
 */
static void
QCBOREncode_AddTMIMEData(QCBOREncodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         UsefulBufC          MIMEData);

static void
QCBOREncode_AddTMIMEDataToMapSZ(QCBOREncodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC          MIMEData);

static void
QCBOREncode_AddTMIMEDataToMapN(QCBOREncodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               UsefulBufC          MIMEData);


static void
QCBOREncode_AddMIMEData(QCBOREncodeContext *pCtx,
                        UsefulBufC          MIMEData);

static void
QCBOREncode_AddMIMEDataToMap(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             UsefulBufC          MIMEData);

static void
QCBOREncode_AddMIMEDataToMapN(QCBOREncodeContext *pCtx,
                              int64_t             nLabel,
                              UsefulBufC          MIMEData);


/**
 * @brief  Add an RFC 3339 date string
 *
 * @param[in] pCtx             The encoding context to add the date to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] szDate           Null-terminated string with date to add.
 *
 * The string szDate should be in the form of [RFC 3339]
 * (https://tools.ietf.org/html/rfc3339) as defined by section 3.3 in
 * [RFC 4287] (https://tools.ietf.org/html/rfc4287). This is as
 * described in section 3.4.1 in [RFC 8949]
 * (https://tools.ietf.org/html/rfc8949).
 *
 * Note that this function doesn't validate the format of the date
 * string at all. If you add an incorrect format date string, the
 * generated CBOR will be incorrect and the receiver may not be able
 * to handle it.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddTDayString().
 */
static void
QCBOREncode_AddTDateString(QCBOREncodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           const char         *szDate);

static void
QCBOREncode_AddTDateStringToMapSZ(QCBOREncodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  const char         *szDate);

static void
QCBOREncode_AddTDateStringToMapN(QCBOREncodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 const char         *szDate);


static void
QCBOREncode_AddDateString(QCBOREncodeContext *pCtx,
                          const char         *szDate);

static void
QCBOREncode_AddDateStringToMap(QCBOREncodeContext *pCtx,
                               const char         *szLabel,
                               const char         *szDate);

static void
QCBOREncode_AddDateStringToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                const char         *szDate);


/**
 * @brief  Add a date-only string.
 *
 * @param[in] pCtx             The encoding context to add the date to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] szDate           Null-terminated string with date to add.
 *
 * This date format is described in
 * [RFC 8943] (https://tools.ietf.org/html/rfc8943), but that mainly
 * references RFC 3339.  The string szDate must be in the forrm
 * specified the ABNF for a full-date in
 * [RFC 3339] (https://tools.ietf.org/html/rfc3339). Examples of this
 * are "1985-04-12" and "1937-01-01".  The time and the time zone are
 * never included.
 *
 * Note that this function doesn't validate the format of the date
 * string at all. If you add an incorrect format date string, the
 * generated CBOR will be incorrect and the receiver may not be able
 * to handle it.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddTDateString().
 */
static void
QCBOREncode_AddTDaysString(QCBOREncodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           const char         *szDate);

static void
QCBOREncode_AddTDaysStringToMapSZ(QCBOREncodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  const char         *szDate);

static void
QCBOREncode_AddTDaysStringToMapN(QCBOREncodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 const char         *szDate);


/**
 * @brief  Add a standard Boolean.
 *
 * @param[in] pCtx  The encoding context to add the Boolean to.
 * @param[in] b     true or false from @c <stdbool.h>.
 *
 * Adds a Boolean value as CBOR major type 7.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddBool(QCBOREncodeContext *pCtx, bool b);

static void
QCBOREncode_AddBoolToMap(QCBOREncodeContext *pCtx, const char *szLabel, bool b);

static void
QCBOREncode_AddBoolToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, bool b);


/**
 * @brief  Add a NULL to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the NULL to.
 *
 * Adds the NULL value as CBOR major type 7.
 *
 * This NULL doesn't have any special meaning in CBOR such as a
 * terminating value for a string or an empty value.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddNULL(QCBOREncodeContext *pCtx);

static void
QCBOREncode_AddNULLToMap(QCBOREncodeContext *pCtx, const char *szLabel);

static void
QCBOREncode_AddNULLToMapN(QCBOREncodeContext *pCtx, int64_t nLabel);


/**
 * @brief  Add an "undef" to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the "undef" to.
 *
 * Adds the undef value as CBOR major type 7.
 *
 * Note that this value will not translate to JSON.
 *
 * This Undef doesn't have any special meaning in CBOR such as a
 * terminating value for a string or an empty value.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddUndef(QCBOREncodeContext *pCtx);

static void
QCBOREncode_AddUndefToMap(QCBOREncodeContext *pCtx, const char *szLabel);

static void
QCBOREncode_AddUndefToMapN(QCBOREncodeContext *pCtx, int64_t nLabel);


/**
 * @brief Add a simple value.
 *
 * @param[in] pMe    The encode context.
 * @param[in] uNum   The simple value.
 *
 * QCBOREncode_AddBool(), QCBOREncode_AddUndef() and
 * QCBOREncode_AddNull() are preferred to this for the simple values
 * defined in RFC 8949, but this can be used for them too.
 *
 * The main purpose of this is to add simple values beyond those in
 * defined RFC 8949. Note that simple values must be registered with
 * IANA. Those in the range of 0 to 19 must be standardized.  Those in
 * the range of 32 to 255 do not require a standard, but must be
 * publically specified. There is no range of values for proprietary
 * use. See
 * https://www.iana.org/assignments/cbor-simple-values/cbor-simple-values.xhtml
 */
static void
QCBOREncode_AddSimple(QCBOREncodeContext *pMe, const uint8_t uNum);

static void
QCBOREncode_AddSimpleToMap(QCBOREncodeContext *pMe,
                           const char         *szLabel,
                           const uint8_t       uSimple);

static void
QCBOREncode_AddSimpleToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const uint8_t       uSimple);


/**
 * @brief  Indicates that the next items added are in an array.
 *
 * @param[in] pCtx The encoding context to open the array in.
 *
 * Arrays are the basic CBOR aggregate or structure type. Call this
 * function to start or open an array. Then call the various
 * @c QCBOREncode_AddXxx() functions to add the items that go into the
 * array. Then call QCBOREncode_CloseArray() when all items have been
 * added. The data items in the array can be of any type and can be of
 * mixed types.
 *
 * Nesting of arrays and maps is allowed and supported just by calling
 * QCBOREncode_OpenArray() again before calling
 * QCBOREncode_CloseArray().  While CBOR has no limit on nesting, this
 * implementation does in order to keep it smaller and simpler.  The
 * limit is @ref QCBOR_MAX_ARRAY_NESTING. This is the max number of
 * times this can be called without calling
 * QCBOREncode_CloseArray(). QCBOREncode_Finish() will return
 * @ref QCBOR_ERR_ARRAY_NESTING_TOO_DEEP when it is called as this
 * function just sets an error state and returns no value when this
 * occurs.
 *
 * If you try to add more than @ref QCBOR_MAX_ITEMS_IN_ARRAY items to
 * a single array or map, @ref QCBOR_ERR_ARRAY_TOO_LONG will be
 * returned when QCBOREncode_Finish() is called.
 *
 * An array itself must have a label if it is being added to a map.
 * Note that array elements do not have labels (but map elements do).
 *
 * An array itself may be tagged by calling QCBOREncode_AddTag()
 * before this call.
 */
static void
QCBOREncode_OpenArray(QCBOREncodeContext *pCtx);

static void
QCBOREncode_OpenArrayInMap(QCBOREncodeContext *pCtx, const char *szLabel);

static void
QCBOREncode_OpenArrayInMapN(QCBOREncodeContext *pCtx,  int64_t nLabel);


/**
 * @brief Close an open array.
 *
 * @param[in] pCtx The encoding context to close the array in.
 *
 * The closes an array opened by QCBOREncode_OpenArray(). It reduces
 * nesting level by one. All arrays (and maps) must be closed before
 * calling QCBOREncode_Finish().
 *
 * When an error occurs as a result of this call, the encoder records
 * the error and enters the error state. The error will be returned
 * when QCBOREncode_Finish() is called.
 *
 * If this has been called more times than QCBOREncode_OpenArray(), then
 * @ref QCBOR_ERR_TOO_MANY_CLOSES will be returned when QCBOREncode_Finish()
 * is called.
 *
 * If this is called and it is not an array that is currently open,
 * @ref QCBOR_ERR_CLOSE_MISMATCH will be returned when
 * QCBOREncode_Finish() is called.
 */
static void
QCBOREncode_CloseArray(QCBOREncodeContext *pCtx);




/**
 * @brief  Indicates that the next items added are in a map.
 *
 * @param[in] pCtx The encoding context to open the map in.
 *
 * See QCBOREncode_OpenArray() for more information, particularly
 * error handling.
 *
 * CBOR maps are an aggregate type where each item in the map consists
 * of a label and a value. They are similar to JSON objects.
 *
 * The value can be any CBOR type including another map.
 *
 * The label can also be any CBOR type, but in practice they are
 * typically, integers as this gives the most compact output. They
 * might also be text strings which gives readability and translation
 * to JSON.
 *
 * Every @c QCBOREncode_AddXxx() call has one version that ends with
 * @c InMap for adding items to maps with string labels and one that
 * ends with @c InMapN that is for adding with integer labels.
 *
 * RFC 8949 uses the term "key" instead of "label".
 *
 * If you wish to use map labels that are neither integer labels nor
 * text strings, then just call the QCBOREncode_AddXxx() function
 * explicitly to add the label. Then call it again to add the value.
 *
 * See the [RFC 8949] (https://tools.ietf.org/html/rfc8949) for a lot
 * more information on creating maps.
 */
static void
QCBOREncode_OpenMap(QCBOREncodeContext *pCtx);

static void
QCBOREncode_OpenMapInMap(QCBOREncodeContext *pCtx, const char *szLabel);

static void
QCBOREncode_OpenMapInMapN(QCBOREncodeContext *pCtx, int64_t nLabel);


/**
 * @brief Close an open map.
 *
 * @param[in] pCtx The encoding context to close the map in.
 *
 * This closes a map opened by QCBOREncode_OpenMap(). It reduces
 * nesting level by one.
 *
 * When an error occurs as a result of this call, the encoder records
 * the error and enters the error state. The error will be returned
 * when QCBOREncode_Finish() is called.
 *
 * If this has been called more times than QCBOREncode_OpenMap(), then
 * @ref QCBOR_ERR_TOO_MANY_CLOSES will be returned when
 * QCBOREncode_Finish() is called.
 *
 * If this is called and it is not a map that is currently open,
 * @ref QCBOR_ERR_CLOSE_MISMATCH will be returned when
 * QCBOREncode_Finish() is called.
 */
static void
QCBOREncode_CloseMap(QCBOREncodeContext *pCtx);


/**
 * @brief Indicates that the next items added are in an indefinite length array.
 *
 * @param[in] pCtx The encoding context to open the array in.
 *
 * This is the same as QCBOREncode_OpenArray() except the array is
 * indefinite length.
 *
 * This must be closed with QCBOREncode_CloseArrayIndefiniteLength().
 */
static void
QCBOREncode_OpenArrayIndefiniteLength(QCBOREncodeContext *pCtx);

static void
QCBOREncode_OpenArrayIndefiniteLengthInMap(QCBOREncodeContext *pCtx,
                                           const char         *szLabel);

static void
QCBOREncode_OpenArrayIndefiniteLengthInMapN(QCBOREncodeContext *pCtx,
                                            int64_t            nLabel);


/**
 * @brief Close an open indefinite length array.
 *
 * @param[in] pCtx The encoding context to close the array in.
 *
 * This is the same as QCBOREncode_CloseArray(), but the open array
 * that is being close must be of indefinite length.
 */
static void
QCBOREncode_CloseArrayIndefiniteLength(QCBOREncodeContext *pCtx);


/**
 * @brief Indicates that the next items added are in an indefinite length map.
 *
 * @param[in] pCtx The encoding context to open the map in.
 *
 * This is the same as QCBOREncode_OpenMap() except the array is
 * indefinite length.
 *
 * This must be closed with QCBOREncode_CloseMapIndefiniteLength().
 */
static void
QCBOREncode_OpenMapIndefiniteLength(QCBOREncodeContext *pCtx);

static void
QCBOREncode_OpenMapIndefiniteLengthInMap(QCBOREncodeContext *pCtx,
                                         const char         *szLabel);

static void
QCBOREncode_OpenMapIndefiniteLengthInMapN(QCBOREncodeContext *pCtx,
                                          int64_t            nLabel);


/**
 * @brief Close an open indefinite length map.
 *
 * @param[in] pCtx The encoding context to close the map in.
 *
 * This is the same as QCBOREncode_CloseMap(), but the open map that
 * is being close must be of indefinite length.
 */
static  void
QCBOREncode_CloseMapIndefiniteLength(QCBOREncodeContext *pCtx);




/**
 * @brief Indicate start of encoded CBOR to be wrapped in a bstr.
 *
 * @param[in] pCtx The encoding context to open the bstr-wrapped CBOR in.
 *
 * All added encoded items between this call and a call to
 * QCBOREncode_CloseBstrWrap2() will be wrapped in a bstr. They will
 * appear in the final output as a byte string.  That byte string will
 * contain encoded CBOR. This increases nesting level by one.
 *
 * The typical use case is for encoded CBOR that is to be
 * cryptographically hashed, as part of a [RFC 8152, COSE]
 * (https://tools.ietf.org/html/rfc8152) implementation. The wrapping
 * byte string is taken as input by the hash function (which is why it
 * is returned by QCBOREncode_CloseBstrWrap2()).  It is also easy to
 * recover on decoding with standard CBOR decoders.
 *
 * Using QCBOREncode_BstrWrap() and QCBOREncode_CloseBstrWrap2()
 * avoids having to encode the items first in one buffer (e.g., the
 * COSE payload) and then add that buffer as a bstr to another
 * encoding (e.g. the COSE to-be-signed bytes, the @c Sig_structure)
 * potentially halving the memory needed.
 *
 * CBOR by nature must be decoded item by item in order from the
 * start.  By wrapping some CBOR in a byte string, the decoding of
 * that wrapped CBOR can be skipped. This is another use of wrapping,
 * perhaps because the CBOR is large and deeply nested. Perhaps APIs
 * for handling one defined CBOR message that is being embedded in
 * another only take input as a byte string. Perhaps the desire is to
 * be able to decode the out layer even in the wrapped has errors.
 */
static void
QCBOREncode_BstrWrap(QCBOREncodeContext *pCtx);

static void
QCBOREncode_BstrWrapInMap(QCBOREncodeContext *pCtx, const char *szLabel);

static void
QCBOREncode_BstrWrapInMapN(QCBOREncodeContext *pCtx, int64_t nLabel);


/**
 * @brief Close a wrapping bstr.
 *
 * @param[in] pCtx              The encoding context to close of bstr wrapping in.
 * @param[in] bIncludeCBORHead  Include the encoded CBOR head of the bstr
 *                              as well as the bytes in @c pWrappedCBOR.
 * @param[out] pWrappedCBOR     A @ref UsefulBufC containing wrapped bytes.
 *
 * The closes a wrapping bstr opened by QCBOREncode_BstrWrap(). It reduces
 * nesting level by one.
 *
 * A pointer and length of the enclosed encoded CBOR is returned in @c
 * *pWrappedCBOR if it is not @c NULL. The main purpose of this is so
 * this data can be hashed (e.g., with SHA-256) as part of a [RFC
 * 8152, COSE] (https://tools.ietf.org/html/rfc8152)
 * implementation. **WARNING**, this pointer and length should be used
 * right away before any other calls to @c QCBOREncode_CloseXxx() as
 * they will move data around and the pointer and length will no
 * longer be to the correct encoded CBOR.
 *
 * When an error occurs as a result of this call, the encoder records
 * the error and enters the error state. The error will be returned
 * when QCBOREncode_Finish() is called.
 *
 * If this has been called more times than QCBOREncode_BstrWrap(),
 * then @ref QCBOR_ERR_TOO_MANY_CLOSES will be returned when
 * QCBOREncode_Finish() is called.
 *
 * If this is called and it is not a wrapping bstr that is currently
 * open, @ref QCBOR_ERR_CLOSE_MISMATCH will be returned when
 * QCBOREncode_Finish() is called.
 *
 * QCBOREncode_CloseBstrWrap() is a deprecated version of this function
 * that is equivalent to the call with @c bIncludeCBORHead @c true.
 */
void
QCBOREncode_CloseBstrWrap2(QCBOREncodeContext *pCtx, bool bIncludeCBORHead, UsefulBufC *pWrappedCBOR);

static void
QCBOREncode_CloseBstrWrap(QCBOREncodeContext *pCtx, UsefulBufC *pWrappedCBOR);


/**
 * @brief Cancel byte string wrapping.
 *
 * @param[in] pCtx       The encoding context.
 *
 * This cancels QCBOREncode_BstrWrap() making tghe encoding as if it
 * were never called.
 *
 * WARNING: This does not work on QCBOREncode_BstrWrapInMap()
 * or QCBOREncode_BstrWrapInMapN() and there is no error detection
 * of an attempt at their use.
 *
 * This only works if nothing has been added into the wrapped byte
 * string.  If something has been added, this sets the error
 * @ref QCBOR_ERR_CANNOT_CANCEL.
 */
void
QCBOREncode_CancelBstrWrap(QCBOREncodeContext *pCtx);


/**
 * @brief Add some already-encoded CBOR bytes.
 *
 * @param[in] pCtx     The encoding context to add the already-encode CBOR to.
 * @param[in] Encoded  The already-encoded CBOR to add to the context.
 *
 * The encoded CBOR being added must be fully conforming CBOR. It must
 * be complete with no arrays or maps that are incomplete. While this
 * encoder doesn't ever produce indefinite lengths, it is OK for the
 * raw CBOR added here to have indefinite lengths.
 *
 * The raw CBOR added here is not checked in anyway. If it is not
 * conforming or has open arrays or such, the final encoded CBOR
 * will probably be wrong or not what was intended.
 *
 * If the encoded CBOR being added here contains multiple items, they
 * must be enclosed in a map or array. At the top level the raw
 * CBOR must be a single data item.
 */
void
QCBOREncode_AddEncoded(QCBOREncodeContext *pCtx, UsefulBufC Encoded);

static void
QCBOREncode_AddEncodedToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Encoded);

static void
QCBOREncode_AddEncodedToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC Encoded);


/**
 * @brief Get the encoded result.
 *
 * @param[in] pCtx           The context to finish encoding with.
 * @param[out] pEncodedCBOR  Structure in which the pointer and length of
 *                           the encoded CBOR is returned.
 *
 * @retval QCBOR_SUCCESS                     Encoded CBOR is returned.
 *
 * @retval QCBOR_ERR_TOO_MANY_CLOSES         Nesting error
 *
 * @retval QCBOR_ERR_CLOSE_MISMATCH          Nesting error
 *
 * @retval QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN Nesting error
 *
 * @retval QCBOR_ERR_BUFFER_TOO_LARGE        Encoded output buffer size
 *
 * @retval QCBOR_ERR_BUFFER_TOO_SMALL        Encoded output buffer size
 *
 * @retval QCBOR_ERR_ARRAY_NESTING_TOO_DEEP  Implementation limit
 *
 * @retval QCBOR_ERR_ARRAY_TOO_LONG          Implementation limit
 *
 * On success, the pointer and length of the encoded CBOR are returned
 * in @c *pEncodedCBOR. The pointer is the same pointer that was passed
 * in to QCBOREncode_Init(). Note that it is not const when passed to
 * QCBOREncode_Init(), but it is const when returned here.  The length
 * will be smaller than or equal to the length passed in when
 * QCBOREncode_Init() as this is the length of the actual result, not
 * the size of the buffer it was written to.
 *
 * If a @c NULL was passed for @c Storage.ptr when QCBOREncode_Init()
 * was called, @c NULL will be returned here, but the length will be
 * that of the CBOR that would have been encoded.
 *
 * Encoding errors primarily manifest here as most other encoding function
 * do no return an error. They just set the error state in the encode
 * context after which no encoding function does anything.
 *
 * Three types of errors manifest here. The first type are nesting
 * errors where the number of @c QCBOREncode_OpenXxx() calls do not
 * match the number @c QCBOREncode_CloseXxx() calls. The solution is to
 * fix the calling code.
 *
 * The second type of error is because the buffer given is either too
 * small or too large. The remedy is to give a correctly sized buffer.
 *
 * The third type are due to limits in this implementation.
 * @ref QCBOR_ERR_ARRAY_NESTING_TOO_DEEP can be worked around by
 * encoding the CBOR in two (or more) phases and adding the CBOR from
 * the first phase to the second with @c QCBOREncode_AddEncoded().
 *
 * If an error is returned, the buffer may have partially encoded
 * incorrect CBOR in it and it should not be used. Likewise, the length
 * may be incorrect and should not be used.
 *
 * Note that the error could have occurred in one of the many
 * @c QCBOREncode_AddXxx() calls long before QCBOREncode_Finish() was
 * called. This error handling reduces the CBOR implementation size
 * but makes debugging harder.
 *
 * This may be called multiple times. It will always return the
 * same. It can also be interleaved with calls to
 * QCBOREncode_FinishGetSize().
 *
 * QCBOREncode_GetErrorState() can be called to get the current
 * error state in order to abort encoding early as an optimization, but
 * calling it is is never required.
 */
QCBORError
QCBOREncode_Finish(QCBOREncodeContext *pCtx, UsefulBufC *pEncodedCBOR);


/**
 * @brief Get the encoded CBOR and error status.
 *
 * @param[in] pCtx          The context to finish encoding with.
 * @param[out] uEncodedLen  The length of the encoded or potentially
 *                          encoded CBOR in bytes.
 *
 * @return The same errors as QCBOREncode_Finish().
 *
 * This functions the same as QCBOREncode_Finish(), but only returns the
 * size of the encoded output.
 */
QCBORError
QCBOREncode_FinishGetSize(QCBOREncodeContext *pCtx, size_t *uEncodedLen);


/**
 * @brief Indicate whether output buffer is NULL or not.
 *
 * @param[in] pCtx  The encoding context.
 *
 * @return 1 if the output buffer is @c NULL.
 *
 * Sometimes a @c NULL input buffer is given to QCBOREncode_Init() so
 * that the size of the generated CBOR can be calculated without
 * allocating a buffer for it. This returns 1 when the output buffer
 * is @c NULL and 0 when it is not.
 */
static int
QCBOREncode_IsBufferNULL(QCBOREncodeContext *pCtx);


/**
 * @brief Get the encoding error state.
 *
 * @param[in] pCtx  The encoding context.
 *
 * @return One of @ref QCBORError. See return values from
 *         QCBOREncode_Finish()
 *
 * Normally encoding errors need only be handled at the end of
 * encoding when QCBOREncode_Finish() is called. This can be called to
 * get the error result before finish should there be a need to halt
 * encoding before QCBOREncode_Finish() is called.
 */
static QCBORError
QCBOREncode_GetErrorState(QCBOREncodeContext *pCtx);


/**
 * Encode the "head" of a CBOR data item.
 *
 * @param Buffer       Buffer to output the encoded head to; must be
 *                     @ref QCBOR_HEAD_BUFFER_SIZE bytes in size.
 * @param uMajorType   One of CBOR_MAJOR_TYPE_XX.
 * @param uMinLen      The minimum number of bytes to encode uNumber. Almost
 *                     always this is 0 to use preferred
 *                     serialization. If this is 4, then even the
 *                     values 0xffff and smaller will be encoded in 4
 *                     bytes. This is used primarily when encoding a
 *                     float or double put into uNumber as the leading
 *                     zero bytes for them must be encoded.
 * @param uNumber      The numeric argument part of the CBOR head.
 * @return             Pointer and length of the encoded head or
 *                     @ref NULLUsefulBufC if the output buffer is too small.
 *
 * Callers do not to need to call this for normal CBOR encoding. Note
 * that it doesn't even take a @ref QCBOREncodeContext argument.
 *
 * This encodes the major type and argument part of a data item. The
 * argument is an integer that is usually either the value or the length
 * of the data item.
 *
 * This is exposed in the public interface to allow hashing of some CBOR
 * data types, bstr in particular, a chunk at a time so the full CBOR
 * doesn't have to be encoded in a contiguous buffer.
 *
 * For example, if you have a 100,000 byte binary blob in a buffer that
 * needs to be a bstr encoded and then hashed. You could allocate a
 * 100,010 byte buffer and encode it normally. Alternatively, you can
 * encode the head in a 10 byte buffer with this function, hash that and
 * then hash the 100,000 bytes using the same hash context.
 */
UsefulBufC
QCBOREncode_EncodeHead(UsefulBuf Buffer,
                       uint8_t   uMajorType,
                       uint8_t   uMinLen,
                       uint64_t  uNumber);




/* =========================================================================
     BEGINNING OF PRIVATE IMPLEMENTATION
   ========================================================================= */

/* Semi-private funcion used by public inline functions. See qcbor_encode.c */
void QCBOREncode_Private_AppendCBORHead(QCBOREncodeContext *pMe,
                                        const uint8_t       uMajorType,
                                        const uint64_t      uArgument,
                                        const uint8_t       uMinLen);


/* Semi-private funcion used by public inline functions. See qcbor_encode.c */
void
QCBOREncode_Private_AddBuffer(QCBOREncodeContext *pCtx,
                              uint8_t             uMajorType,
                              UsefulBufC          Bytes);


/* Semi-private function for adding a double with preferred encoding. See qcbor_encode.c */
void
QCBOREncode_Private_AddPreferredDouble(QCBOREncodeContext *pMe, const double dNum);


/* Semi-private function for adding a float with preferred encoding. See qcbor_encode.c */
void
QCBOREncode_Private_AddPreferredFloat(QCBOREncodeContext *pMe, const float fNum);


/* Semi-private funcion used by public inline functions. See qcbor_encode.c */
void
QCBOREncode_Private_OpenMapOrArray(QCBOREncodeContext *pCtx,
                                   uint8_t             uMajorType);


/* Semi-private funcion used by public inline functions. See qcbor_encode.c */
void
QCBOREncode_Private_OpenMapOrArrayIndefiniteLength(QCBOREncodeContext *pCtx,
                                                   uint8_t             uMajorType);


/* Semi-private funcion used by public inline functions. See qcbor_encode.c */
void
QCBOREncode_Private_CloseMapOrArray(QCBOREncodeContext *pCtx,
                                    uint8_t             uMajorType);


/* Semi-private funcion used by public inline functions. See qcbor_encode.c */
void
QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(QCBOREncodeContext *pCtx,
                                                    uint8_t             uMajorType);


/* Semi-private funcion used by public inline functions. See qcbor_encode.c */
void
QCBOREncode_Private_AddExpMantissa(QCBOREncodeContext *pCtx,
                                   uint64_t            uTag,
                                   UsefulBufC          BigNumMantissa,
                                   bool                bBigNumIsNegative,
                                   int64_t             nMantissa,
                                   int64_t             nExponent);


/**
 * @brief  Semi-private method to add simple items and floating-point.
 *
 * @param[in] pMe        The encoding context.
 * @param[in] uMinLen    Minimum encoding size for uNum. Usually 0.
 * @param[in] uArgument  The value to add.
 *
 * This is used to add simple types like true and false and float-point
 * values, both of which are type 7.
 *
 * Call QCBOREncode_AddBool(), QCBOREncode_AddNULL(),
 * QCBOREncode_AddUndef() QCBOREncode_AddDouble() instead of this.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static inline void
QCBOREncode_Private_AddType7(QCBOREncodeContext *pMe,
                             const uint8_t       uMinLen,
                             const uint64_t      uArgument)
{
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_SIMPLE, uArgument, uMinLen);
}


/**
 * @brief Semi-private method to add only the type and length of a byte string.
 *
 * @param[in] pCtx    The context to initialize.
 * @param[in] Bytes   Pointer and length of the input data.
 *
 * This will be removed in QCBOR 2.0. It was never a public function.
 *
 * This is the same as QCBOREncode_AddBytes() except it only adds the
 * CBOR encoding for the type and the length. It doesn't actually add
 * the bytes. You can't actually produce correct CBOR with this and
 * the rest of this API. It is only used for a special case where the
 * valid CBOR is created manually by putting this type and length in
 * and then adding the actual bytes. In particular, when only a hash
 * of the encoded CBOR is needed, where the type and header are hashed
 * separately and then the bytes is hashed. This makes it possible to
 * implement COSE Sign1 with only one copy of the payload in the
 * output buffer, rather than two, roughly cutting memory use in half.
 *
 * This is only used for this odd case, but this is a supported
 * tested function for QCBOR 1.0.
 *
 * See also QCBOREncode_EncodeHead().
 */
static void
QCBOREncode_AddBytesLenOnly(QCBOREncodeContext *pCtx,
                            UsefulBufC          Bytes);

static void
QCBOREncode_AddBytesLenOnlyToMap(QCBOREncodeContext *pCtx,
                                 const char         *szLabel,
                                 UsefulBufC          Bytes);

static void
QCBOREncode_AddBytesLenOnlyToMapN(QCBOREncodeContext *pCtx,
                                 int64_t              nLabel,
                                 UsefulBufC           Bytes);


/* Forward declaration */
static void
QCBOREncode_AddSZString(QCBOREncodeContext *pMe, const char *szString);




static inline void
QCBOREncode_AddInt64ToMap(QCBOREncodeContext *pMe,
                          const char        *szLabel,
                          const int64_t      uNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddInt64(pMe, uNum);
}

static inline void
QCBOREncode_AddInt64ToMapN(QCBOREncodeContext *pMe,
                           const int64_t       nLabel,
                           const int64_t       uNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddInt64(pMe, uNum);
}


static inline void
QCBOREncode_AddUInt64(QCBOREncodeContext *pMe, const uint64_t uValue)
{
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_POSITIVE_INT, uValue, 0);
}


static inline void
QCBOREncode_AddUInt64ToMap(QCBOREncodeContext *pMe,
                           const char         *szLabel,
                           const uint64_t      uNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddUInt64(pMe, uNum);
}

static inline void
QCBOREncode_AddUInt64ToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const uint64_t      uNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddUInt64(pMe, uNum);
}


static inline void
QCBOREncode_AddText(QCBOREncodeContext *pMe, const UsefulBufC Text)
{
   QCBOREncode_Private_AddBuffer(pMe, CBOR_MAJOR_TYPE_TEXT_STRING, Text);
}

static inline void
QCBOREncode_AddTextToMap(QCBOREncodeContext *pMe,
                         const char         *szLabel,
                         const UsefulBufC    Text)
{
   QCBOREncode_AddText(pMe, UsefulBuf_FromSZ(szLabel));
   QCBOREncode_AddText(pMe, Text);
}

static inline void
QCBOREncode_AddTextToMapN(QCBOREncodeContext *pMe,
                          const int64_t       nLabel,
                          const UsefulBufC    Text)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddText(pMe, Text);
}


inline static void
QCBOREncode_AddSZString(QCBOREncodeContext *pMe, const char *szString)
{
   QCBOREncode_AddText(pMe, UsefulBuf_FromSZ(szString));
}

static inline void
QCBOREncode_AddSZStringToMap(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const char         *szString)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddSZString(pMe, szString);
}

static inline void
QCBOREncode_AddSZStringToMapN(QCBOREncodeContext *pMe,
                              const int64_t       nLabel,
                              const char         *szString)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddSZString(pMe, szString);
}



/*
 * Public functions for adding a tag. See qcbor/qcbor_encode.h
 */
static inline void
QCBOREncode_AddTag(QCBOREncodeContext *pMe, const uint64_t uTag)
{
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_TAG, uTag, 0);
}



#ifndef USEFULBUF_DISABLE_ALL_FLOAT

static inline void
QCBOREncode_AddDoubleNoPreferred(QCBOREncodeContext *pMe, const double dNum)
{
   QCBOREncode_Private_AddType7(pMe,
                                sizeof(uint64_t),
                                UsefulBufUtil_CopyDoubleToUint64(dNum));
}

static inline void
QCBOREncode_AddFloatNoPreferred(QCBOREncodeContext *pMe, const float fNum)
{
   QCBOREncode_Private_AddType7(pMe,
                                sizeof(uint32_t),
                                UsefulBufUtil_CopyFloatToUint32(fNum));
}


static inline void
QCBOREncode_AddDouble(QCBOREncodeContext *pMe, const double dNum)
{
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   QCBOREncode_Private_AddPreferredDouble(pMe, dNum);
#else /* QCBOR_DISABLE_PREFERRED_FLOAT */
   QCBOREncode_AddDoubleNoPreferred(pMe, dNum);
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
}

static inline void
QCBOREncode_AddDoubleToMap(QCBOREncodeContext *pMe,
                           const char         *szLabel,
                           const double        dNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddDouble(pMe, dNum);
}

static inline void
QCBOREncode_AddDoubleToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const double        dNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddDouble(pMe, dNum);
}


static inline void
QCBOREncode_AddFloat(QCBOREncodeContext *pMe, const float fNum)
{
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   QCBOREncode_Private_AddPreferredFloat(pMe, fNum);
#else /* QCBOR_DISABLE_PREFERRED_FLOAT */
   QCBOREncode_AddFloatNoPreferred(pMe, fNum);
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
}

static inline void
QCBOREncode_AddFloatToMap(QCBOREncodeContext *pMe,
                          const char         *szLabel,
                          const float         dNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddFloat(pMe, dNum);
}

static inline void
QCBOREncode_AddFloatToMapN(QCBOREncodeContext *pMe,
                           const int64_t       nLabel,
                           const float         fNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddFloat(pMe, fNum);
}

static inline void
QCBOREncode_AddDoubleNoPreferredToMap(QCBOREncodeContext *pMe,
                                      const char         *szLabel,
                                      const double        dNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddDoubleNoPreferred(pMe, dNum);
}

static inline void
QCBOREncode_AddDoubleNoPreferredToMapN(QCBOREncodeContext *pMe,
                                       const int64_t       nLabel,
                                       const double        dNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddDoubleNoPreferred(pMe, dNum);
}

static inline void
QCBOREncode_AddFloatNoPreferredToMap(QCBOREncodeContext *pMe,
                                     const char         *szLabel,
                                     const float         dNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddFloatNoPreferred(pMe, dNum);
}

static inline void
QCBOREncode_AddFloatNoPreferredToMapN(QCBOREncodeContext *pMe,
                                      const int64_t       nLabel,
                                      const float         dNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddFloatNoPreferred(pMe, dNum);
}
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */





static inline void
QCBOREncode_AddTDateEpoch(QCBOREncodeContext *pMe,
                          const uint8_t       uTag,
                          const int64_t       nDate)
{
   if(uTag == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_DATE_EPOCH);
   }
   QCBOREncode_AddInt64(pMe, nDate);
}

static inline void
QCBOREncode_AddTDateEpochToMapSZ(QCBOREncodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTag,
                                 const int64_t       nDate)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDateEpoch(pMe, uTag, nDate);
}

static inline void
QCBOREncode_AddTDateEpochToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTag,
                                const int64_t       nDate)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDateEpoch(pMe, uTag, nDate);
}

static inline void
QCBOREncode_AddDateEpoch(QCBOREncodeContext *pMe,
                         const int64_t       nDate)
{
   QCBOREncode_AddTDateEpoch(pMe, QCBOR_ENCODE_AS_TAG, nDate);
}

static inline void
QCBOREncode_AddDateEpochToMap(QCBOREncodeContext *pMe,
                              const char         *szLabel,
                              const int64_t       nDate)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddDateEpoch(pMe, nDate);
}

static inline void
QCBOREncode_AddDateEpochToMapN(QCBOREncodeContext *pMe,
                               const int64_t       nLabel,
                               const int64_t       nDate)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddDateEpoch(pMe, nDate);
}


static inline void
QCBOREncode_AddTDaysEpoch(QCBOREncodeContext *pMe,
                          const uint8_t       uTag,
                          const int64_t       nDays)
{
   if(uTag == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_DAYS_EPOCH);
   }
   QCBOREncode_AddInt64(pMe, nDays);
}

static inline void
QCBOREncode_AddTDaysEpochToMapSZ(QCBOREncodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTag,
                                 const int64_t       nDays)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDaysEpoch(pMe, uTag, nDays);
}

static inline void
QCBOREncode_AddTDaysEpochToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTag,
                                const int64_t       nDays)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDaysEpoch(pMe, uTag, nDays);
}


static inline void
QCBOREncode_AddBytes(QCBOREncodeContext *pMe,
                     const UsefulBufC    Bytes)
{
   QCBOREncode_Private_AddBuffer(pMe, CBOR_MAJOR_TYPE_BYTE_STRING, Bytes);
}

static inline void
QCBOREncode_AddBytesToMap(QCBOREncodeContext *pMe,
                          const char         *szLabel,
                          const UsefulBufC    Bytes)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddBytes(pMe, Bytes);
}

static inline void
QCBOREncode_AddBytesToMapN(QCBOREncodeContext *pMe,
                           const int64_t       nLabel,
                           const UsefulBufC    Bytes)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddBytes(pMe, Bytes);
}

static inline void
QCBOREncode_OpenBytesInMapSZ(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             UsefulBuf          *pPlace)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenBytes(pMe, pPlace);
}

static inline void
QCBOREncode_OpenBytesInMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            UsefulBuf          *pPlace)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenBytes(pMe, pPlace);
}


/*
 * Public functions for adding only a byte string length. See qcbor/qcbor_encode.h
 */
static inline void
QCBOREncode_AddBytesLenOnly(QCBOREncodeContext *pMe, const UsefulBufC Bytes)
{
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_BYTE_STRING, Bytes.len, 0);
}


static inline void
QCBOREncode_AddBytesLenOnlyToMap(QCBOREncodeContext *pMe,
                                 const char         *szLabel,
                                 const UsefulBufC    Bytes)
{
    QCBOREncode_AddSZString(pMe, szLabel);
    QCBOREncode_AddBytesLenOnly(pMe, Bytes);
}

static inline void
QCBOREncode_AddBytesLenOnlyToMapN(QCBOREncodeContext *pMe,
                                  const int64_t       nLabel,
                                  const UsefulBufC    Bytes)
{
    QCBOREncode_AddInt64(pMe, nLabel);
    QCBOREncode_AddBytesLenOnly(pMe, Bytes);
}


static inline void
QCBOREncode_AddTBinaryUUID(QCBOREncodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           const UsefulBufC    Bytes)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_BIN_UUID);
   }
   QCBOREncode_AddBytes(pMe, Bytes);
}

static inline void
QCBOREncode_AddTBinaryUUIDToMapSZ(QCBOREncodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  const UsefulBufC    Bytes)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBinaryUUID(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddTBinaryUUIDToMapN(QCBOREncodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 const UsefulBufC    Bytes)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBinaryUUID(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddBinaryUUID(QCBOREncodeContext *pMe, const UsefulBufC Bytes)
{
   QCBOREncode_AddTBinaryUUID(pMe, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddBinaryUUIDToMap(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const UsefulBufC    Bytes)
{
   QCBOREncode_AddTBinaryUUIDToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddBinaryUUIDToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const UsefulBufC    Bytes)
{
   QCBOREncode_AddTBinaryUUIDToMapN(pMe,
                                    nLabel,
                                    QCBOR_ENCODE_AS_TAG,
                                    Bytes);
}


static inline void
QCBOREncode_AddTPositiveBignum(QCBOREncodeContext *pMe,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    Bytes)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_POS_BIGNUM);
   }
   QCBOREncode_AddBytes(pMe, Bytes);
}

static inline void
QCBOREncode_AddTPositiveBignumToMapSZ(QCBOREncodeContext *pMe,
                                      const char         *szLabel,
                                      const uint8_t       uTagRequirement,
                                      const UsefulBufC    Bytes)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTPositiveBignum(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddTPositiveBignumToMapN(QCBOREncodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint8_t       uTagRequirement,
                                     const UsefulBufC    Bytes)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTPositiveBignum(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddPositiveBignum(QCBOREncodeContext *pMe, const UsefulBufC Bytes)
{
   QCBOREncode_AddTPositiveBignum(pMe, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddPositiveBignumToMap(QCBOREncodeContext *pMe,
                                   const char         *szLabel,
                                   const UsefulBufC    Bytes)
{
   QCBOREncode_AddTPositiveBignumToMapSZ(pMe,
                                         szLabel,
                                         QCBOR_ENCODE_AS_TAG,
                                         Bytes);
}

static inline void
QCBOREncode_AddPositiveBignumToMapN(QCBOREncodeContext *pMe,
                                    const int64_t       nLabel,
                                    const UsefulBufC    Bytes)
{
   QCBOREncode_AddTPositiveBignumToMapN(pMe,
                                        nLabel,
                                        QCBOR_ENCODE_AS_TAG,
                                        Bytes);
}


static inline void
QCBOREncode_AddTNegativeBignum(QCBOREncodeContext *pMe,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    Bytes)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_NEG_BIGNUM);
   }
   QCBOREncode_AddBytes(pMe, Bytes);
}

static inline void
QCBOREncode_AddTNegativeBignumToMapSZ(QCBOREncodeContext *pMe,
                                      const char         *szLabel,
                                      const uint8_t       uTagRequirement,
                                      const UsefulBufC    Bytes)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTNegativeBignum(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddTNegativeBignumToMapN(QCBOREncodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint8_t       uTagRequirement,
                                     const UsefulBufC    Bytes)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTNegativeBignum(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddNegativeBignum(QCBOREncodeContext *pMe, const UsefulBufC Bytes)
{
   QCBOREncode_AddTNegativeBignum(pMe, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddNegativeBignumToMap(QCBOREncodeContext *pMe,
                                   const char         *szLabel,
                                   const UsefulBufC    Bytes)
{
   QCBOREncode_AddTNegativeBignumToMapSZ(pMe,
                                         szLabel,
                                         QCBOR_ENCODE_AS_TAG,
                                         Bytes);
}

static inline void
QCBOREncode_AddNegativeBignumToMapN(QCBOREncodeContext *pMe,
                                    const int64_t       nLabel,
                                    const UsefulBufC    Bytes)
{
   QCBOREncode_AddTNegativeBignumToMapN(pMe,
                                        nLabel,
                                        QCBOR_ENCODE_AS_TAG,
                                        Bytes);
}



#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

static inline void
QCBOREncode_AddTDecimalFraction(QCBOREncodeContext *pMe,
                                const uint8_t       uTagRequirement,
                                const int64_t       nMantissa,
                                const int64_t       nBase10Exponent)
{
   uint64_t uTag;
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      uTag = CBOR_TAG_DECIMAL_FRACTION;
   } else {
      uTag = CBOR_TAG_INVALID64;
   }
   QCBOREncode_Private_AddExpMantissa(pMe,
                                      uTag,
                                      NULLUsefulBufC,
                                      false,
                                      nMantissa,
                                      nBase10Exponent);
}

static inline void
QCBOREncode_AddTDecimalFractionToMapSZ(QCBOREncodeContext *pMe,
                                       const char         *szLabel,
                                       const uint8_t       uTagRequirement,
                                       const int64_t       nMantissa,
                                       const int64_t       nBase10Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDecimalFraction(pMe,
                                   uTagRequirement,
                                   nMantissa,
                                   nBase10Exponent);
}

static inline void
QCBOREncode_AddTDecimalFractionToMapN(QCBOREncodeContext *pMe,
                                      const int64_t       nLabel,
                                      const uint8_t       uTagRequirement,
                                      const int64_t       nMantissa,
                                      const int64_t       nBase10Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDecimalFraction(pMe,
                                   uTagRequirement,
                                   nMantissa,
                                   nBase10Exponent);
}

static inline void
QCBOREncode_AddDecimalFraction(QCBOREncodeContext *pMe,
                               const int64_t       nMantissa,
                               const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFraction(pMe,
                                   QCBOR_ENCODE_AS_TAG,
                                   nMantissa,
                                   nBase10Exponent);
}

static inline void
QCBOREncode_AddDecimalFractionToMap(QCBOREncodeContext *pMe,
                                    const char         *szLabel,
                                    const int64_t       nMantissa,
                                    const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionToMapSZ(pMe,
                                          szLabel,
                                          QCBOR_ENCODE_AS_TAG,
                                          nMantissa,
                                          nBase10Exponent);
}

static inline void
QCBOREncode_AddDecimalFractionToMapN(QCBOREncodeContext *pMe,
                                     const int64_t       nLabel,
                                     const int64_t       nMantissa,
                                     const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionToMapN(pMe,
                                         nLabel,
                                         QCBOR_ENCODE_AS_TAG,
                                         nMantissa,
                                         nBase10Exponent);
}



static inline void
QCBOREncode_AddTDecimalFractionBigNum(QCBOREncodeContext *pMe,
                                      const uint8_t       uTagRequirement,
                                      const UsefulBufC    Mantissa,
                                      const bool          bIsNegative,
                                      const int64_t       nBase10Exponent)
{
   uint64_t uTag;
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      uTag = CBOR_TAG_DECIMAL_FRACTION;
   } else {
      uTag = CBOR_TAG_INVALID64;
   }
   QCBOREncode_Private_AddExpMantissa(pMe,
                                      uTag,
                                      Mantissa,
                                      bIsNegative,
                                      0,
                                      nBase10Exponent);
}

static inline void
QCBOREncode_AddTDecimalFractionBigNumToMapSZ(QCBOREncodeContext *pMe,
                                             const char         *szLabel,
                                             const uint8_t       uTagRequirement,
                                             const UsefulBufC    Mantissa,
                                             const bool          bIsNegative,
                                             const int64_t       nBase10Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDecimalFractionBigNum(pMe,
                                         uTagRequirement,
                                         Mantissa,
                                         bIsNegative,
                                         nBase10Exponent);
}

static inline void
QCBOREncode_AddTDecimalFractionBigNumToMapN(QCBOREncodeContext *pMe,
                                            const int64_t       nLabel,
                                            const uint8_t       uTagRequirement,
                                            const UsefulBufC    Mantissa,
                                            const bool          bIsNegative,
                                            const int64_t       nBase10Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDecimalFractionBigNum(pMe,
                                         uTagRequirement,
                                         Mantissa,
                                         bIsNegative,
                                         nBase10Exponent);
}

static inline void
QCBOREncode_AddDecimalFractionBigNum(QCBOREncodeContext *pMe,
                                     const UsefulBufC    Mantissa,
                                     const bool          bIsNegative,
                                     const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionBigNum(pMe,
                                         QCBOR_ENCODE_AS_TAG,
                                         Mantissa,
                                         bIsNegative,
                                         nBase10Exponent);
}

static inline void
QCBOREncode_AddDecimalFractionBigNumToMapSZ(QCBOREncodeContext *pMe,
                                            const char         *szLabel,
                                            const UsefulBufC    Mantissa,
                                            const bool          bIsNegative,
                                            const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionBigNumToMapSZ(pMe,
                                                szLabel,
                                                QCBOR_ENCODE_AS_TAG,
                                                Mantissa,
                                                bIsNegative,
                                                nBase10Exponent);
}

static inline void
QCBOREncode_AddDecimalFractionBigNumToMapN(QCBOREncodeContext *pMe,
                                           const int64_t       nLabel,
                                           const UsefulBufC    Mantissa,
                                           const bool          bIsNegative,
                                           const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTDecimalFractionBigNumToMapN(pMe,
                                               nLabel,
                                               QCBOR_ENCODE_AS_TAG,
                                               Mantissa,
                                               bIsNegative,
                                               nBase2Exponent);
}





static inline void
QCBOREncode_AddTBigFloat(QCBOREncodeContext *pMe,
                         const uint8_t       uTagRequirement,
                         const int64_t       nMantissa,
                         const int64_t       nBase2Exponent)
{
   uint64_t uTag;
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      uTag = CBOR_TAG_BIGFLOAT;
   } else {
      uTag = CBOR_TAG_INVALID64;
   }
   QCBOREncode_Private_AddExpMantissa(pMe,
                                      uTag,
                                      NULLUsefulBufC,
                                      false,
                                      nMantissa,
                                      nBase2Exponent);
}

static inline void
QCBOREncode_AddTBigFloatToMapSZ(QCBOREncodeContext *pMe,
                                const char         *szLabel,
                                const uint8_t       uTagRequirement,
                                const int64_t       nMantissa,
                                const int64_t       nBase2Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBigFloat(pMe, uTagRequirement, nMantissa, nBase2Exponent);
}

static inline void
QCBOREncode_AddTBigFloatToMapN(QCBOREncodeContext *pMe,
                               const int64_t       nLabel,
                               const uint8_t       uTagRequirement,
                               const int64_t       nMantissa,
                               const int64_t       nBase2Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBigFloat(pMe, uTagRequirement, nMantissa, nBase2Exponent);
}

static inline void
QCBOREncode_AddBigFloat(QCBOREncodeContext *pMe,
                        const int64_t       nMantissa,
                        const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloat(pMe,
                            QCBOR_ENCODE_AS_TAG,
                            nMantissa,
                            nBase2Exponent);
}

static inline void
QCBOREncode_AddBigFloatToMap(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const int64_t       nMantissa,
                             const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatToMapSZ(pMe,
                                   szLabel,
                                   QCBOR_ENCODE_AS_TAG,
                                   nMantissa,
                                   nBase2Exponent);
}

static inline void
QCBOREncode_AddBigFloatToMapN(QCBOREncodeContext *pMe,
                              const int64_t       nLabel,
                              const int64_t       nMantissa,
                              const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatToMapN(pMe,
                                  nLabel,
                                  QCBOR_ENCODE_AS_TAG,
                                  nMantissa,
                                  nBase2Exponent);
}



static inline void
QCBOREncode_AddTBigFloatBigNum(QCBOREncodeContext *pMe,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    Mantissa,
                               const bool          bIsNegative,
                               const int64_t       nBase2Exponent)
{
   uint64_t uTag;
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      uTag = CBOR_TAG_BIGFLOAT;
   } else {
      uTag = CBOR_TAG_INVALID64;
   }
   QCBOREncode_Private_AddExpMantissa(pMe,
                                      uTag,
                                      Mantissa,
                                      bIsNegative,
                                      0,
                                      nBase2Exponent);
}

static inline void
QCBOREncode_AddTBigFloatBigNumToMapSZ(QCBOREncodeContext *pMe,
                                      const char         *szLabel,
                                      const uint8_t       uTagRequirement,
                                      const UsefulBufC    Mantissa,
                                      const bool          bIsNegative,
                                      const int64_t       nBase2Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBigFloatBigNum(pMe,
                                  uTagRequirement,
                                  Mantissa,
                                  bIsNegative,
                                  nBase2Exponent);
}

static inline void
QCBOREncode_AddTBigFloatBigNumToMapN(QCBOREncodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint8_t       uTagRequirement,
                                     const UsefulBufC    Mantissa,
                                     const bool          bIsNegative,
                                     const int64_t       nBase2Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBigFloatBigNum(pMe,
                                  uTagRequirement,
                                  Mantissa,
                                  bIsNegative,
                                  nBase2Exponent);
}


static inline void
QCBOREncode_AddBigFloatBigNum(QCBOREncodeContext *pMe,
                              const UsefulBufC    Mantissa,
                              const bool          bIsNegative,
                              const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigNum(pMe,
                                  QCBOR_ENCODE_AS_TAG,
                                  Mantissa, bIsNegative,
                                  nBase2Exponent);
}

static inline void
QCBOREncode_AddBigFloatBigNumToMap(QCBOREncodeContext *pMe,
                                   const char         *szLabel,
                                   const UsefulBufC    Mantissa,
                                   const bool          bIsNegative,
                                   const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigNumToMapSZ(pMe,
                                         szLabel,
                                         QCBOR_ENCODE_AS_TAG,
                                         Mantissa,
                                         bIsNegative,
                                         nBase2Exponent);
}

static inline void
QCBOREncode_AddBigFloatBigNumToMapN(QCBOREncodeContext *pMe,
                                    const int64_t       nLabel,
                                    const UsefulBufC    Mantissa,
                                    const bool          bIsNegative,
                                    const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigNumToMapN(pMe,
                                        nLabel,
                                        QCBOR_ENCODE_AS_TAG,
                                        Mantissa,
                                        bIsNegative,
                                        nBase2Exponent);
}
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */


static inline void
QCBOREncode_AddTURI(QCBOREncodeContext *pMe,
                    const uint8_t       uTagRequirement,
                    const UsefulBufC    URI)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_URI);
   }
   QCBOREncode_AddText(pMe, URI);
}

static inline void
QCBOREncode_AddTURIToMapSZ(QCBOREncodeContext *pMe,
                           const char         *szLabel,
                           const uint8_t       uTagRequirement,
                           const UsefulBufC    URI)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTURI(pMe, uTagRequirement, URI);
}

static inline void
QCBOREncode_AddTURIToMapN(QCBOREncodeContext *pMe,
                          const int64_t       nLabel,
                          const uint8_t       uTagRequirement,
                          const UsefulBufC    URI)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTURI(pMe, uTagRequirement, URI);
}

static inline void
QCBOREncode_AddURI(QCBOREncodeContext *pMe, const UsefulBufC URI)
{
   QCBOREncode_AddTURI(pMe, QCBOR_ENCODE_AS_TAG, URI);
}

static inline void
QCBOREncode_AddURIToMap(QCBOREncodeContext *pMe,
                        const char         *szLabel,
                        const UsefulBufC    URI)
{
   QCBOREncode_AddTURIToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, URI);
}

static inline void
QCBOREncode_AddURIToMapN(QCBOREncodeContext *pMe,
                         const int64_t       nLabel,
                         const UsefulBufC    URI)
{
   QCBOREncode_AddTURIToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, URI);
}



static inline void
QCBOREncode_AddTB64Text(QCBOREncodeContext *pMe,
                        const uint8_t       uTagRequirement,
                        const UsefulBufC    B64Text)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_B64);
   }
   QCBOREncode_AddText(pMe, B64Text);
}

static inline void
QCBOREncode_AddTB64TextToMapSZ(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    B64Text)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTB64Text(pMe, uTagRequirement, B64Text);
}

static inline void
QCBOREncode_AddTB64TextToMapN(QCBOREncodeContext *pMe,
                              const int64_t       nLabel,
                              const uint8_t       uTagRequirement,
                              const UsefulBufC    B64Text)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTB64Text(pMe, uTagRequirement, B64Text);
}

static inline void
QCBOREncode_AddB64Text(QCBOREncodeContext *pMe, const UsefulBufC B64Text)
{
   QCBOREncode_AddTB64Text(pMe, QCBOR_ENCODE_AS_TAG, B64Text);
}

static inline void
QCBOREncode_AddB64TextToMap(QCBOREncodeContext *pMe,
                            const char         *szLabel,
                            const UsefulBufC    B64Text)
{
   QCBOREncode_AddTB64TextToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, B64Text);
}

static inline void
QCBOREncode_AddB64TextToMapN(QCBOREncodeContext *pMe,
                             const int64_t       nLabel,
                             const UsefulBufC    B64Text)
{
   QCBOREncode_AddTB64TextToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, B64Text);
}



static inline void
QCBOREncode_AddTB64URLText(QCBOREncodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           const UsefulBufC    B64Text)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_B64URL);
   }
   QCBOREncode_AddText(pMe, B64Text);
}

static inline void
QCBOREncode_AddTB64URLTextToMapSZ(QCBOREncodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  const UsefulBufC    B64Text)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTB64URLText(pMe, uTagRequirement, B64Text);
}

static inline void
QCBOREncode_AddTB64URLTextToMapN(QCBOREncodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 const UsefulBufC    B64Text)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTB64URLText(pMe, uTagRequirement, B64Text);
}

static inline void
QCBOREncode_AddB64URLText(QCBOREncodeContext *pMe, const UsefulBufC B64Text)
{
   QCBOREncode_AddTB64URLText(pMe, QCBOR_ENCODE_AS_TAG, B64Text);
}

static inline void
QCBOREncode_AddB64URLTextToMap(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const UsefulBufC    B64Text)
{
   QCBOREncode_AddTB64URLTextToMapSZ(pMe,
                                     szLabel,
                                     QCBOR_ENCODE_AS_TAG,
                                     B64Text);
}

static inline void
QCBOREncode_AddB64URLTextToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const UsefulBufC    B64Text)
{
   QCBOREncode_AddTB64URLTextToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, B64Text);
}



static inline void
QCBOREncode_AddTRegex(QCBOREncodeContext *pMe,
                      const uint8_t       uTagRequirement,
                      const UsefulBufC    Bytes)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_REGEX);
   }
   QCBOREncode_AddText(pMe, Bytes);
}

static inline void
QCBOREncode_AddTRegexToMapSZ(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const uint8_t       uTagRequirement,
                             const UsefulBufC    Bytes)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTRegex(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddTRegexToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const uint8_t       uTagRequirement,
                            const UsefulBufC    Bytes)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTRegex(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddRegex(QCBOREncodeContext *pMe, const UsefulBufC Bytes)
{
   QCBOREncode_AddTRegex(pMe, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddRegexToMap(QCBOREncodeContext *pMe,
                          const char         *szLabel,
                          const UsefulBufC    Bytes)
{
   QCBOREncode_AddTRegexToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddRegexToMapN(QCBOREncodeContext *pMe,
                           const int64_t       nLabel,
                           const UsefulBufC    Bytes)
{
   QCBOREncode_AddTRegexToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, Bytes);

}


static inline void
QCBOREncode_AddTMIMEData(QCBOREncodeContext *pMe,
                         const uint8_t       uTagRequirement,
                         const UsefulBufC    MIMEData)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_BINARY_MIME);
   }
   QCBOREncode_AddBytes(pMe, MIMEData);
}

static inline void
QCBOREncode_AddTMIMEDataToMapSZ(QCBOREncodeContext *pMe,
                                const char         *szLabel,
                                const uint8_t       uTagRequirement,
                                const UsefulBufC    MIMEData)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTMIMEData(pMe, uTagRequirement, MIMEData);
}

static inline void
QCBOREncode_AddTMIMEDataToMapN(QCBOREncodeContext *pMe,
                               const int64_t       nLabel,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    MIMEData)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTMIMEData(pMe, uTagRequirement, MIMEData);
}

static inline void
QCBOREncode_AddMIMEData(QCBOREncodeContext *pMe, UsefulBufC MIMEData)
{
   QCBOREncode_AddTMIMEData(pMe, QCBOR_ENCODE_AS_TAG, MIMEData);
}

static inline void
QCBOREncode_AddMIMEDataToMap(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const UsefulBufC    MIMEData)
{
   QCBOREncode_AddTMIMEDataToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, MIMEData);
}

static inline void
QCBOREncode_AddMIMEDataToMapN(QCBOREncodeContext *pMe,
                              const int64_t       nLabel,
                              const UsefulBufC    MIMEData)
{
   QCBOREncode_AddTMIMEDataToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, MIMEData);
}


static inline void
QCBOREncode_AddTDateString(QCBOREncodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           const char         *szDate)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_DATE_STRING);
   }
   QCBOREncode_AddSZString(pMe, szDate);
}

static inline void
QCBOREncode_AddTDateStringToMapSZ(QCBOREncodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  const char         *szDate)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDateString(pMe, uTagRequirement, szDate);
}

static inline void
QCBOREncode_AddTDateStringToMapN(QCBOREncodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 const char         *szDate)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDateString(pMe, uTagRequirement, szDate);
}

static inline void
QCBOREncode_AddDateString(QCBOREncodeContext *pMe, const char *szDate)
{
   QCBOREncode_AddTDateString(pMe, QCBOR_ENCODE_AS_TAG, szDate);
}

static inline void
QCBOREncode_AddDateStringToMap(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const char         *szDate)
{
   QCBOREncode_AddTDateStringToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, szDate);
}

static inline void
QCBOREncode_AddDateStringToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const char         *szDate)
{
   QCBOREncode_AddTDateStringToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, szDate);
}


static inline void
QCBOREncode_AddTDaysString(QCBOREncodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           const char         *szDate)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, CBOR_TAG_DAYS_STRING);
   }
   QCBOREncode_AddSZString(pMe, szDate);
}

static inline void
QCBOREncode_AddTDaysStringToMapSZ(QCBOREncodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  const char         *szDate)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDaysString(pMe, uTagRequirement, szDate);
}

static inline void
QCBOREncode_AddTDaysStringToMapN(QCBOREncodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 const char         *szDate)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDaysString(pMe, uTagRequirement, szDate);
}


static inline void
QCBOREncode_AddSimple(QCBOREncodeContext *pMe, const uint8_t uNum)
{
   /* This check often is optimized out because uNum is known at compile time. */
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uNum >= CBOR_SIMPLEV_RESERVED_START && uNum <= CBOR_SIMPLEV_RESERVED_END) {
      pMe->uError = QCBOR_ERR_ENCODE_UNSUPPORTED;
      return;
   }
#endif /* !QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   QCBOREncode_Private_AddType7(pMe, 0, uNum);
}

static inline void
QCBOREncode_AddSimpleToMap(QCBOREncodeContext *pMe,
                           const char         *szLabel,
                           const uint8_t       uSimple)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddSimple(pMe, uSimple);
}

static inline void
QCBOREncode_AddSimpleToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const uint8_t       uSimple)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddSimple(pMe, uSimple);
}


static inline void
QCBOREncode_AddBool(QCBOREncodeContext *pMe, const bool b)
{
   uint8_t uSimple = CBOR_SIMPLEV_FALSE;
   if(b) {
      uSimple = CBOR_SIMPLEV_TRUE;
   }
   QCBOREncode_AddSimple(pMe, uSimple);
}

static inline void
QCBOREncode_AddBoolToMap(QCBOREncodeContext *pMe, const char *szLabel, const bool b)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddBool(pMe, b);
}

static inline void
QCBOREncode_AddBoolToMapN(QCBOREncodeContext *pMe, const int64_t nLabel, const bool b)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddBool(pMe, b);
}


static inline void
QCBOREncode_AddNULL(QCBOREncodeContext *pMe)
{
   QCBOREncode_AddSimple(pMe, CBOR_SIMPLEV_NULL);
}

static inline void
QCBOREncode_AddNULLToMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddNULL(pMe);
}

static inline void
QCBOREncode_AddNULLToMapN(QCBOREncodeContext *pMe, const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddNULL(pMe);
}


static inline void
QCBOREncode_AddUndef(QCBOREncodeContext *pMe)
{
   QCBOREncode_AddSimple(pMe, CBOR_SIMPLEV_UNDEF);
}

static inline void
QCBOREncode_AddUndefToMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddUndef(pMe);
}

static inline void
QCBOREncode_AddUndefToMapN(QCBOREncodeContext *pMe, const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddUndef(pMe);
}


static inline void
QCBOREncode_OpenArray(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArray(pMe, CBOR_MAJOR_TYPE_ARRAY);
}

static inline void
QCBOREncode_OpenArrayInMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenArray(pMe);
}

static inline void
QCBOREncode_OpenArrayInMapN(QCBOREncodeContext *pMe,  const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenArray(pMe);
}

static inline void
QCBOREncode_CloseArray(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_CloseMapOrArray(pMe, CBOR_MAJOR_TYPE_ARRAY);
}


static inline void
QCBOREncode_OpenMap(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArray(pMe, CBOR_MAJOR_TYPE_MAP);
}

static inline void
QCBOREncode_OpenMapInMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenMap(pMe);
}

static inline void
QCBOREncode_OpenMapInMapN(QCBOREncodeContext *pMe, const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenMap(pMe);
}

static inline void
QCBOREncode_CloseMap(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_CloseMapOrArray(pMe, CBOR_MAJOR_TYPE_MAP);
}

static inline void
QCBOREncode_OpenArrayIndefiniteLength(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_ARRAY_INDEFINITE_LEN);
}

static inline void
QCBOREncode_OpenArrayIndefiniteLengthInMap(QCBOREncodeContext *pMe,
                                           const char         *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenArrayIndefiniteLength(pMe);
}

static inline void
QCBOREncode_OpenArrayIndefiniteLengthInMapN(QCBOREncodeContext *pMe,
                                            const int64_t       nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenArrayIndefiniteLength(pMe);
}

static inline void
QCBOREncode_CloseArrayIndefiniteLength(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_ARRAY_INDEFINITE_LEN);
}


static inline void
QCBOREncode_OpenMapIndefiniteLength(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_MAP_INDEFINITE_LEN);
}

static inline void
QCBOREncode_OpenMapIndefiniteLengthInMap(QCBOREncodeContext *pMe,
                                         const char         *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenMapIndefiniteLength(pMe);
}

static inline void
QCBOREncode_OpenMapIndefiniteLengthInMapN(QCBOREncodeContext *pMe,
                                          const int64_t       nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenMapIndefiniteLength(pMe);
}

static inline void
QCBOREncode_CloseMapIndefiniteLength(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_MAP_INDEFINITE_LEN);
}


static inline void
QCBOREncode_BstrWrap(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArray(pMe, CBOR_MAJOR_TYPE_BYTE_STRING);
}

static inline void
QCBOREncode_BstrWrapInMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_BstrWrap(pMe);
}

static inline void
QCBOREncode_BstrWrapInMapN(QCBOREncodeContext *pMe, const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_BstrWrap(pMe);
}

static inline void
QCBOREncode_CloseBstrWrap(QCBOREncodeContext *pMe, UsefulBufC *pWrappedCBOR)
{
   QCBOREncode_CloseBstrWrap2(pMe, true, pWrappedCBOR);
}



static inline void
QCBOREncode_AddEncodedToMap(QCBOREncodeContext *pMe,
                            const char         *szLabel,
                            const UsefulBufC    Encoded)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddEncoded(pMe, Encoded);
}

static inline void
QCBOREncode_AddEncodedToMapN(QCBOREncodeContext *pMe,
                             const int64_t       nLabel,
                             const UsefulBufC    Encoded)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddEncoded(pMe, Encoded);
}


static inline int
QCBOREncode_IsBufferNULL(QCBOREncodeContext *pMe)
{
   return UsefulOutBuf_IsBufferNULL(&(pMe->OutBuf));
}

static inline QCBORError
QCBOREncode_GetErrorState(QCBOREncodeContext *pMe)
{
   if(UsefulOutBuf_GetError(&(pMe->OutBuf))) {
      /* Items didn't fit in the buffer. This check catches this
       * condition for all the appends and inserts so checks aren't
       * needed when the appends and inserts are performed.  And of
       * course UsefulBuf will never overrun the input buffer given to
       * it. No complex analysis of the error handling in this file is
       * needed to know that is true. Just read the UsefulBuf code.
       */
      pMe->uError = QCBOR_ERR_BUFFER_TOO_SMALL;
      /* QCBOR_ERR_BUFFER_TOO_SMALL masks other errors, but that is
       * OK. Once the caller fixes this, they'll be unmasked.
       */
   }

   return (QCBORError)pMe->uError;
}


/* ========================================================================
     END OF PRIVATE INLINE IMPLEMENTATION
   ======================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* qcbor_encode_h */
