// SPDX-License-Identifier: BSD-3-Clause
/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2024, Laurence Lundblade.
 Copyright (c) 2021, Arm Limited.
 All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors, nor the name "Laurence Lundblade" may be used to
      endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 =============================================================================*/


#include "qcbor/qcbor_encode.h"
#include "ieee754.h"


/**
 * @file qcbor_encode.c
 *
 * The entire implementation of the QCBOR encoder.
 */


/*
 * == Nesting Tracking ==
 *
 * The following functions and data type QCBORTrackNesting implement
 * the nesting management for encoding.
 *
 * CBOR's two nesting types, arrays and maps, are tracked here. There
 * is a limit of QCBOR_MAX_ARRAY_NESTING to the number of arrays and
 * maps that can be nested in one encoding so the encoding context
 * stays small enough to fit on the stack.
 *
 * When an array/map is opened, pCurrentNesting points to the element
 * in pArrays that records the type, start position and accumulates a
 * count of the number of items added. When closed the start position
 * is used to go back and fill in the type and number of items in the
 * array/map.
 *
 * Encoded output can be a CBOR Sequence (RFC 8742) in which case
 * there is no top-level array or map. It starts out with a string,
 * integer or other non-aggregate type. It may have an array or map
 * other than at the start, in which case that nesting is tracked
 * here.
 *
 * QCBOR has a special feature to allow constructing byte string
 * wrapped CBOR directly into the output buffer, so no extra buffer is
 * needed for byte string wrapping.  This is implemented as nesting
 * with the type CBOR_MAJOR_TYPE_BYTE_STRING and is tracked here. Byte
 * string wrapped CBOR is used by COSE for data that is to be hashed.
 */
static void
Nesting_Init(QCBORTrackNesting *pNesting)
{
   /* Assumes pNesting has been zeroed. */
   pNesting->pCurrentNesting = &pNesting->pArrays[0];
   /* Implied CBOR array at the top nesting level. This is never
    * returned, but makes the item count work correctly.
    */
   pNesting->pCurrentNesting->uMajorType = CBOR_MAJOR_TYPE_ARRAY;
}

static uint8_t
Nesting_Increase(QCBORTrackNesting *pNesting,
                 const uint8_t      uMajorType,
                 const uint32_t     uPos)
{
   if(pNesting->pCurrentNesting == &pNesting->pArrays[QCBOR_MAX_ARRAY_NESTING]) {
      return QCBOR_ERR_ARRAY_NESTING_TOO_DEEP;
   } else {
      pNesting->pCurrentNesting++;
      pNesting->pCurrentNesting->uCount     = 0;
      pNesting->pCurrentNesting->uStart     = uPos;
      pNesting->pCurrentNesting->uMajorType = uMajorType;
      return QCBOR_SUCCESS;
   }
}

static void
Nesting_Decrease(QCBORTrackNesting *pNesting)
{
   if(pNesting->pCurrentNesting > &pNesting->pArrays[0]) {
      pNesting->pCurrentNesting--;
   }
}

static uint8_t
Nesting_Increment(QCBORTrackNesting *pNesting)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(1 >= QCBOR_MAX_ITEMS_IN_ARRAY - pNesting->pCurrentNesting->uCount) {
      return QCBOR_ERR_ARRAY_TOO_LONG;
   }
#endif /* !QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   pNesting->pCurrentNesting->uCount++;

   return QCBOR_SUCCESS;
}

static void
Nesting_Decrement(QCBORTrackNesting *pNesting)
{
   /* No error check for going below 0 here needed because this
    * is only used by QCBOREncode_CancelBstrWrap() and it checks
    * the nesting level before calling this. */
   pNesting->pCurrentNesting->uCount--;
}

static uint16_t
Nesting_GetCount(QCBORTrackNesting *pNesting)
{
   /* The nesting count recorded is always the actual number of
    * individual data items in the array or map. For arrays CBOR uses
    * the actual item count. For maps, CBOR uses the number of pairs.
    * This function returns the number needed for the CBOR encoding,
    * so it divides the number of items by two for maps to get the
    * number of pairs.
    */
   if(pNesting->pCurrentNesting->uMajorType == CBOR_MAJOR_TYPE_MAP) {
      /* Cast back to uint16_t after integer promotion from bit shift */
      return (uint16_t)(pNesting->pCurrentNesting->uCount >> 1);
   } else {
      return pNesting->pCurrentNesting->uCount;
   }
}

static uint32_t
Nesting_GetStartPos(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->uStart;
}

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
static uint8_t
Nesting_GetMajorType(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->uMajorType;
}

static bool
Nesting_IsInNest(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting == &pNesting->pArrays[0] ? false : true;
}
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */




/*
 * == Major CBOR Types ==
 *
 * Encoding of the major CBOR types is by these functions:
 *
 * CBOR Major Type  Public Function
 * 0                QCBOREncode_AddUInt64()
 * 0, 1             QCBOREncode_AddUInt64(), QCBOREncode_AddInt64()
 * 2, 3             QCBOREncode_AddBuffer()
 * 4, 5             QCBOREncode_OpenMapOrArray(), QCBOREncode_CloseMapOrArray(),
 *                  QCBOREncode_OpenMapOrArrayIndefiniteLength(),
 *                  QCBOREncode_CloseMapOrArrayIndefiniteLength()
 * 6                QCBOREncode_AddTag()
 * 7                QCBOREncode_AddDouble(), QCBOREncode_AddFloat(),
 *                  QCBOREncode_AddDoubleNoPreferred(),
 *                  QCBOREncode_AddFloatNoPreferred(), QCBOREncode_AddType7()
 *
 * Additionally, encoding of decimal fractions and bigfloats is by
 * QCBOREncode_AddExponentAndMantissa() and byte strings that wrap
 * encoded CBOR are handled by QCBOREncode_OpenMapOrArray() and
 * QCBOREncode_CloseBstrWrap2().
 *
 *
 * == Error Tracking Plan ==
 *
 * Errors are tracked internally and not returned until
 * QCBOREncode_Finish() or QCBOREncode_GetErrorState() is called. The
 * CBOR errors are in me->uError.  UsefulOutBuf also tracks whether
 * the buffer is full or not in its context.  Once either of these
 * errors is set they are never cleared. Only QCBOREncode_Init()
 * resets them. Or said another way, they must never be cleared or
 * we'll tell the caller all is good when it is not.
 *
 * Only one error code is reported by QCBOREncode_Finish() even if
 * there are multiple errors. The last one set wins. The caller might
 * have to fix one error to reveal the next one they have to fix.
 * This is OK.
 *
 * The buffer full error tracked by UsefulBuf is only pulled out of
 * UsefulBuf in QCBOREncode_Finish() so it is the one that usually
 * wins.  UsefulBuf will never go off the end of the buffer even if it
 * is called again and again when full.
 *
 * QCBOR_DISABLE_ENCODE_USAGE_GUARDS disables about half of the error
 * checks here to reduce code size by about 150 bytes leaving only the
 * checks for size to avoid buffer overflow. If the calling code is
 * completely correct, checks are completely unnecessary.  For
 * example, there is no need to check that all the opens are matched
 * by a close.
 *
 * QCBOR_DISABLE_ENCODE_USAGE_GUARDS also disables the check for more
 * than QCBOR_MAX_ITEMS_IN_ARRAY in an array. Since
 * QCBOR_MAX_ITEMS_IN_ARRAY is very large (65,535) it is very unlikely
 * to be reached. If it is reached, the count will wrap around to zero
 * and CBOR that is not well formed will be produced, but there will
 * be no buffers overrun and new security issues in the code.
 *
 * The 8 errors returned here fall into three categories:
 *
 * Sizes
 *   QCBOR_ERR_BUFFER_TOO_LARGE        -- Encoded output exceeded UINT32_MAX
 *   QCBOR_ERR_BUFFER_TOO_SMALL        -- Output buffer too small
 *   QCBOR_ERR_ARRAY_NESTING_TOO_DEEP  -- Nesting > QCBOR_MAX_ARRAY_NESTING1
 *   QCBOR_ERR_ARRAY_TOO_LONG          -- Too many items added to an array/map [1]
 *
 * Nesting constructed incorrectly
 *   QCBOR_ERR_TOO_MANY_CLOSES         -- More close calls than opens [1]
 *   QCBOR_ERR_CLOSE_MISMATCH          -- Type of close does not match open [1]
 *   QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN -- Finish called without enough closes [1]
 *
 * Would generate not-well-formed CBOR
 *   QCBOR_ERR_ENCODE_UNSUPPORTED      -- Simple type between 24 and 31 [1]
 *
 * [1] indicated disabled by QCBOR_DISABLE_ENCODE_USAGE_GUARDS
 */


/*
 * Public function for initialization. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_Init(QCBOREncodeContext *pMe, UsefulBuf Storage)
{
   memset(pMe, 0, sizeof(QCBOREncodeContext));
   UsefulOutBuf_Init(&(pMe->OutBuf), Storage);
   Nesting_Init(&(pMe->nesting));
}


/*
 * Public function to encode a CBOR head. See qcbor/qcbor_encode.h
 */
UsefulBufC
QCBOREncode_EncodeHead(UsefulBuf Buffer,
                       uint8_t   uMajorType,
                       uint8_t   uMinLen,
                       uint64_t  uArgument)
{
   /*
    * == Description of the CBOR Head ==
    *
    *    The head of a CBOR data item
    *  +---+-----+ +--------+ +--------+ +--------+      +--------+
    *  |M T|  A R G U M E N T . . .                               |
    *  +---+-----+ +--------+ +--------+ +--------+ ...  +--------+
    *
    * Every CBOR data item has a "head". It is made up of the "major
    * type" and the "argument".
    *
    * The major type indicates whether the data item is an integer,
    * string, array or such. It is encoded in 3 bits giving it a range
    * from 0 to 7.  0 indicates the major type is a positive integer,
    * 1 a negative integer, 2 a byte string and so on.
    *
    * These 3 bits are the first part of the "initial byte" in a data
    * item.  Every data item has an initial byte, and some only have
    * the initial byte.
    *
    * The argument is essentially a number between 0 and UINT64_MAX
    * (18446744073709551615). This number is interpreted to mean
    * different things for the different major types. For major type
    * 0, a positive integer, it is value of the data item. For major
    * type 2, a byte string, it is the length in bytes of the byte
    * string. For major type 4, an array, it is the number of data
    * items in the array.
    *
    * Special encoding is used so that the argument values less than
    * 24 can be encoded very compactly in the same byte as the major
    * type is encoded. When the lower 5 bits of the initial byte have
    * a value less than 24, then that is the value of the argument.
    *
    * If the lower 5 bits of the initial byte are less than 24, then
    * they are the value of the argument. This allows integer values 0
    * - 23 to be CBOR encoded in just one byte.
    *
    * When the value of lower 5 bits are 24, 25, 26, or 27 the
    * argument is encoded in 1, 2, 4 or 8 bytes following the initial
    * byte in network byte order (bit endian). The cases when it is
    * 28, 29 and 30 are reserved for future use. The value 31 is a
    * special indicator for indefinite length strings, arrays and
    * maps.
    *
    * The lower 5 bits are called the "additional information."
    *
    * Thus the CBOR head may be 1, 2, 3, 5 or 9 bytes long.
    *
    * It is legal in CBOR to encode the argument using any of these
    * lengths even if it could be encoded in a shorter length. For
    * example it is legal to encode a data item representing the
    * positive integer 0 in 9 bytes even though it could be encoded in
    * only 0. This is legal to allow for for very simple code or even
    * hardware-only implementations that just output a register
    * directly.
    *
    * CBOR defines preferred encoding as the encoding of the argument
    * in the smallest number of bytes needed to encode it.
    *
    * This function takes the major type and argument as inputs and
    * outputs the encoded CBOR head for them. It does conversion to
    * network byte order.  It implements CBOR preferred encoding,
    * outputting the shortest representation of the argument.
    *
    * == Endian Conversion ==
    *
    * This code does endian conversion without hton() or knowing the
    * endianness of the machine by using masks and shifts. This avoids
    * the dependency on hton() and the mess of figuring out how to
    * find the machine's endianness.
    *
    * This is a good efficient implementation on little-endian
    * machines.  A faster and smaller implementation is possible on
    * big-endian machines because CBOR/network byte order is
    * big-endian. However big-endian machines are uncommon.
    *
    * On x86, this is about 150 bytes instead of 500 bytes for the
    * original, more formal unoptimized code.
    *
    * This also does the CBOR preferred shortest encoding for integers
    * and is called to do endian conversion for floats.
    *
    * It works backwards from the least significant byte to the most
    * significant byte.
    *
    * == Floating Point ==
    *
    * When the major type is 7 and the 5 lower bits have the values
    * 25, 26 or 27, the argument is a floating-point number that is
    * half, single or double-precision. Note that it is not the
    * conversion from a floating-point value to an integer value like
    * converting 0x00 to 0.00, it is the interpretation of the bits in
    * the argument as an IEEE 754 float-point number.
    *
    * Floating-point numbers must be converted to network byte
    * order. That is accomplished here by exactly the same code that
    * converts integer arguments to network byte order.
    *
    * There is preferred encoding for floating-point numbers in CBOR,
    * but it is very different than for integers and it is not
    * implemented here.  Half-precision is preferred to
    * single-precision which is preferred to double-precision only if
    * the conversion can be performed without loss of precision. Zero
    * and infinity can always be converted to half-precision, without
    * loss but 3.141592653589 cannot.
    *
    * The way this function knows to not do preferred encoding on the
    * argument passed here when it is a floating point number is the
    * uMinLen parameter. It should be 2, 4 or 8 for half, single and
    * double precision floating point values. This prevents and the
    * incorrect removal of leading zeros when encoding arguments that
    * are floating-point numbers.
    *
    * == Use of Type int and Static Analyzers ==
    *
    * The type int is used here for several variables because of the
    * way integer promotion works in C for variables that are uint8_t
    * or uint16_t. The basic rule is that they will always be promoted
    * to int if they will fit. These integer variables here need only
    * hold values less than 255 so they will always fit into an int.
    *
    * Most of values stored are never negative, so one might think
    * that unsigned int would be more correct than int. However the C
    * integer promotion rules only promote to unsigned int if the
    * result won't fit into an int even if the promotion is for an
    * unsigned variable like uint8_t.
    *
    * By declaring these int, there are few implicit conversions and
    * fewer casts needed. Code size is reduced a little. It makes
    * static analyzers happier.
    *
    * Note also that declaring these uint8_t won't stop integer wrap
    * around if the code is wrong. It won't make the code more
    * correct.
    *
    * https://stackoverflow.com/questions/46073295/implicit-type-promotion-rules
    * https://stackoverflow.com/questions/589575/what-does-the-c-standard-state-the-size-of-int-long-type-to-be
    *
    * Code Reviewers: THIS FUNCTION DOES POINTER MATH
    */

   /* The buffer must have room for the largest CBOR HEAD + one
    * extra. The one extra is needed for this code to work as it does
    * a pre-decrement.
    */
    if(Buffer.len < QCBOR_HEAD_BUFFER_SIZE) {
        return NULLUsefulBufC;
    }

   /* Pointer to last valid byte in the buffer */
   uint8_t * const pBufferEnd = &((uint8_t *)Buffer.ptr)[QCBOR_HEAD_BUFFER_SIZE-1];

   /* Point to the last byte and work backwards */
   uint8_t *pByte = pBufferEnd;
   /* The 5 bits in the initial byte that are not the major type */
   int nAdditionalInfo;

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   if(uMajorType > QCBOR_INDEFINITE_LEN_TYPE_MODIFIER) {
      /* Special case for start & end of indefinite length */
      uMajorType  = uMajorType - QCBOR_INDEFINITE_LEN_TYPE_MODIFIER;
      /* This takes advantage of design of CBOR where additional info
       * is 31 for both opening and closing indefinite length
       * maps and arrays.
       */
       #if CBOR_SIMPLE_BREAK != LEN_IS_INDEFINITE
       #error additional info for opening array not the same as for closing
       #endif
      nAdditionalInfo = CBOR_SIMPLE_BREAK;

   } else
#endif /* !QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
      if (uArgument < CBOR_TWENTY_FOUR && uMinLen == 0) {
      /* Simple case where argument is < 24 */
      nAdditionalInfo = (int)uArgument;

   } else  {
      /* This encodes the argument in 1,2,4 or 8 bytes. The outer loop
       * runs once for 1 byte and 4 times for 8 bytes.  The inner loop
       * runs 1, 2 or 4 times depending on outer loop counter. This
       * works backwards shifting 8 bits off the argument being
       * encoded at a time until all bits from uArgument have been
       * encoded and the minimum encoding size is reached.  Minimum
       * encoding size is for floating-point numbers that have some
       * zero-value bytes that must be output.
       */
      static const uint8_t aIterate[] = {1,1,2,4};

      /* uMinLen passed in is unsigned, but goes negative in the loop
       * so it must be converted to a signed value.
       */
      int nMinLen = (int)uMinLen;
      int i;
      for(i = 0; uArgument || nMinLen > 0; i++) {
         const int nIterations = (int)aIterate[i];
         for(int j = 0; j < nIterations; j++) {
            *--pByte = (uint8_t)(uArgument & 0xff);
            uArgument = uArgument >> 8;
         }
         nMinLen -= nIterations;
      }

      nAdditionalInfo = LEN_IS_ONE_BYTE-1 + i;
   }

   /* This expression integer-promotes to type int. The code above in
    * function guarantees that nAdditionalInfo will never be larger
    * than 0x1f. The caller may pass in a too-large uMajor type. The
    * conversion to uint8_t will cause an integer wrap around and
    * incorrect CBOR will be generated, but no security issue will
    * occur.
    */
   const int nInitialByte = (uMajorType << 5) + nAdditionalInfo;
   *--pByte = (uint8_t)nInitialByte;

#ifdef EXTRA_ENCODE_HEAD_CHECK
   /* This is a sanity check that can be turned on to verify the
    * pointer math in this function is not going wrong. Turn it on and
    * run the whole test suite to perform the check.
    */
   if(pBufferEnd - pByte > 9 || pBufferEnd - pByte < 1 || pByte < (uint8_t *)buffer.ptr) {
      return NULLUsefulBufC;
   }
#endif /* EXTRA_ENCODE_HEAD_CHECK */

   /* Length will not go negative because the loops run for at most 8 decrements
    * of pByte, only one other decrement is made, and the array is sized
    * for this.
    */
   return (UsefulBufC){pByte, (size_t)(pBufferEnd - pByte)};
}


/**
 * @brief Increment item counter for maps and arrays.
 *
 * @param pMe          QCBOR encoding context.
 *
 * This is mostly a separate function to make code more readable and
 * to have fewer occurrences of #ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
 */
static void
QCBOREncode_Private_IncrementMapOrArrayCount(QCBOREncodeContext *pMe)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uError == QCBOR_SUCCESS) {
      pMe->uError = Nesting_Increment(&(pMe->nesting));
   }
#else
   (void)Nesting_Increment(&(pMe->nesting));
#endif /* !QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
}


/**
 * @brief Append the CBOR head, the major type and argument
 *
 * @param pMe         Encoder context.
 * @param uMajorType  Major type to insert.
 * @param uArgument   The argument (an integer value or a length).
 * @param uMinLen     The minimum number of bytes for encoding the CBOR argument.
 *
 * This formats the CBOR "head" and appends it to the output.
 *
 * This also increments the array/map item counter in most cases.
 */
void
QCBOREncode_Private_AppendCBORHead(QCBOREncodeContext *pMe,
                                   const uint8_t       uMajorType,
                                   const uint64_t      uArgument,
                                   const uint8_t       uMinLen)
{
   /* A stack buffer large enough for a CBOR head */
   UsefulBuf_MAKE_STACK_UB  (pBufferForEncodedHead, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC EncodedHead = QCBOREncode_EncodeHead(pBufferForEncodedHead,
                                                    uMajorType,
                                                    uMinLen,
                                                    uArgument);

   /* No check for EncodedHead == NULLUsefulBufC is performed here to
    * save object code. It is very clear that pBufferForEncodedHead is
    * the correct size. If EncodedHead == NULLUsefulBufC then
    * UsefulOutBuf_AppendUsefulBuf() will do nothing so there is no
    * security hole introduced.
    */

   UsefulOutBuf_AppendUsefulBuf(&(pMe->OutBuf), EncodedHead);

   if(!(uMajorType & QCBOR_INDEFINITE_LEN_TYPE_MODIFIER || uMajorType == CBOR_MAJOR_TYPE_TAG)) {
      /* Don't increment the map count for tag or break because that is
       * not needed. Don't do it for indefinite-length arrays and maps
       * because it is done elsewhere. This is never called for definite-length
       * arrays and maps.
       */
      QCBOREncode_Private_IncrementMapOrArrayCount(pMe);
   }
}


/*
 * Public functions for adding signed integers. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_AddInt64(QCBOREncodeContext *pMe, const int64_t nNum)
{
   uint8_t  uMajorType;
   uint64_t uValue;

   if(nNum < 0) {
      /* In CBOR -1 encodes as 0x00 with major type negative int.
       * First add one as a signed integer because that will not
       * overflow. Then change the sign as needed for encoding.  (The
       * opposite order, changing the sign and subtracting, can cause
       * an overflow when encoding INT64_MIN. */
      int64_t nTmp = nNum + 1;
      uValue = (uint64_t)-nTmp;
      uMajorType = CBOR_MAJOR_TYPE_NEGATIVE_INT;
   } else {
      uValue = (uint64_t)nNum;
      uMajorType = CBOR_MAJOR_TYPE_POSITIVE_INT;
   }
   QCBOREncode_Private_AppendCBORHead(pMe, uMajorType, uValue, 0);
}


/**
 * @brief Semi-private method to add a buffer full of bytes to encoded output.
 *
 * @param[in] pMe       The encoding context to add the string to.
 * @param[in] uMajorType The CBOR major type of the bytes.
 * @param[in] Bytes      The bytes to add.
 *
 * Called by inline functions to add text and byte strings.
 *
 * (This used to support QCBOREncode_AddEncoded() and
 * QCBOREncode_AddBytesLenOnly(), but that was pulled out to make this
 * smaller. This is one of the most used methods and they are some of
 * the least used).
 */
void
QCBOREncode_Private_AddBuffer(QCBOREncodeContext *pMe,
                              const uint8_t       uMajorType,
                              const UsefulBufC    Bytes)
{
   QCBOREncode_Private_AppendCBORHead(pMe, uMajorType, Bytes.len, 0);
   UsefulOutBuf_AppendUsefulBuf(&(pMe->OutBuf), Bytes);
}


/*
 * Public functions for adding raw encoded CBOR. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_AddEncoded(QCBOREncodeContext *pMe, const UsefulBufC Encoded)
{
   UsefulOutBuf_AppendUsefulBuf(&(pMe->OutBuf), Encoded);
   QCBOREncode_Private_IncrementMapOrArrayCount(pMe);
}


#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
/**
 * @brief Semi-private method to add a double using preferred encoding.
 *
 * @param[in] pMe   The encode context.
 * @param[in] dNum  The double to add.
 *
 * This converts the double to a float or half-precision if it can be done
 * without a loss of precision. See QCBOREncode_AddDouble().
 */
void
QCBOREncode_Private_AddPreferredDouble(QCBOREncodeContext *pMe, const double dNum)
{
   const IEEE754_union uNum = IEEE754_DoubleToSmaller(dNum, true);
   QCBOREncode_Private_AddType7(pMe, (uint8_t)uNum.uSize, uNum.uValue);
}


/**
 * @brief Semi-private method to add a float using preferred encoding.
 *
 * @param[in] pMe   The encode context.
 * @param[in] fNum  The float to add.
 *
 * This converts the float to a half-precision if it can be done
 * without a loss of precision. See QCBOREncode_AddFloat().
 */
void
QCBOREncode_Private_AddPreferredFloat(QCBOREncodeContext *pMe, const float fNum)
{
   const IEEE754_union uNum = IEEE754_SingleToHalf(fNum);
   QCBOREncode_Private_AddType7(pMe, (uint8_t)uNum.uSize, uNum.uValue);
}
#endif /* !QCBOR_DISABLE_PREFERRED_FLOAT */


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
/**
 * @brief  Semi-private method to add bigfloats and decimal fractions.
 *
 * @param[in] pMe               The encoding context to add the value to.
 * @param[in] uTag               The type 6 tag indicating what this is to be.
 * @param[in] BigNumMantissa     Is @ref NULLUsefulBufC if mantissa is an
 *                               @c int64_t or the actual big number mantissa
 *                               if not.
 * @param[in] bBigNumIsNegative  This is @c true if the big number is negative.
 * @param[in] nMantissa          The @c int64_t mantissa if it is not a big number.
 * @param[in] nExponent          The exponent.
 *
 * This outputs either the @ref CBOR_TAG_DECIMAL_FRACTION or
 * @ref CBOR_TAG_BIGFLOAT tag. if @c uTag is @ref CBOR_TAG_INVALID64,
 * then this outputs the "borrowed" content format.
 *
 * The tag content output by this is an array with two members, the
 * exponent and then the mantissa. The mantissa can be either a big
 * number or an @c int64_t.
 *
 * This implementation cannot output an exponent further from 0 than
 * @c INT64_MAX.
 *
 * To output a mantissa that is between INT64_MAX and UINT64_MAX from 0,
 * it must be as a big number.
 *
 * Typically, QCBOREncode_AddDecimalFraction(), QCBOREncode_AddBigFloat(),
 * QCBOREncode_AddDecimalFractionBigNum() or QCBOREncode_AddBigFloatBigNum()
 * is called instead of this.
 */
void
QCBOREncode_Private_AddExpMantissa(QCBOREncodeContext *pMe,
                                   const uint64_t      uTag,
                                   const UsefulBufC    BigNumMantissa,
                                   const bool          bBigNumIsNegative,
                                   const int64_t       nMantissa,
                                   const int64_t       nExponent)
{
   /* This is for encoding either a big float or a decimal fraction,
    * both of which are an array of two items, an exponent and a
    * mantissa.  The difference between the two is that the exponent
    * is base-2 for big floats and base-10 for decimal fractions, but
    * that has no effect on the code here.
    */
   if(uTag != CBOR_TAG_INVALID64) {
      QCBOREncode_AddTag(pMe, uTag);
   }
   QCBOREncode_OpenArray(pMe);
   QCBOREncode_AddInt64(pMe, nExponent);
   if(!UsefulBuf_IsNULLC(BigNumMantissa)) {
      if(bBigNumIsNegative) {
         QCBOREncode_AddNegativeBignum(pMe, BigNumMantissa);
      } else {
         QCBOREncode_AddPositiveBignum(pMe, BigNumMantissa);
      }
   } else {
      QCBOREncode_AddInt64(pMe, nMantissa);
   }
   QCBOREncode_CloseArray(pMe);
}
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */


/**
 * @brief Semi-private method to open a map, array or bstr-wrapped CBOR
 *
 * @param[in] pMe        The context to add to.
 * @param[in] uMajorType  The major CBOR type to close
 *
 * Call QCBOREncode_OpenArray(), QCBOREncode_OpenMap() or
 * QCBOREncode_BstrWrap() instead of this.
 */
void
QCBOREncode_Private_OpenMapOrArray(QCBOREncodeContext *pMe,
                                   const uint8_t       uMajorType)
{
   /* Add one item to the nesting level we are in for the new map or array */
   QCBOREncode_Private_IncrementMapOrArrayCount(pMe);

   /* The offset where the length of an array or map will get written
    * is stored in a uint32_t, not a size_t to keep stack usage
    * smaller. This checks to be sure there is no wrap around when
    * recording the offset.  Note that on 64-bit machines CBOR larger
    * than 4GB can be encoded as long as no array/map offsets occur
    * past the 4GB mark, but the public interface says that the
    * maximum is 4GB to keep the discussion simpler.
    */
   size_t uEndPosition = UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));

   /* QCBOR_MAX_ARRAY_OFFSET is slightly less than UINT32_MAX so this
    * code can run on a 32-bit machine and tests can pass on a 32-bit
    * machine. If it was exactly UINT32_MAX, then this code would not
    * compile or run on a 32-bit machine and an #ifdef or some machine
    * size detection would be needed reducing portability.
    */
   if(uEndPosition >= QCBOR_MAX_ARRAY_OFFSET) {
      pMe->uError = QCBOR_ERR_BUFFER_TOO_LARGE;

   } else {
      /* Increase nesting level because this is a map or array.  Cast
       * from size_t to uin32_t is safe because of check above.
       */
      pMe->uError = Nesting_Increase(&(pMe->nesting), uMajorType, (uint32_t)uEndPosition);
   }
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/**
 * @brief Semi-private method to open a map, array with indefinite length
 *
 * @param[in] pMe        The context to add to.
 * @param[in] uMajorType  The major CBOR type to close
 *
 * Call QCBOREncode_OpenArrayIndefiniteLength() or
 * QCBOREncode_OpenMapIndefiniteLength() instead of this.
 */
void
QCBOREncode_Private_OpenMapOrArrayIndefiniteLength(QCBOREncodeContext *pMe,
                                                   const uint8_t       uMajorType)
{
   /* Insert the indefinite length marker (0x9f for arrays, 0xbf for maps) */
   QCBOREncode_Private_AppendCBORHead(pMe, uMajorType, 0, 0);

   /* Call the definite-length opener just to do the bookkeeping for
    * nesting.  It will record the position of the opening item in the
    * encoded output but this is not used when closing this open.
    */
   QCBOREncode_Private_OpenMapOrArray(pMe, uMajorType);
}
#endif


/**
 * @brief Check for errors when decreasing nesting.
 *
 * @param pMe          QCBOR encoding context.
 * @param uMajorType  The major type of the nesting.
 *
 * Check that there is no previous error, that there is actually some
 * nesting and that the major type of the opening of the nesting
 * matches the major type of the nesting being closed.
 *
 * This is called when closing maps, arrays, byte string wrapping and
 * open/close of byte strings.
 */
static bool
QCBOREncode_Private_CheckDecreaseNesting(QCBOREncodeContext *pMe,
                                         const uint8_t       uMajorType)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uError != QCBOR_SUCCESS) {
      return true;
   }

   if(!Nesting_IsInNest(&(pMe->nesting))) {
      pMe->uError = QCBOR_ERR_TOO_MANY_CLOSES;
      return true;
   }

   if(Nesting_GetMajorType(&(pMe->nesting)) != uMajorType) {
      pMe->uError = QCBOR_ERR_CLOSE_MISMATCH;
      return true;
   }

#else /* !QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   /* None of these checks are performed if the encode guards are
    * turned off as they all relate to correct calling.
    *
    * Turning off all these checks does not turn off any checking for
    * buffer overflows or pointer issues.
    */

   (void)uMajorType;
   (void)pMe;
#endif /* !QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   return false;
}


/**
 * @brief Insert the CBOR head for a map, array or wrapped bstr
 *
 * @param pMe         QCBOR encoding context.
 * @param uMajorType  One of CBOR_MAJOR_TYPE_XXXX.
 * @param uLen        The length of the data item.
 *
 * When an array, map or bstr was opened, nothing was done but note
 * the position. This function goes back to that position and inserts
 * the CBOR Head with the major type and length.
 */
static void
QCBOREncode_Private_CloseAggregate(QCBOREncodeContext *pMe,
                                   uint8_t             uMajorType,
                                   size_t              uLen)
{
   if(QCBOREncode_Private_CheckDecreaseNesting(pMe, uMajorType)) {
      return;
   }

   if(uMajorType == CBOR_MAJOR_NONE_TYPE_OPEN_BSTR) {
      uMajorType = CBOR_MAJOR_TYPE_BYTE_STRING;
   }

   /* A stack buffer large enough for a CBOR head (9 bytes) */
   UsefulBuf_MAKE_STACK_UB(pBufferForEncodedHead, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC EncodedHead = QCBOREncode_EncodeHead(pBufferForEncodedHead,
                                                   uMajorType,
                                                   0,
                                                   uLen);

   /* No check for EncodedHead == NULLUsefulBufC is performed here to
    * save object code. It is very clear that pBufferForEncodedHead is
    * the correct size. If EncodedHead == NULLUsefulBufC then
    * UsefulOutBuf_InsertUsefulBuf() will do nothing so there is no
    * security hole introduced.
    */
   UsefulOutBuf_InsertUsefulBuf(&(pMe->OutBuf),
                                EncodedHead,
                                Nesting_GetStartPos(&(pMe->nesting)));

   Nesting_Decrease(&(pMe->nesting));
}


/**
 * @brief Semi-private method to close a map, array or bstr wrapped CBOR
 *
 * @param[in] pMe           The context to add to.
 * @param[in] uMajorType     The major CBOR type to close.
 *
 * Call QCBOREncode_CloseArray() or QCBOREncode_CloseMap() instead of this.
 */
void
QCBOREncode_Private_CloseMapOrArray(QCBOREncodeContext *pMe,
                                    const uint8_t       uMajorType)
{
   QCBOREncode_Private_CloseAggregate(pMe, uMajorType, Nesting_GetCount(&(pMe->nesting)));
}


/*
 * Public functions for closing bstr wrapping. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_CloseBstrWrap2(QCBOREncodeContext *pMe,
                           const bool          bIncludeCBORHead,
                           UsefulBufC         *pWrappedCBOR)
{
   const size_t uInsertPosition = Nesting_GetStartPos(&(pMe->nesting));
   const size_t uEndPosition    = UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));

   /* This subtraction can't go negative because the UsefulOutBuf
    * always only grows and never shrinks. UsefulOutBut itself also
    * has defenses such that it won't write where it should not even
    * if given incorrect input lengths.
    */
   const size_t uBstrLen = uEndPosition - uInsertPosition;

   /* Actually insert */
   QCBOREncode_Private_CloseAggregate(pMe, CBOR_MAJOR_TYPE_BYTE_STRING, uBstrLen);

   if(pWrappedCBOR) {
      /* Return pointer and length to the enclosed encoded CBOR. The
       * intended use is for it to be hashed (e.g., SHA-256) in a COSE
       * implementation.  This must be used right away, as the pointer
       * and length go invalid on any subsequent calls to this
       * function because there might be calls to
       * InsertEncodedTypeAndNumber() that slides data to the right.
       */
      size_t uStartOfNew = uInsertPosition;
      if(!bIncludeCBORHead) {
         /* Skip over the CBOR head to just get the inserted bstr */
         const size_t uNewEndPosition = UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));
         uStartOfNew += uNewEndPosition - uEndPosition;
      }
      const UsefulBufC PartialResult = UsefulOutBuf_OutUBuf(&(pMe->OutBuf));
      *pWrappedCBOR = UsefulBuf_Tail(PartialResult, uStartOfNew);
   }
}


/*
 * Public function for canceling a bstr wrap. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_CancelBstrWrap(QCBOREncodeContext *pMe)
{
   if(QCBOREncode_Private_CheckDecreaseNesting(pMe, CBOR_MAJOR_TYPE_BYTE_STRING)) {
      return;
   }

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   const size_t uCurrent = UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));
   if(pMe->nesting.pCurrentNesting->uStart != uCurrent) {
      pMe->uError = QCBOR_ERR_CANNOT_CANCEL;
      return;
   }
   /* QCBOREncode_CancelBstrWrap() can't correctly undo
    * QCBOREncode_BstrWrapInMap() or QCBOREncode_BstrWrapInMapN(). It
    * can't undo the labels they add. It also doesn't catch the error
    * of using it this way.  QCBOREncode_CancelBstrWrap() is used
    * infrequently and the the result is incorrect CBOR, not a
    * security hole, so no extra code or state is added to handle this
    * condition.
    */
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   Nesting_Decrease(&(pMe->nesting));
   Nesting_Decrement(&(pMe->nesting));
}


/*
 * Public function for opening a byte string. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_OpenBytes(QCBOREncodeContext *pMe, UsefulBuf *pPlace)
{
   *pPlace = UsefulOutBuf_GetOutPlace(&(pMe->OutBuf));
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   uint8_t uMajorType = Nesting_GetMajorType(&(pMe->nesting));
   if(uMajorType == CBOR_MAJOR_NONE_TYPE_OPEN_BSTR) {
      /* It's OK to nest a byte string in any type but
       * another open byte string. */
      pMe->uError = QCBOR_ERR_OPEN_BYTE_STRING;
      return;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   QCBOREncode_Private_OpenMapOrArray(pMe, CBOR_MAJOR_NONE_TYPE_OPEN_BSTR);
}


/*
 * Public function for closing a byte string. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_CloseBytes(QCBOREncodeContext *pMe, const size_t uAmount)
{
   UsefulOutBuf_Advance(&(pMe->OutBuf), uAmount);
   if(UsefulOutBuf_GetError(&(pMe->OutBuf))) {
      /* Advance too far. Normal off-end error handling in effect here. */
      return;
   }

   QCBOREncode_Private_CloseAggregate(pMe, CBOR_MAJOR_NONE_TYPE_OPEN_BSTR, uAmount);
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS

/**
 * @brief Semi-private method to close a map, array with indefinite length
 *
 * @param[in] pMe           The context to add to.
 * @param[in] uMajorType     The major CBOR type to close.
 *
 * Call QCBOREncode_CloseArrayIndefiniteLength() or
 * QCBOREncode_CloseMapIndefiniteLength() instead of this.
 */
void
QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(QCBOREncodeContext *pMe,
                                                    const uint8_t       uMajorType)
{
   if(QCBOREncode_Private_CheckDecreaseNesting(pMe, uMajorType)) {
      return;
   }

   /* Append the break marker (0xff for both arrays and maps) */
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_NONE_TYPE_SIMPLE_BREAK, CBOR_SIMPLE_BREAK, 0);
   Nesting_Decrease(&(pMe->nesting));
}
#endif


/*
 * Public function to finish and get the encoded result. See qcbor/qcbor_encode.h
 */
QCBORError
QCBOREncode_Finish(QCBOREncodeContext *pMe, UsefulBufC *pEncodedCBOR)
{
   if(QCBOREncode_GetErrorState(pMe) != QCBOR_SUCCESS) {
      goto Done;
   }

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(Nesting_IsInNest(&(pMe->nesting))) {
      pMe->uError = QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN;
      goto Done;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   *pEncodedCBOR = UsefulOutBuf_OutUBuf(&(pMe->OutBuf));

Done:
   return pMe->uError;
}


/*
 * Public functions to get size of the encoded result. See qcbor/qcbor_encode.h
 */
QCBORError
QCBOREncode_FinishGetSize(QCBOREncodeContext *pMe, size_t *puEncodedLen)
{
   UsefulBufC Enc;

   QCBORError nReturn = QCBOREncode_Finish(pMe, &Enc);

   if(nReturn == QCBOR_SUCCESS) {
      *puEncodedLen = Enc.len;
   }

   return nReturn;
}
