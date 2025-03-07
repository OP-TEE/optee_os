// SPDX-License-Identifier: BSD-3-Clause
/* ==========================================================================
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


#ifndef qcbor_private_h
#define qcbor_private_h


#include <stdint.h>
#include "UsefulBuf.h"
#include "qcbor/qcbor_common.h"


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif


/* This was originally defined as QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA,
 * but this is inconsistent with all the other QCBOR_DISABLE_
 * #defines, so the name was changed and this was added for backwards
 * compatibility
 */
#ifdef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
#define QCBOR_DISABLE_EXP_AND_MANTISSA
#endif

/* If USEFULBUF_DISABLE_ALL_FLOATis defined then define
 * QCBOR_DISABLE_FLOAT_HW_USE and QCBOR_DISABLE_PREFERRED_FLOAT
 */
#ifdef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
#define QCBOR_DISABLE_FLOAT_HW_USE
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
#define QCBOR_DISABLE_PREFERRED_FLOAT
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */


/*
 * Convenience macro for selecting the proper return value in case floating
 * point feature(s) are disabled.
 *
 * The macros:
 *
 *  FLOAT_ERR_CODE_NO_FLOAT(x) Can be used when disabled floating point should
 *                              result error, and all other cases should return
 *                             'x'.
 *
 *  The below macros always return QCBOR_ERR_ALL_FLOAT_DISABLED when all
 *  floating point is disabled.
 *
 *  FLOAT_ERR_CODE_NO_HALF_PREC(x) Can be used when disabled preferred float
 *                                 results in error, and all other cases should
 *                                 return 'x'.
 *  FLOAT_ERR_CODE_NO_FLOAT_HW(x) Can be used when disabled hardware floating
 *                                point results in error, and all other cases
 *                                should return 'x'.
 *  FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(x) Can be used when either disabled
 *                                             preferred float or disabling
 *                                             hardware floating point results in
 *                                             error, and all other cases should
 *                                             return 'x'.
 */
#ifdef USEFULBUF_DISABLE_ALL_FLOAT
   #define FLOAT_ERR_CODE_NO_FLOAT(x)                 QCBOR_ERR_ALL_FLOAT_DISABLED
   #define FLOAT_ERR_CODE_NO_HALF_PREC(x)             QCBOR_ERR_ALL_FLOAT_DISABLED
   #define FLOAT_ERR_CODE_NO_FLOAT_HW(x)              QCBOR_ERR_ALL_FLOAT_DISABLED
   #define FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(x) QCBOR_ERR_ALL_FLOAT_DISABLED
#else /* USEFULBUF_DISABLE_ALL_FLOAT*/
   #define FLOAT_ERR_CODE_NO_FLOAT(x)     x
   #ifdef QCBOR_DISABLE_PREFERRED_FLOAT
      #define FLOAT_ERR_CODE_NO_HALF_PREC(x) QCBOR_ERR_HALF_PRECISION_DISABLED
      #define FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(x) QCBOR_ERR_HALF_PRECISION_DISABLED
   #else /* QCBOR_DISABLE_PREFERRED_FLOAT */
      #define FLOAT_ERR_CODE_NO_HALF_PREC(x) x
      #ifdef QCBOR_DISABLE_FLOAT_HW_USE
         #define FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(x) QCBOR_ERR_HW_FLOAT_DISABLED
      #else
         #define FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(x) x
      #endif
   #endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
   #ifdef QCBOR_DISABLE_FLOAT_HW_USE
      #define FLOAT_ERR_CODE_NO_FLOAT_HW(x)  QCBOR_ERR_HW_FLOAT_DISABLED
   #else /* QCBOR_DISABLE_FLOAT_HW_USE */
      #define FLOAT_ERR_CODE_NO_FLOAT_HW(x)  x
   #endif /* QCBOR_DISABLE_FLOAT_HW_USE */
#endif /*USEFULBUF_DISABLE_ALL_FLOAT*/


/*
 * These are special values for the AdditionalInfo bits that are part of
 * the first byte.  Mostly they encode the length of the data item.
 */
#define LEN_IS_ONE_BYTE    24
#define LEN_IS_TWO_BYTES   25
#define LEN_IS_FOUR_BYTES  26
#define LEN_IS_EIGHT_BYTES 27
#define ADDINFO_RESERVED1  28
#define ADDINFO_RESERVED2  29
#define ADDINFO_RESERVED3  30
#define LEN_IS_INDEFINITE  31


/*
 * 24 is a special number for CBOR. Integers and lengths
 * less than it are encoded in the same byte as the major type.
 */
#define CBOR_TWENTY_FOUR   24


/*
 * Values for the 5 bits for items of major type 7
 */
#define CBOR_SIMPLEV_FALSE   20
#define CBOR_SIMPLEV_TRUE    21
#define CBOR_SIMPLEV_NULL    22
#define CBOR_SIMPLEV_UNDEF   23
#define CBOR_SIMPLEV_ONEBYTE 24
#define HALF_PREC_FLOAT      25
#define SINGLE_PREC_FLOAT    26
#define DOUBLE_PREC_FLOAT    27
#define CBOR_SIMPLE_BREAK    31
#define CBOR_SIMPLEV_RESERVED_START  CBOR_SIMPLEV_ONEBYTE
#define CBOR_SIMPLEV_RESERVED_END    CBOR_SIMPLE_BREAK


/* The largest offset to the start of an array or map. It is slightly
 * less than UINT32_MAX so the error condition can be tested on 32-bit
 * machines.  UINT32_MAX comes from uStart in QCBORTrackNesting being
 * a uin32_t.
 *
 * This will cause trouble on a machine where size_t is less than 32-bits.
 */
#define QCBOR_MAX_ARRAY_OFFSET  (UINT32_MAX - 100)


/* The number of tags that are 16-bit or larger that can be handled
 * in a decode.
 */
#define QCBOR_NUM_MAPPED_TAGS 4

/* The number of tags (of any size) recorded for an individual item. */
#define QCBOR_MAX_TAGS_PER_ITEM1 4




/*
 * PRIVATE DATA STRUCTURE
 *
 * Holds the data for tracking array and map nesting during
 * encoding. Pairs up with the Nesting_xxx functions to make an
 * "object" to handle nesting encoding.
 *
 * uStart is a uint32_t instead of a size_t to keep the size of this
 * struct down so it can be on the stack without any concern.  It
 * would be about double if size_t was used instead.
 *
 * Size approximation (varies with CPU/compiler):
 *    64-bit machine: (15 + 1) * (4 + 2 + 1 + 1 pad) + 8 = 136 bytes
 *   32-bit machine: (15 + 1) * (4 + 2 + 1 + 1 pad) + 4 = 132 bytes
 */
typedef struct __QCBORTrackNesting {
  /* PRIVATE DATA STRUCTURE */
   struct {
      /* See QCBOREncode_OpenMapOrArray() for details on how this works */
      uint32_t  uStart;   /* uStart is the position where the array starts */
      uint16_t  uCount;   /* Number of items in the arrary or map; counts items
                           * in a map, not pairs of items */
      uint8_t   uMajorType; /* Indicates if item is a map or an array */
   } pArrays[QCBOR_MAX_ARRAY_NESTING+1], /* stored state for nesting levels */
   *pCurrentNesting; /* the current nesting level */
} QCBORTrackNesting;


/*
 * PRIVATE DATA STRUCTURE
 *
 * Context / data object for encoding some CBOR. Used by all encode
 * functions to form a public "object" that does the job of encdoing.
 *
 * Size approximation (varies with CPU/compiler):
 *   64-bit machine: 27 + 1 (+ 4 padding) + 136 = 32 + 136 = 168 bytes
 *  32-bit machine: 15 + 1 + 132 = 148 bytes
 */
struct _QCBOREncodeContext {
   /* PRIVATE DATA STRUCTURE */
   UsefulOutBuf      OutBuf;  /* Pointer to output buffer, its length and
                               * position in it. */
   uint8_t           uError;  /* Error state, always from QCBORError enum */
   QCBORTrackNesting nesting; /* Keep track of array and map nesting */
};


/*
 * PRIVATE DATA STRUCTURE
 *
 * Holds the data for array and map nesting for decoding work. This
 * structure and the DecodeNesting_Xxx() functions in qcbor_decode.c
 * form an "object" that does the work for arrays and maps. All access
 * to this structure is through DecodeNesting_Xxx() functions.
 *
 * 64-bit machine size
 *   128 = 16 * 8 for the two unions
 *   64  = 16 * 4 for the uLevelType, 1 byte padded to 4 bytes for alignment
 *   16  = 16 bytes for two pointers
 *   208 TOTAL
 *
 * 32-bit machine size is 200 bytes
 */
typedef struct __QCBORDecodeNesting  {
  /* PRIVATE DATA STRUCTURE */
   struct nesting_decode_level {
      /*
       * This keeps tracking info for each nesting level. There are two
       * main types of levels:
       *   1) Byte count tracking. This is for the top level input CBOR
       *   which might be a single item or a CBOR sequence and byte
       *   string wrapped encoded CBOR.
       *   2) Item count tracking. This is for maps and arrays.
       *
       * uLevelType has value QCBOR_TYPE_BYTE_STRING for 1) and
       * QCBOR_TYPE_MAP or QCBOR_TYPE_ARRAY or QCBOR_TYPE_MAP_AS_ARRAY
       * for 2).
       *
       * Item count tracking is either for definite or indefinite-length
       * maps/arrays. For definite lengths, the total count and items
       * unconsumed are tracked. For indefinite-length, uTotalCount is
       * QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH (UINT16_MAX) and
       * there is no per-item count of members. For indefinite-length
       * maps and arrays, uCountCursor is UINT16_MAX if not consumed
       * and zero if it is consumed in the pre-order
       * traversal. Additionally, if entered in bounded mode,
       * uCountCursor is QCBOR_COUNT_INDICATES_ZERO_LENGTH to indicate
       * it is empty.
       *
       * This also records whether a level is bounded or not. All
       * byte-count tracked levels (the top-level sequence and
       * bstr-wrapped CBOR) are bounded implicitly. Maps and arrays
       * may or may not be bounded. They are bounded if they were
       * Entered() and not if they were traversed with GetNext(). They
       * are marked as bounded by uStartOffset not being @c UINT32_MAX.
       */
      /*
       * If uLevelType can put in a separately indexed array, the
       * union/struct will be 8 bytes rather than 9 and a lot of
       * wasted padding for alignment will be saved.
       */
      uint8_t  uLevelType;
      union {
         struct {
#define QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH UINT16_MAX
#define QCBOR_COUNT_INDICATES_ZERO_LENGTH UINT16_MAX-1
            uint16_t uCountTotal;
            uint16_t uCountCursor;
#define QCBOR_NON_BOUNDED_OFFSET UINT32_MAX
            /* The start of the array or map in bounded mode so
             * the input can be rewound for GetInMapXx() by label. */
            uint32_t uStartOffset;
         } ma; /* for maps and arrays */
         struct {
            /* The end of the input before the bstr was entered so that
             * it can be restored when the bstr is exited. */
            uint32_t uSavedEndOffset;
            /* The beginning of the bstr so that it can be rewound. */
            uint32_t uBstrStartOffset;
         } bs; /* for top-level sequence and bstr-wrapped CBOR */
      } u;
   } pLevels[QCBOR_MAX_ARRAY_NESTING+1],
    *pCurrent,
    *pCurrentBounded;
   /*
    * pCurrent is for item-by-item pre-order traversal.
    *
    * pCurrentBounded points to the current bounding level or is NULL
    * if there isn't one.
    *
    * pCurrent must always be below pCurrentBounded as the pre-order
    * traversal is always bounded by the bounding level.
    *
    * When a bounded level is entered, the pre-order traversal is set
    * to the first item in the bounded level. When a bounded level is
    * exited, the pre-order traversl is set to the next item after the
    * map, array or bstr. This may be more than one level up, or even
    * the end of the input CBOR.
    */
} QCBORDecodeNesting;


typedef struct  {
   /* PRIVATE DATA STRUCTURE */
   void *pAllocateCxt;
   UsefulBuf (* pfAllocator)(void *pAllocateCxt, void *pOldMem, size_t uNewSize);
} QCBORInternalAllocator;


/*
 * PRIVATE DATA STRUCTURE
 *
 * The decode context. This data structure plus the public
 * QCBORDecode_xxx functions form an "object" that does CBOR decoding.
 *
 * Size approximation (varies with CPU/compiler):
 *  64-bit machine: 32 + 1 + 1 + 6 bytes padding + 72 + 16 + 8 + 8 = 144 bytes
 *  32-bit machine: 16 + 1 + 1 + 2 bytes padding + 68 +  8 + 8 + 4 = 108 bytes
 */
struct _QCBORDecodeContext {
  /* PRIVATE DATA STRUCTURE */
   UsefulInputBuf InBuf;

   QCBORDecodeNesting nesting;

   /* If a string allocator is configured for indefinite-length
    * strings, it is configured here.
    */
   QCBORInternalAllocator StringAllocator;

   /* These are special for the internal MemPool allocator.  They are
    * not used otherwise. We tried packing these in the MemPool
    * itself, but there are issues with memory alignment.
    */
   uint32_t uMemPoolSize;
   uint32_t uMemPoolFreeOffset;

   /* A cached offset to the end of the current map 0 if no value is
    * cached.
    */
#define QCBOR_MAP_OFFSET_CACHE_INVALID UINT32_MAX
   uint32_t uMapEndOffsetCache;

   uint8_t  uDecodeMode;
   uint8_t  bStringAllocateAll;
   uint8_t  uLastError;  /* QCBORError stuffed into a uint8_t */

   /* See MapTagNumber() for description of how tags are mapped. */
   uint64_t auMappedTags[QCBOR_NUM_MAPPED_TAGS];

   uint16_t uLastTags[QCBOR_MAX_TAGS_PER_ITEM1];
};


/* Used internally in the impementation here Must not conflict with
 * any of the official CBOR types
 */
#define CBOR_MAJOR_NONE_TAG_LABEL_REORDER  10
#define CBOR_MAJOR_NONE_TYPE_OPEN_BSTR     12


/* Add this to types to indicate they are to be encoded as indefinite lengths */
#define QCBOR_INDEFINITE_LEN_TYPE_MODIFIER 0x80
#define CBOR_MAJOR_NONE_TYPE_ARRAY_INDEFINITE_LEN \
            CBOR_MAJOR_TYPE_ARRAY + QCBOR_INDEFINITE_LEN_TYPE_MODIFIER
#define CBOR_MAJOR_NONE_TYPE_MAP_INDEFINITE_LEN \
            CBOR_MAJOR_TYPE_MAP + QCBOR_INDEFINITE_LEN_TYPE_MODIFIER
#define CBOR_MAJOR_NONE_TYPE_SIMPLE_BREAK \
            CBOR_MAJOR_TYPE_SIMPLE + QCBOR_INDEFINITE_LEN_TYPE_MODIFIER


/* Value of QCBORItem.val.string.len when the string length is
 * indefinite. Used temporarily in the implementation and never
 * returned in the public interface.
 */
#define QCBOR_STRING_LENGTH_INDEFINITE SIZE_MAX


/* The number of elements in a C array of a particular type */
#define C_ARRAY_COUNT(array, type) (sizeof(array)/sizeof(type))


#ifdef __cplusplus
}
#endif

#endif /* qcbor_private_h */
