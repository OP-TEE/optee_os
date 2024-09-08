/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2022, Laurence Lundblade.

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

/*=============================================================================
 FILE:  UsefulBuf.c

 DESCRIPTION:  General purpose input and output buffers

 EDIT HISTORY FOR FILE:

 This section contains comments describing changes made to the module.
 Notice that changes are listed in reverse chronological order.

 when        who          what, where, why
 --------    ----         ---------------------------------------------------
 19/12/2022  llundblade   Don't pass NULL to memmove when adding empty data.
 4/11/2022   llundblade   Add GetOutPlace and Advance to UsefulOutBuf
 3/6/2021     mcr/llundblade  Fix warnings related to --Wcast-qual
 01/28/2020  llundblade   Refine integer signedness to quiet static analysis.
 01/08/2020  llundblade   Documentation corrections & improved code formatting.
 11/08/2019  llundblade   Re check pointer math and update comments
 3/6/2019    llundblade   Add UsefulBuf_IsValue()
 09/07/17    llundbla     Fix critical bug in UsefulBuf_Find() -- a read off
                          the end of memory when the bytes to find is longer
                          than the bytes to search.
 06/27/17    llundbla     Fix UsefulBuf_Compare() bug. Only affected comparison
                          for < or > for unequal length buffers.  Added
                          UsefulBuf_Set() function.
 05/30/17    llundbla     Functions for NULL UsefulBufs and const / unconst
 11/13/16    llundbla     Initial Version.

 ============================================================================*/

#include "UsefulBuf.h"

// used to catch use of uninitialized or corrupted UsefulOutBuf
#define USEFUL_OUT_BUF_MAGIC  (0x0B0F)


/*
 Public function -- see UsefulBuf.h
 */
UsefulBufC UsefulBuf_CopyOffset(UsefulBuf Dest, size_t uOffset, const UsefulBufC Src)
{
   // Do this with subtraction so it doesn't give erroneous
   // result if uOffset + Src.len overflows
   if(uOffset > Dest.len || Src.len > Dest.len - uOffset) { // uOffset + Src.len > Dest.len
      return NULLUsefulBufC;
   }

   memcpy((uint8_t *)Dest.ptr + uOffset, Src.ptr, Src.len);

   return (UsefulBufC){Dest.ptr, Src.len + uOffset};
}


/*
   Public function -- see UsefulBuf.h
 */
int UsefulBuf_Compare(const UsefulBufC UB1, const UsefulBufC UB2)
{
   // use the comparisons rather than subtracting lengths to
   // return an int instead of a size_t
   if(UB1.len < UB2.len) {
      return -1;
   } else if (UB1.len > UB2.len) {
      return 1;
   } // else UB1.len == UB2.len

   return memcmp(UB1.ptr, UB2.ptr, UB1.len);
}


/*
 Public function -- see UsefulBuf.h
 */
size_t UsefulBuf_IsValue(const UsefulBufC UB, uint8_t uValue)
{
   if(UsefulBuf_IsNULLOrEmptyC(UB)) {
      /* Not a match */
      return 0;
   }

   const uint8_t * const pEnd = (const uint8_t *)UB.ptr + UB.len;
   for(const uint8_t *p = UB.ptr; p < pEnd; p++) {
      if(*p != uValue) {
         /* Byte didn't match */
         /* Cast from signed  to unsigned . Safe because the loop increments.*/
         return (size_t)(p - (const uint8_t *)UB.ptr);
      }
   }

   /* Success. All bytes matched */
   return SIZE_MAX;
}


/*
 Public function -- see UsefulBuf.h
 */
size_t UsefulBuf_FindBytes(UsefulBufC BytesToSearch, UsefulBufC BytesToFind)
{
   if(BytesToSearch.len < BytesToFind.len) {
      return SIZE_MAX;
   }

   for(size_t uPos = 0; uPos <= BytesToSearch.len - BytesToFind.len; uPos++) {
      if(!UsefulBuf_Compare((UsefulBufC){((const uint8_t *)BytesToSearch.ptr) + uPos, BytesToFind.len}, BytesToFind)) {
         return uPos;
      }
   }

   return SIZE_MAX;
}


/*
 Public function -- see UsefulBuf.h

 Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
void UsefulOutBuf_Init(UsefulOutBuf *pMe, UsefulBuf Storage)
{
    pMe->magic  = USEFUL_OUT_BUF_MAGIC;
    UsefulOutBuf_Reset(pMe);
    pMe->UB     = Storage;

#if 0
   // This check is off by default.

   // The following check fails on ThreadX

    // Sanity check on the pointer and size to be sure we are not
    // passed a buffer that goes off the end of the address space.
    // Given this test, we know that all unsigned lengths less than
    // me->size are valid and won't wrap in any pointer additions
    // based off of pStorage in the rest of this code.
    const uintptr_t ptrM = UINTPTR_MAX - Storage.len;
    if(Storage.ptr && (uintptr_t)Storage.ptr > ptrM) // Check #0
        me->err = 1;
#endif
}



/*
 Public function -- see UsefulBuf.h

 The core of UsefulOutBuf -- put some bytes in the buffer without writing off
                             the end of it.

 Code Reviewers: THIS FUNCTION DOES POINTER MATH

 This function inserts the source buffer, NewData, into the destination
 buffer, me->UB.ptr.

 Destination is represented as:
   me->UB.ptr -- start of the buffer
   me->UB.len -- size of the buffer UB.ptr
   me->data_len -- length of value data in UB

 Source is data:
   NewData.ptr -- start of source buffer
   NewData.len -- length of source buffer

 Insertion point:
   uInsertionPos.

 Steps:

 0. Corruption checks on UsefulOutBuf

 1. Figure out if the new data will fit or not

 2. Is insertion position in the range of valid data?

 3. If insertion point is not at the end, slide data to the right of the
    insertion point to the right

 4. Put the new data in at the insertion position.

 */
void UsefulOutBuf_InsertUsefulBuf(UsefulOutBuf *pMe, UsefulBufC NewData, size_t uInsertionPos)
{
   if(pMe->err) {
      // Already in error state.
      return;
   }

   /* 0. Sanity check the UsefulOutBuf structure */
   // A "counter measure". If magic number is not the right number it
   // probably means me was not initialized or it was corrupted. Attackers
   // can defeat this, but it is a hurdle and does good with very
   // little code.
   if(pMe->magic != USEFUL_OUT_BUF_MAGIC) {
      pMe->err = 1;
      return;  // Magic number is wrong due to uninitalization or corrption
   }

   // Make sure valid data is less than buffer size. This would only occur
   // if there was corruption of me, but it is also part of the checks to
   // be sure there is no pointer arithmatic under/overflow.
   if(pMe->data_len > pMe->UB.len) {  // Check #1
      pMe->err = 1;
      // Offset of valid data is off the end of the UsefulOutBuf due to
      // uninitialization or corruption
      return;
   }

   /* 1. Will it fit? */
   // WillItFit() is the same as: NewData.len <= (me->UB.len - me->data_len)
   // Check #1 makes sure subtraction in RoomLeft will not wrap around
   if(! UsefulOutBuf_WillItFit(pMe, NewData.len)) { // Check #2
      // The new data will not fit into the the buffer.
      pMe->err = 1;
      return;
   }

   /* 2. Check the Insertion Position */
   // This, with Check #1, also confirms that uInsertionPos <= me->data_len and
   // that uInsertionPos + pMe->UB.ptr will not wrap around the end of the
   // address space.
   if(uInsertionPos > pMe->data_len) { // Check #3
      // Off the end of the valid data in the buffer.
      pMe->err = 1;
      return;
   }

   /* 3. Slide existing data to the right */
   if (!UsefulOutBuf_IsBufferNULL(pMe)) {
      uint8_t *pSourceOfMove       = ((uint8_t *)pMe->UB.ptr) + uInsertionPos; // PtrMath #1
      size_t   uNumBytesToMove     = pMe->data_len - uInsertionPos; // PtrMath #2
      uint8_t *pDestinationOfMove  = pSourceOfMove + NewData.len; // PtrMath #3

      // To know memmove won't go off end of destination, see PtrMath #4
      // Use memove because it handles overlapping buffers
      memmove(pDestinationOfMove, pSourceOfMove, uNumBytesToMove);

      /* 4. Put the new data in */
      uint8_t *pInsertionPoint = pSourceOfMove;
      // To know memmove won't go off end of destination, see PtrMath #5
      if(NewData.ptr != NULL) {
         memmove(pInsertionPoint, NewData.ptr, NewData.len);
      }
   }

   pMe->data_len += NewData.len;
}


/*
 Rationale that describes why the above pointer math is safe

 PtrMath #1 will never wrap around over because
    Check #0 in UsefulOutBuf_Init makes sure me->UB.ptr + me->UB.len doesn't wrap
    Check #1 makes sure me->data_len is less than me->UB.len
    Check #3 makes sure uInsertionPos is less than me->data_len

 PtrMath #2 will never wrap around under because
    Check #3 makes sure uInsertionPos is less than me->data_len

 PtrMath #3 will never wrap around over because
    PtrMath #1 is checked resulting in pSourceOfMove being between me->UB.ptr and me->UB.ptr + me->data_len
    Check #2 that NewData.len will fit in the unused space left in me->UB

 PtrMath #4 will never wrap under because
    Calculation for extent or memmove is uRoomInDestination  = me->UB.len - (uInsertionPos + NewData.len)
    Check #3 makes sure uInsertionPos is less than me->data_len
    Check #3 allows Check #2 to be refactored as NewData.Len > (me->size - uInsertionPos)
    This algebraically rearranges to me->size > uInsertionPos + NewData.len

 PtrMath #5 will never wrap under because
    Calculation for extent of memove is uRoomInDestination = me->UB.len - uInsertionPos;
    Check #1 makes sure me->data_len is less than me->size
    Check #3 makes sure uInsertionPos is less than me->data_len
 */


/*
 * Public function for advancing data length. See qcbor/UsefulBuf.h
 */
void UsefulOutBuf_Advance(UsefulOutBuf *pMe, size_t uAmount)
{
   /* This function is a trimmed down version of
    * UsefulOutBuf_InsertUsefulBuf(). This could be combined with the
    * code in UsefulOutBuf_InsertUsefulBuf(), but that would make
    * UsefulOutBuf_InsertUsefulBuf() bigger and this will be very
    * rarely used.
    */

   if(pMe->err) {
      /* Already in error state. */
      return;
   }

   /* 0. Sanity check the UsefulOutBuf structure
    *
    * A "counter measure". If magic number is not the right number it
    * probably means me was not initialized or it was
    * corrupted. Attackers can defeat this, but it is a hurdle and
    * does good with very little code.
    */
   if(pMe->magic != USEFUL_OUT_BUF_MAGIC) {
      pMe->err = 1;
      return;  /* Magic number is wrong due to uninitalization or corrption */
   }

   /* Make sure valid data is less than buffer size. This would only
    * occur if there was corruption of me, but it is also part of the
    * checks to be sure there is no pointer arithmatic
    * under/overflow.
    */
   if(pMe->data_len > pMe->UB.len) {  // Check #1
      pMe->err = 1;
      /* Offset of valid data is off the end of the UsefulOutBuf due
       * to uninitialization or corruption.
       */
      return;
   }

   /* 1. Will it fit?
    *
    * WillItFit() is the same as: NewData.len <= (me->UB.len -
    * me->data_len) Check #1 makes sure subtraction in RoomLeft will
    * not wrap around
    */
   if(! UsefulOutBuf_WillItFit(pMe, uAmount)) { /* Check #2 */
      /* The new data will not fit into the the buffer. */
      pMe->err = 1;
      return;
   }

   pMe->data_len += uAmount;
}


/*
 Public function -- see UsefulBuf.h
 */
UsefulBufC UsefulOutBuf_OutUBuf(UsefulOutBuf *pMe)
{
   if(pMe->err) {
      return NULLUsefulBufC;
   }

   if(pMe->magic != USEFUL_OUT_BUF_MAGIC) {
      pMe->err = 1;
      return NULLUsefulBufC;
   }

   return (UsefulBufC){pMe->UB.ptr, pMe->data_len};
}


/*
 Public function -- see UsefulBuf.h

 Copy out the data accumulated in to the output buffer.
 */
UsefulBufC UsefulOutBuf_CopyOut(UsefulOutBuf *pMe, UsefulBuf pDest)
{
   const UsefulBufC Tmp = UsefulOutBuf_OutUBuf(pMe);
   if(UsefulBuf_IsNULLC(Tmp)) {
      return NULLUsefulBufC;
   }
   return UsefulBuf_Copy(pDest, Tmp);
}




/*
 Public function -- see UsefulBuf.h

 The core of UsefulInputBuf -- consume bytes without going off end of buffer.

 Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
const void * UsefulInputBuf_GetBytes(UsefulInputBuf *pMe, size_t uAmount)
{
   // Already in error state. Do nothing.
   if(pMe->err) {
      return NULL;
   }

   if(!UsefulInputBuf_BytesAvailable(pMe, uAmount)) {
      // Number of bytes asked for at current position are more than available
      pMe->err = 1;
      return NULL;
   }

   // This is going to succeed
   const void * const result = ((const uint8_t *)pMe->UB.ptr) + pMe->cursor;
   // Will not overflow because of check using UsefulInputBuf_BytesAvailable()
   pMe->cursor += uAmount;
   return result;
}

