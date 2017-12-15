// SPDX-License-Identifier: BSD-3-Clause

/*============================================================================

This C source file is part of the SoftFloat IEEE Floating-Point Arithmetic
Package, Release 3a, by John R. Hauser.

Copyright 2011, 2012, 2013, 2014, 2015 The Regents of the University of
California.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions, and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions, and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the University nor the names of its contributors may
    be used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS", AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE
DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=============================================================================*/

#include <stdint.h>
#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shiftRightJam256M

static
 void
  softfloat_shortShiftRightJamM(
      uint_fast8_t size_words,
      const uint64_t *aPtr,
      uint_fast8_t count,
      uint64_t *zPtr
  )
{
    uint_fast8_t negCount;
    unsigned int index, lastIndex;
    uint64_t partWordZ, wordA;

    negCount = -count;
    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    wordA = aPtr[index];
    partWordZ = wordA>>count;
    if ( partWordZ<<count != wordA ) partWordZ |= 1;
    while ( index != lastIndex ) {
        wordA = aPtr[index + wordIncr];
        zPtr[index] = wordA<<(negCount & 63) | partWordZ;
        index += wordIncr;
        partWordZ = wordA>>count;
    }
    zPtr[index] = partWordZ;

}

void
 softfloat_shiftRightJam256M(
     const uint64_t *aPtr, uint_fast32_t count, uint64_t *zPtr )
{
    uint64_t wordJam;
    uint_fast32_t wordCount;
    uint64_t *ptr;
    uint_fast8_t i, innerCount;

    wordJam = 0;
    wordCount = count>>6;
    if ( wordCount ) {
        if ( 4 < wordCount ) wordCount = 4;
        ptr = (uint64_t *) (aPtr + indexMultiwordLo( 4, wordCount ));
        i = wordCount;
        do {
            wordJam = *ptr++;
            if ( wordJam ) break;
            --i;
        } while ( i );
        ptr = zPtr;
    }
    if ( wordCount < 4 ) {
        aPtr += indexMultiwordHiBut( 4, wordCount );
        innerCount = count & 63;
        if ( innerCount ) {
            softfloat_shortShiftRightJamM(
                4 - wordCount,
                aPtr,
                innerCount,
                zPtr + indexMultiwordLoBut( 4, wordCount )
            );
            if ( ! wordCount ) goto wordJam;
        } else {
            aPtr += indexWordLo( 4 - wordCount );
            ptr = zPtr + indexWordLo( 4 );
            for ( i = 4 - wordCount; i; --i ) {
                *ptr = *aPtr;
                aPtr += wordIncr;
                ptr += wordIncr;
            }
        }
        ptr = zPtr + indexMultiwordHi( 4, wordCount );
    }
    do {
        *ptr++ = 0;
        --wordCount;
    } while ( wordCount );
 wordJam:
    if ( wordJam ) zPtr[indexWordLo( 4 )] |= 1;

}

#endif

