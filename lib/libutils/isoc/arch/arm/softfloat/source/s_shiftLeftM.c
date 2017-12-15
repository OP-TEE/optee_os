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

#ifndef softfloat_shiftLeftM

#define softfloat_shiftLeftM softfloat_shiftLeftM
#include "primitives.h"

void
 softfloat_shiftLeftM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t count,
     uint32_t *zPtr
 )
{
    uint32_t wordCount;
    uint_fast8_t innerCount;
    uint32_t *destPtr;
    uint_fast8_t i;

    wordCount = count>>5;
    if ( wordCount < size_words ) {
        aPtr += indexMultiwordLoBut( size_words, wordCount );
        innerCount = count & 31;
        if ( innerCount ) {
            softfloat_shortShiftLeftM(
                size_words - wordCount,
                aPtr,
                innerCount,
                zPtr + indexMultiwordHiBut( size_words, wordCount )
            );
            if ( ! wordCount ) return;
        } else {
            aPtr += indexWordHi( size_words - wordCount );
            destPtr = zPtr + indexWordHi( size_words );
            for ( i = size_words - wordCount; i; --i ) {
                *destPtr = *aPtr;
                aPtr -= wordIncr;
                destPtr -= wordIncr;
            }
        }
        zPtr += indexMultiwordLo( size_words, wordCount );
    } else {
        wordCount = size_words;
    }
    do {
        *zPtr++ = 0;
        --wordCount;
    } while ( wordCount );

}

#endif

