// SPDX-License-Identifier: BSD-3-Clause

/*============================================================================

This C source file is part of the SoftFloat IEEE Floating-Point Arithmetic
Package, Release 3a, by John R. Hauser.

Copyright 2011, 2012, 2013, 2014 The Regents of the University of California.
All rights reserved.

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

#include <stdbool.h>
#include <stdint.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

#ifdef SOFTFLOAT_FAST_INT64

int_fast64_t
 f128M_to_i64( const float128_t *aPtr, uint_fast8_t roundingMode, bool exact )
{

    return f128_to_i64( *aPtr, roundingMode, exact );

}

#else

int_fast64_t
 f128M_to_i64( const float128_t *aPtr, uint_fast8_t roundingMode, bool exact )
{
    const uint32_t *aWPtr;
    uint32_t uiA96;
    int32_t exp;
    bool sign;
    uint32_t sig96;
    int32_t shiftCount;
    uint32_t sig[4];

    aWPtr = (const uint32_t *) aPtr;
    uiA96 = aWPtr[indexWordHi( 4 )];
    exp = expF128UI96( uiA96 );
    sign  = signF128UI96( uiA96 );
    sig96 = fracF128UI96( uiA96 );
    shiftCount = 0x404F - exp;
    if ( shiftCount < 17 ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        return
            ! sign
                || ((exp == 0x7FFF)
                        && (sig96
                                || (  aWPtr[indexWord( 4, 2 )]
                                    | aWPtr[indexWord( 4, 1 )]
                                    | aWPtr[indexWord( 4, 0 )]
                                   )))
                ? INT64_C( 0x7FFFFFFFFFFFFFFF )
                : -INT64_C( 0x7FFFFFFFFFFFFFFF ) - 1;
    }
    if ( exp ) sig96 |= 0x00010000;
    sig[indexWord( 4, 3 )] = sig96;
    sig[indexWord( 4, 2 )] = aWPtr[indexWord( 4, 2 )];
    sig[indexWord( 4, 1 )] = aWPtr[indexWord( 4, 1 )];
    sig[indexWord( 4, 0 )] = aWPtr[indexWord( 4, 0 )];
    softfloat_shiftRightJam128M( sig, shiftCount, sig );
    return
        softfloat_roundPackMToI64(
            sign, sig + indexMultiwordLo( 4, 3 ), roundingMode, exact );

}

#endif

