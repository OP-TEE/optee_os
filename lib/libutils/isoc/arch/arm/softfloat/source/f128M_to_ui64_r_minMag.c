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

uint_fast64_t f128M_to_ui64_r_minMag( const float128_t *aPtr, bool exact )
{

    return f128_to_ui64_r_minMag( *aPtr, exact );

}

#else

uint_fast64_t f128M_to_ui64_r_minMag( const float128_t *aPtr, bool exact )
{
    const uint32_t *aWPtr;
    uint32_t uiA96;
    int32_t exp, shiftCount;
    uint32_t sig96, sig[4];
    uint64_t z;

    aWPtr = (const uint32_t *) aPtr;
    uiA96 = aWPtr[indexWordHi( 4 )];
    exp = expF128UI96( uiA96 );
    shiftCount = 0x403E - exp;
    if ( shiftCount < 0 ) goto invalid;
    if ( exact ) {
        sig96 = fracF128UI96( uiA96 );
        if ( exp ) sig96 |= 0x00010000;
        sig[indexWord( 4, 3 )] = sig96;
        sig[indexWord( 4, 2 )] = aWPtr[indexWord( 4, 2 )];
        sig[indexWord( 4, 1 )] = aWPtr[indexWord( 4, 1 )];
        sig[indexWord( 4, 0 )] = aWPtr[indexWord( 4, 0 )];
        softfloat_shiftRightJam128M( sig, shiftCount + 17, sig );
        z = (uint64_t) sig[indexWord( 4, 2 )]<<32 | sig[indexWord( 4, 1 )];
        if ( signF128UI96( uiA96 ) && z ) goto invalid;
        if ( sig[indexWordLo( 4 )] ) {
            softfloat_exceptionFlags |= softfloat_flag_inexact;
        }
    } else {
        if ( 64 <= shiftCount ) return 0;
        if ( signF128UI96( uiA96 ) ) goto invalid;
        z =   UINT64_C( 0x8000000000000000 )
            | (uint64_t) fracF128UI96( uiA96 )<<47
            | (uint64_t) aWPtr[indexWord( 4, 2 )]<<15
            | aWPtr[indexWord( 4, 1 )]>>17;
        z >>= shiftCount;
    }
    return z;
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    return UINT64_C( 0xFFFFFFFFFFFFFFFF );

}

#endif

