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

uint_fast32_t
 f128M_to_ui32( const float128_t *aPtr, uint_fast8_t roundingMode, bool exact )
{

    return f128_to_ui32( *aPtr, roundingMode, exact );

}

#else

uint_fast32_t
 f128M_to_ui32( const float128_t *aPtr, uint_fast8_t roundingMode, bool exact )
{
    const uint32_t *aWPtr;
    uint32_t uiA96;
    int32_t exp;
    uint64_t sig64;
    int32_t shiftCount;

    aWPtr = (const uint32_t *) aPtr;
    uiA96 = aWPtr[indexWordHi( 4 )];
    exp = expF128UI96( uiA96 );
    sig64 = (uint64_t) fracF128UI96( uiA96 )<<32 | aWPtr[indexWord( 4, 2 )];
    if ( exp ) sig64 |= UINT64_C( 0x0001000000000000 );
    if ( aWPtr[indexWord( 4, 1 )] | aWPtr[indexWord( 4, 0 )] ) sig64 |= 1;
    shiftCount = 0x4028 - exp;
    if ( 0 < shiftCount ) {
        sig64 = softfloat_shiftRightJam64( sig64, shiftCount );
    }
    return
        softfloat_roundPackToUI32(
            signF128UI96( uiA96 ), sig64, roundingMode, exact );

}

#endif

