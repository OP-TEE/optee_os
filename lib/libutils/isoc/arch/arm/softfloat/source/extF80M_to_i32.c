
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

int_fast32_t
 extF80M_to_i32(
     const extFloat80_t *aPtr, uint_fast8_t roundingMode, bool exact )
{

    return extF80_to_i32( *aPtr, roundingMode, exact );

}

#else

int_fast32_t
 extF80M_to_i32(
     const extFloat80_t *aPtr, uint_fast8_t roundingMode, bool exact )
{
    const struct extFloat80M *aSPtr;
    uint_fast16_t uiA64;
    bool sign;
    int32_t exp;
    uint64_t sig;
    int32_t shiftCount;

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    aSPtr = (const struct extFloat80M *) aPtr;
    uiA64 = aSPtr->signExp;
    sign = signExtF80UI64( uiA64 );
    exp  = expExtF80UI64( uiA64 );
    sig = aSPtr->signif;
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    if ( (exp == 0x7FFF) && (sig & UINT64_C( 0x7FFFFFFFFFFFFFFF )) ) sign = 0;
    shiftCount = 0x4037 - exp;
    if ( shiftCount <= 0 ) {
        if ( sig>>32 ) goto invalid;
        if ( -32 < shiftCount ) {
            sig <<= -shiftCount;
        } else {
            if ( (uint32_t) sig ) goto invalid;
        }
    } else {
        sig = softfloat_shiftRightJam64( sig, shiftCount );
    }
    return softfloat_roundPackToI32( sign, sig, roundingMode, exact );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    return sign ? -0x7FFFFFFF - 1 : 0x7FFFFFFF;

}

#endif

