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

uint_fast64_t
 extF80M_to_ui64(
     const extFloat80_t *aPtr, uint_fast8_t roundingMode, bool exact )
{

    return extF80_to_ui64( *aPtr, roundingMode, exact );

}

#else

uint_fast64_t
 extF80M_to_ui64(
     const extFloat80_t *aPtr, uint_fast8_t roundingMode, bool exact )
{
    const struct extFloat80M *aSPtr;
    uint_fast16_t uiA64;
    int32_t exp, shiftCount;
    bool sign;
    uint64_t sig;
    uint32_t extSig[3];

    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    aSPtr = (const struct extFloat80M *) aPtr;
    uiA64 = aSPtr->signExp;
    exp = expExtF80UI64( uiA64 );
    /*------------------------------------------------------------------------
    *------------------------------------------------------------------------*/
    shiftCount = 0x403E - exp;
    if ( shiftCount < 0 ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        return UINT64_C( 0xFFFFFFFFFFFFFFFF );
    }
    sign = signExtF80UI64( uiA64 );
    sig = aSPtr->signif;
    extSig[indexWord( 3, 2 )] = sig>>32;
    extSig[indexWord( 3, 1 )] = sig;
    extSig[indexWord( 3, 0 )] = 0;
    if ( shiftCount ) softfloat_shiftRightJam96M( extSig, shiftCount, extSig );
    return softfloat_roundPackMToUI64( sign, extSig, roundingMode, exact );

}

#endif

