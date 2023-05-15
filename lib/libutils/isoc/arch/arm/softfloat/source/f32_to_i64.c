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

int_fast64_t f32_to_i64( float32_t a, uint_fast8_t roundingMode, bool exact )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    bool sign;
    int_fast16_t exp;
    uint_fast32_t sig;
    int_fast16_t shiftCount;
#ifdef SOFTFLOAT_FAST_INT64
    uint_fast64_t sig64, extra;
    struct uint64_extra sig64Extra;
#else
    uint32_t extSig[3];
#endif

    uA.f = a;
    uiA = uA.ui;
    sign = signF32UI( uiA );
    exp  = expF32UI( uiA );
    sig  = fracF32UI( uiA );
    shiftCount = 0xBE - exp;
    if ( shiftCount < 0 ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        if ( ! sign || ((exp == 0xFF) && sig) ) {
            return INT64_C( 0x7FFFFFFFFFFFFFFF );
        }
        return -INT64_C( 0x7FFFFFFFFFFFFFFF ) - 1;
    }
    if ( exp ) sig |= 0x00800000;
#ifdef SOFTFLOAT_FAST_INT64
    sig64 = (uint_fast64_t) sig<<40;
    extra = 0;
    if ( shiftCount ) {
        sig64Extra = softfloat_shiftRightJam64Extra( sig64, 0, shiftCount );
        sig64 = sig64Extra.v;
        extra = sig64Extra.extra;
    }
    return softfloat_roundPackToI64( sign, sig64, extra, roundingMode, exact );
#else
    extSig[indexWord( 3, 2 )] = sig<<8;
    extSig[indexWord( 3, 1 )] = 0;
    extSig[indexWord( 3, 0 )] = 0;
    if ( shiftCount ) softfloat_shiftRightJam96M( extSig, shiftCount, extSig );
    return softfloat_roundPackMToI64( sign, extSig, roundingMode, exact );
#endif

}

