/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//** Includes and Local Values

#define _CRT_RAND_S
#include <stdlib.h>
#include <memory.h>
#include "PlatformData.h"
#include "Platform_fp.h"
#include <time.h>

#include <tee_internal_api.h>

#ifdef _MSC_VER
#include <process.h>
#else
#include <unistd.h>
#endif

// This is the last 32-bits of hardware entropy produced. We have to check to
// see that two consecutive 32-bit values are not the same because
// (according to FIPS 140-2, annex C
//
// 1. If each call to a RNG produces blocks of n bits (where n > 15), the first
// n-bit block generated after power-up, initialization, or reset shall not be
// used, but shall be saved for comparison with the next n-bit block to be
// generated. Each subsequent generation of an n-bit block shall be compared with
// the previously generated block. The test shall fail if any two compared n-bit
// blocks are equal.
extern uint32_t        lastEntropy;

//** Functions

//*** rand32()
// Local function to get a 32-bit random number
static uint32_t
rand32(
    void
)
{

    uint32_t    rndNum;
    TEE_GenerateRandom((void *)(&rndNum), sizeof(uint32_t));
    return rndNum;
}


//** _plat__GetEntropy()
// This function is used to get available hardware entropy. In a hardware
// implementation of this function, there would be no call to the system
// to get entropy.
// return type: int32_t
//  < 0        hardware failure of the entropy generator, this is sticky
// >= 0        the returned amount of entropy (bytes)
//
LIB_EXPORT int32_t
_plat__GetEntropy(
    unsigned char       *entropy,           // output buffer
    uint32_t             amount             // amount requested
)
{
    uint32_t            rndNum;
    int32_t             ret;

    if(amount == 0)
    {
        lastEntropy = rand32();
        ret = 0;
    }
    else
    {
        rndNum = rand32();
        if(rndNum == lastEntropy)
        {
            ret = -1;
        }
        else
        {
            lastEntropy = rndNum;
            // Each process will have its random number generator initialized according
            // to the process id and the initialization time. This is not a lot of
            // entropy so, to add a bit more, XOR the current time value into the
            // returned entropy value.
            // NOTE: the reason for including the time here rather than have it in
            // in the value assigned to lastEntropy is that rand() could be broken and
            // using the time would in the lastEntropy value would hide this.
            rndNum ^= (uint32_t)_plat__RealTime();

            // Only provide entropy 32 bits at a time to test the ability
            // of the caller to deal with partial results.
            ret = MIN(amount, sizeof(rndNum));
            memcpy(entropy, &rndNum, ret);
        }
    }
    return ret;
}