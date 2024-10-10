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
//** Introduction
// In some implementations of the TPM, the hardware can provide a secret
// value to the TPM. This secret value is statistically unique to the
// instance of the TPM. Typical uses of this value are to provide
// personalization to the random number generation and as a shared secret
// between the TPM and the manufacturer.

//** Includes
#include "PlatformData.h"
#include "Platform_fp.h"

#include <tee_internal_api.h>
#include <assert.h>

//static TEE_UUID deviceUniqueValue = { 0 };
static char *deviceUniqueValue[sizeof(TEE_UUID)+1];
static bool initializedUniqueValue = false;

//** _plat__GetUnique()
// This function is used to access the platform-specific unique value.
// This function places the unique value in the provided buffer ('b')
// and returns the number of bytes transferred. The function will not
// copy more data than 'bSize'.
// NOTE: If a platform unique value has unequal distribution of uniqueness
// and 'bSize' is smaller than the size of the unique value, the 'bSize'
// portion with the most uniqueness should be returned.
LIB_EXPORT uint32_t
_plat__GetUnique(
    uint32_t             which,         // authorities (0) or details
    uint32_t             bSize,         // size of the buffer
    unsigned char       *b              // output buffer
    )
{
    const char          *from = (char *)&deviceUniqueValue;
    uint32_t            uSize = sizeof(TEE_UUID) + 1;
    uint32_t            retVal = 0;
    TEE_Result          teeResult;

    // Check if we've initialized our unique platform value.
    if (!initializedUniqueValue) {
        teeResult = TEE_GetPropertyAsUUID(TEE_PROPSET_TEE_IMPLEMENTATION,
                                       "gpd.tee.deviceID",
                                       (TEE_UUID*)&deviceUniqueValue);
        assert(teeResult == TEE_SUCCESS);
    }
    deviceUniqueValue[uSize-1] = '\0';

    if(which == 0) // the authorities value
    {
        for(retVal = 0;
        *from != 0 && retVal < bSize;
            retVal++)
        {
            *b++ = *from++;
        }
    }
    else
    {
        b = &b[((bSize < uSize) ? bSize : uSize) - 1];
        for(retVal = 0;
        *from != 0 && retVal < bSize;
            retVal++)
        {
            *b-- = *from++;
        }
    }
    return retVal;
}