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
//** Includes and Function Prototypes

#include    "PlatformData.h"
#include    "Platform_fp.h"
#include    "_TPM_Init_fp.h"

//** Functions

//***_plat__Signal_PowerOn()
// Signal platform power on
LIB_EXPORT int
_plat__Signal_PowerOn(
    void
    )
{
    // Reset the timer
    _plat__TimerReset();

   // Need to indicate that we lost power
    s_powerLost = TRUE;

    return 0;
}

//*** _plat__WasPowerLost()
// Test whether power was lost before a _TPM_Init.
//
// This function will clear the "hardware" indication of power loss before return.
// This means that there can only be one spot in the TPM code where this value
// gets read. This method is used here as it is the most difficult to manage in the
// TPM code and, if the hardware actually works this way, it is hard to make it
// look like anything else. So, the burden is placed on the TPM code rather than the
// platform code
// return type: int
//  TRUE(1)     power was lost
//  FALSE(0)    power was not lost
LIB_EXPORT int
_plat__WasPowerLost(
    void
    )
{
    BOOL        retVal = s_powerLost;
    s_powerLost = FALSE;
    return retVal;
}

//*** _plat_Signal_Reset()
// This a TPM reset without a power loss.
LIB_EXPORT int
_plat__Signal_Reset(
    void
    )
{
    // Initialize locality
    s_locality = 0;

    // Command cancel
    s_isCanceled = FALSE;

    _TPM_Init();

    // if we are doing reset but did not have a power failure, then we should
    // not need to reload NV ...

    return 0;
}

//***_plat__Signal_PowerOff()
// Signal platform power off
LIB_EXPORT void
_plat__Signal_PowerOff(
    void
    )
{
    // Prepare NV memory for power off
    _plat__NVDisable();

    return;
}