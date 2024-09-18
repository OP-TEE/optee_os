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

//**Includes
// Force Global.h contents inclusion
#define GLOBAL_C

#include "Admin.h"

//**Types, Structures, and Defines
//
// List of pre-defined address of TPM state data
//
static UINT32       s_stateAddr[NV_TPM_STATE_LAST];

//
// List of pre-defined TPM state data size in byte
//
static UINT32       s_stateSize[NV_TPM_STATE_LAST];

//
// The current chip state
//
TPM_CHIP_STATE g_chipFlags;

//
// The current PPI state
//
extern FTPM_PPI_STATE s_PPIState;

//***_admin__NvInitState()
// Initialize the state NV runtime state values
void
_admin__NvInitState()
{
    UINT16 i;
    UINT32 stateAddr;

    //
    // Initialize TPM saved runtime state
    //
    s_stateSize[NV_TPM_STATE_FLAGS] = sizeof(TPM_CHIP_STATE);
    s_stateSize[NV_TPM_STATE_PPI] = sizeof(FTPM_PPI_STATE);

    //
    // Initialize TPM state data addresses. Stored after the main NV space.
    //
    stateAddr = NV_MEMORY_SIZE;
    for (i = 0; i < NV_TPM_STATE_LAST; i++) {
        s_stateAddr[i] = stateAddr;
        stateAddr += s_stateSize[i];
    }

    pAssert(stateAddr <= (NV_MEMORY_SIZE + NV_TPM_STATE_SIZE));
}

//***_admin__SaveChipFlags()
// Save the g_chipFlags runtime state
void
_admin__SaveChipFlags()
{
    _admin__NvWriteState(NV_TPM_STATE_FLAGS, &g_chipFlags);
}

//***_admin__RestoreChipFlags()
// Restore the g_chipFlags runtime state
void
_admin__RestoreChipFlags()
{
    _admin__NvReadState(NV_TPM_STATE_FLAGS, &g_chipFlags);
}

//***_admin__SavePPIState()
// Save the s_PPIState runtime state
void
_admin__SavePPIState()
{
    _admin__NvWriteState(NV_TPM_STATE_PPI, &s_PPIState);

    _plat__NvCommit();
}

//***_admin__RestorePPIState()
// Restore the s_PPIState runtime state
void
_admin__RestorePPIState()
{
    _admin__NvReadState(NV_TPM_STATE_PPI, &s_PPIState);
}

//***_admin__NvReadState()
// Read TPM state data from NV memory to RAM
void
_admin__NvReadState(
    NV_TPM_STATE     type,    // IN: type of state data
    void             *buffer  // OUT: data buffer
    )
{
    // Input type should be valid
    pAssert(type >= 0 && type < NV_TPM_STATE_LAST);

    _plat__NvMemoryRead(s_stateAddr[type], s_stateSize[type], buffer);
    return;
}

//***_admin__NvWriteState()
// Write TPM state data to NV memory
void
_admin__NvWriteState(
    NV_TPM_STATE     type,    // IN: type of state data
    void             *buffer  // IN: data buffer
    )
{
    // Input type should be valid
    pAssert(type >= 0 && type < NV_TPM_STATE_LAST);

    _plat__NvMemoryWrite(s_stateAddr[type], s_stateSize[type], buffer);
    return;
}