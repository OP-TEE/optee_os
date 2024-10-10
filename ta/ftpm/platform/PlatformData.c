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
//** Description
// This file will instance the TPM variables that are not stack allocated. The
// descriptions for these variables are in Global.h for this project.

//** Includes
#include    "TpmProfile.h"
#include    "PlatformData.h"

// From Cancel.c
BOOL                 s_isCanceled;

// From Clock.c
unsigned int         s_adjustRate;
BOOL                 s_timerReset;
BOOL                 s_timerStopped;

#ifndef HARDWARE_CLOCK
clock64_t            s_realTimePrevious;
clock64_t            s_tpmTime;

clock64_t            s_lastSystemTime;
clock64_t            s_lastReportedTime;


#endif


// From LocalityPlat.c
unsigned char        s_locality;

// From Power.c
BOOL                 s_powerLost;

// From Entropy.c
// This values is used to determine if the entropy generator is broken. If two
// consecutive values are the same, then the entropy generator is considered to be
// broken.
uint32_t             lastEntropy;

// From PPPlat.c
BOOL  s_physicalPresence;
