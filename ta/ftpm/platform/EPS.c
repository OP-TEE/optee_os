/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 */
/* Microsoft Reference Implementation for TPM 2.0
 *
 * The copyright in this software is being made available under the BSD
 * License, included below. This software may be subject to other third
 * party and contributor rights, including patent rights, and no such
 * rights are granted under this license.
 *
 * Copyright (c) 2018-2023 Microsoft Corporation
 *
 * All rights reserved.
 *
 * BSD License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//
// Platform Endorsement Primary Seed
//

#include "TpmError.h"
#include "Admin.h"

#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define TEE_EPS_SIZE      (256/2)   // From TPM2B_RSA_TEST_PRIME in Hierarchy.c

void
_plat__GetEPS(UINT16 Size, uint8_t *EndorsementSeed)
{
    TEE_Result Result = TEE_ERROR_ITEM_NOT_FOUND;
    uint8_t EPS[TEE_EPS_SIZE] = { 0 };
    size_t EPSLen;

    IMSG("Size=%" PRIu16 "",Size);
    IMSG("EPS=%d",TEE_EPS_SIZE);

    pAssert(Size <= (TEE_EPS_SIZE));

    Result = TEE_GetPropertyAsBinaryBlock(TEE_PROPSET_CURRENT_TA,
                                          "com.microsoft.ta.endorsementSeed",
                                          EPS,
                                          &EPSLen);

    if ((EPSLen < Size) || (Result != TEE_SUCCESS)) {
        // We failed to access the property. We can't continue without it
        // and we can't just fail to manufacture, so randomize EPS and
        // continue. If necessary, fTPM TA storage can be cleared, or the
        // TA updated, and we can trigger remanufacture and try again.
        _plat__GetEntropy(EndorsementSeed, TEE_EPS_SIZE);
        return;
    }

    memcpy(EndorsementSeed, EPS, Size);

#ifdef fTPMDebug
    {
        uint32_t x;
        uint8_t *seed = EndorsementSeed;
        DMSG("TEE_GetProperty 0x%x, seedLen 0x%x\n", Result, Size);
        for (x = 0; x < Size; x = x + 8) {
            DMSG(" seed(%2.2d): %2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x\n", x,
                seed[x + 0], seed[x + 1], seed[x + 2], seed[x + 3],
                seed[x + 4], seed[x + 5], seed[x + 6], seed[x + 7]);
        }
    }
#endif

    return;
}
