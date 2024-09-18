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

//**Introduction
// This file contains the emulated Physical Presence Interface.

#include "assert.h"
#include "Admin.h"
#include "string.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define TPM_CC_EmulatePPI     0x200001FF

//
// Hand marshaling, unmarshaling, and maximally sized structures for EmulatePPI
//
#pragma pack (push, 1)
typedef struct {
    TPM_ST tag;
    UINT32 paramSize;
    TPM_CC commandCode;
} TPM2_COMMAND_HEADER;

typedef struct {
    TPM_ST tag;
    UINT32 paramSize;
    TPM_RC responseCode;
} TPM2_RESPONSE_HEADER;

typedef struct{
    UINT32 FunctionIndex;
    UINT32 Op;
} EmulatePPI_In;

typedef struct{
    UINT32 Result1;
    UINT32 Result2;
    UINT32 Result3;
} EmulatePPI_Out;

typedef struct{
    TPM2_COMMAND_HEADER header;
    EmulatePPI_In inputParameters;
} TPM2_EmulatePPI_cmd_t;

typedef struct{
    TPM2_RESPONSE_HEADER header;
    EmulatePPI_Out outputParameters;
} TPM2_EmulatePPI_res_t;
#pragma pack (pop)

FTPM_PPI_STATE s_PPIState;

extern int _plat__NvCommit(void);

static void
ExecutePPICommand(
    _In_  UINT32 FunctionIndex,
    _In_  UINT32 Op,
    _Out_ UINT32 *Result1,
    _Out_ UINT32 *Result2,
    _Out_ UINT32 *Result3
    )
{
    UINT32 retVal1 = 0;
    UINT32 retVal2 = 0;
    UINT32 retVal3 = 0;

    _admin__RestorePPIState();

    memset(Result1, 0, sizeof(UINT32));
    memset(Result2, 0, sizeof(UINT32));
    memset(Result3, 0, sizeof(UINT32));

    switch (FunctionIndex) {
    case FTPM_PPI_CMD_QUERY:
        retVal1 = 0x1AB;             // Per PPI 1.2 specification
        break;

    case FTPM_PPI_CMD_VERSION:
        retVal1 = FTPM_PPI_VERSION;  // String "1.2"
        break;

    case FTPM_PPI_CMD_SUBMIT_OP_REQ:
    case FTPM_PPI_CMD_GET_PLATFORM_ACTION:
        retVal1 = 2;                 // Reboot/General Failure
        break;

    case FTPM_PPI_CMD_GET_PENDING_OP:
        retVal1 = 0;                 // Success
        retVal2 = s_PPIState.PendingPseudoOp;
        break;

    case FTPM_PPI_CMD_RETURN_OP_RESP:
        retVal1 = 0;                 // Success
        retVal2 = s_PPIState.PseudoOpFromLastBoot;
        retVal3 = s_PPIState.ReturnResponse;
        break;

    case FTPM_PPI_CMD_SUBMIT_USER_LANG:
        retVal1 = 3;                 // Not Implemented
        break;

    case FTPM_PPI_CMD_SUBMIT_OP_REQ2:
        switch (Op) {
        case FTPM_PPI_OP_NOP:
        case FTPM_PPI_OP_ENABLE:
        case FTPM_PPI_OP_DISABLE:
        case FTPM_PPI_OP_ACTIVATE:
        case FTPM_PPI_OP_DEACTIVATE:
        case FTPM_PPI_OP_CLEAR:                  // Causes Clear
        case FTPM_PPI_OP_E_A:
        case FTPM_PPI_OP_D_D:
        case FTPM_PPI_OP_OWNERINSTALL_TRUE:
        case FTPM_PPI_OP_OWNERINSTALL_FALSE:
        case FTPM_PPI_OP_E_A_OI_TRUE:
        case FTPM_PPI_OP_OI_FALSE_D_D:
        case FTPM_PPI_OP_FIELD_UPGRADE:
        case FTPM_PPI_OP_OPERATOR_AUTH:
        case FTPM_PPI_OP_C_E_A:                  // Causes Clear
        case FTPM_PPI_OP_SET_NO_PROV_FALSE:
        case FTPM_PPI_OP_SET_NO_PROV_TRUE:
        case FTPM_PPI_OP_SET_NO_MAINT_FALSE:
        case FTPM_PPI_OP_SET_NO_MAINT_TRUE:
        case FTPM_PPI_OP_E_A_C:                  // Causes Clear
        case FTPM_PPI_OP_E_A_C_E_A:              // Causes Clear
            retVal1 = 0;                        // Success
            s_PPIState.PendingPseudoOp = Op;
            _admin__SavePPIState();
            break;

        case FTPM_PPI_OP_SET_NO_CLEAR_FALSE:
        case FTPM_PPI_OP_SET_NO_CLEAR_TRUE:
        default:
            retVal1 = 1;                       // Not Implemented
            break;
        }
        break;

    case FTPM_PPI_CMD_GET_USER_CONF:
        switch (Op) {
        case FTPM_PPI_OP_NOP:
        case FTPM_PPI_OP_ENABLE:
        case FTPM_PPI_OP_DISABLE:
        case FTPM_PPI_OP_ACTIVATE:
        case FTPM_PPI_OP_DEACTIVATE:
        case FTPM_PPI_OP_E_A:
        case FTPM_PPI_OP_D_D:
        case FTPM_PPI_OP_OWNERINSTALL_TRUE:
        case FTPM_PPI_OP_OWNERINSTALL_FALSE:
        case FTPM_PPI_OP_E_A_OI_TRUE:
        case FTPM_PPI_OP_OI_FALSE_D_D:
            retVal1 = 4;    // Allowed and PP user NOT required
            break;

        case FTPM_PPI_OP_CLEAR:
        case FTPM_PPI_OP_C_E_A:
        case FTPM_PPI_OP_E_A_C:
        case FTPM_PPI_OP_E_A_C_E_A:
            retVal1 = 3;    // Allowed and PP user required
            break;

        default:
            retVal1 = 0;    // Not Implemented
            break;
        }
        break;

    default:
        break;
    }

    memcpy(Result1, &retVal1, sizeof(UINT32));
    memcpy(Result2, &retVal2, sizeof(UINT32));
    memcpy(Result3, &retVal3, sizeof(UINT32));
}

static TPM2_EmulatePPI_res_t PPIResponse;

#pragma warning(push)
#pragma warning(disable:28196)
//
// The fTPM TA (OpTEE) may receive, from the TrEE driver, a PPI request
// thru it's ACPI inteface rather than via the TPM_Emulate_PPI command
// we're used to. This function creates a well formes TPM_Emulate_PPI
// command and forwards the request on to _admin__PPICommand to handle.
//
// Return:
//          0 - Omproperly formatted PPI command.
//  Otherwise - Return from _admin__PPICommand
//
int
_admin__PPIRequest(
                                        UINT32  CommandSize,
    __in_ecount(CommandSize)            UINT8   *CommandBuffer,
                                        UINT32  *ResponseSize,
    __deref_out_ecount(*ResponseSize)   UINT8   **ResponseBuffer
    )
{
    TPM2_EmulatePPI_cmd_t cmd;
    TPM2_EmulatePPI_res_t rsp;
    TPM2_EmulatePPI_res_t *rspPtr = &rsp;
    UINT32 rspLen = sizeof(TPM2_EmulatePPI_res_t);
    UINT8 *CmdBuffer;

    // Drop request if CommandSize is invalid
    if (CommandSize < sizeof(UINT32)) {
        return 0;
    }

    CmdBuffer = CommandBuffer;

    cmd.header.tag = __builtin_bswap16(TPM_ST_NO_SESSIONS);
    cmd.header.paramSize = __builtin_bswap32(sizeof(TPM2_EmulatePPI_cmd_t));
    cmd.header.commandCode = __builtin_bswap32(TPM_CC_EmulatePPI);

    cmd.inputParameters.FunctionIndex = BYTE_ARRAY_TO_UINT32(CmdBuffer);
    CmdBuffer += sizeof(UINT32);
    CommandSize -= sizeof(UINT32);

    // Parameter checking is done in _admin__PPICommand but we still need
    // to sanity check the size field so as not to overrun CommandBuffer.
    if (CommandSize > 0) {

        if (CommandSize < sizeof(UINT32))
            return 0;

        cmd.inputParameters.Op = BYTE_ARRAY_TO_UINT32(CmdBuffer);
    }

    if (!_admin__PPICommand(sizeof(TPM2_EmulatePPI_cmd_t),
                            (UINT8 *)&cmd,
                            &rspLen,
                            (UINT8**)&rspPtr)) {
        return 0;
    }

    memcpy(*ResponseBuffer, &(rsp.outputParameters.Result1), (rspLen - sizeof(TPM2_RESPONSE_HEADER)));
    *ResponseSize = (rspLen - sizeof(TPM2_RESPONSE_HEADER));
    return 1;
}

//
// Return:
//  1 - Command has been consumed
//  0 - Not a properly formated PPI command, caller should pass through to TPM
//
int
_admin__PPICommand(
                                        UINT32  CommandSize,
    __in_ecount(CommandSize)            UINT8   *CommandBuffer,
                                        UINT32  *ResponseSize,
    __deref_out_ecount(*ResponseSize)   UINT8   **ResponseBuffer
)
{
    TPM2_EmulatePPI_cmd_t cmd;
    UINT8 *CmdBuffer;
    UINT32 FunctionIndex;
    UINT32 Op;
    UINT32 NumberResults = 0;
    UINT16 Tag;

    memset(&PPIResponse, 0, sizeof(PPIResponse));
    memset(&cmd, 0, sizeof(cmd));

    CmdBuffer = CommandBuffer;

    if (CommandSize < sizeof(TPM2_COMMAND_HEADER)) {
        PPIResponse.header.responseCode = TPM_RC_COMMAND_SIZE;
        goto Exit;
    }

    cmd.header.tag = BYTE_ARRAY_TO_UINT16(CmdBuffer);
    CmdBuffer += sizeof(UINT16);
    CommandSize -= sizeof(UINT16);

    cmd.header.paramSize = BYTE_ARRAY_TO_UINT32(CmdBuffer);
    CmdBuffer += sizeof(UINT32);
    CommandSize -= sizeof(UINT32);

    cmd.header.commandCode = BYTE_ARRAY_TO_UINT32(CmdBuffer);
    CmdBuffer += sizeof(UINT32);
    CommandSize -= sizeof(UINT32);

    //
    // First check that this must be the command we want to execute
    //
    if (cmd.header.commandCode != TPM_CC_EmulatePPI) {
        return 0;
    }

    //
    // Must not be a session
    //
    if (cmd.header.tag != TPM_ST_NO_SESSIONS) {
        PPIResponse.header.responseCode = TPM_RC_BAD_TAG;
        goto Exit;
    }

    //
    // Must have enough command space left
    //
    if (cmd.header.paramSize < CommandSize) {
        PPIResponse.header.responseCode = TPM_RC_COMMAND_SIZE;
        goto Exit;
    }

    if (CommandSize < sizeof(UINT32)) {
        PPIResponse.header.responseCode = TPM_RC_COMMAND_SIZE;
        goto Exit;
    }

    FunctionIndex = BYTE_ARRAY_TO_UINT32(CmdBuffer);
    CmdBuffer += sizeof(UINT32);
    CommandSize -= sizeof(UINT32);

    switch (FunctionIndex) {
    case FTPM_PPI_CMD_QUERY:
    case FTPM_PPI_CMD_VERSION:
    case FTPM_PPI_CMD_SUBMIT_OP_REQ:
    case FTPM_PPI_CMD_GET_PLATFORM_ACTION:
    case FTPM_PPI_CMD_SUBMIT_USER_LANG:
        NumberResults = 1;
        Op = 0;
        break;

    case FTPM_PPI_CMD_GET_PENDING_OP:
        NumberResults = 2;
        Op = 0;
        break;

    case FTPM_PPI_CMD_RETURN_OP_RESP:
        NumberResults = 3;
        Op = 0;
        break;

    case FTPM_PPI_CMD_SUBMIT_OP_REQ2:
    case FTPM_PPI_CMD_GET_USER_CONF:
        NumberResults = 1;

        if (CommandSize < sizeof(UINT32)) {
            PPIResponse.header.responseCode = TPM_RC_COMMAND_SIZE;
            goto Exit;
        }

        Op = BYTE_ARRAY_TO_UINT32(CmdBuffer);
        CmdBuffer += sizeof(UINT32);
        CommandSize -= sizeof(UINT32);
        break;

    default:
        NumberResults = 0;
        PPIResponse.header.responseCode = TPM_RC_FAILURE;
        goto Exit;
    }


    ExecutePPICommand(FunctionIndex,
                      Op,
#pragma warning (push)
#pragma warning (disable:4366)  // The result of unary '&' may be unaligned
                      &PPIResponse.outputParameters.Result1,
                      &PPIResponse.outputParameters.Result2,
                      &PPIResponse.outputParameters.Result3);
#pragma warning (pop)

    PPIResponse.header.responseCode = TPM_RC_SUCCESS;

Exit:
    if (PPIResponse.header.responseCode != TPM_RC_SUCCESS) {
        NumberResults = 0;
    }

    *ResponseSize = sizeof(TPM2_RESPONSE_HEADER) + (NumberResults * sizeof(UINT32));

    //
    // Fill in tag, and size
    //
    Tag = TPM_ST_NO_SESSIONS;
    PPIResponse.header.tag = BYTE_ARRAY_TO_UINT16((BYTE *)&Tag);
    PPIResponse.header.paramSize = BYTE_ARRAY_TO_UINT32((BYTE *)ResponseSize);
    PPIResponse.header.responseCode = BYTE_ARRAY_TO_UINT32((BYTE *)&PPIResponse.header.responseCode);

    //
    // Results are in host byte order
    //
    memcpy(*ResponseBuffer, &PPIResponse, (sizeof(PPIResponse) < *ResponseSize) ? sizeof(PPIResponse) : *ResponseSize);

    return 1;
}
#pragma warning(pop)

