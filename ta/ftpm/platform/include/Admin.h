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
/*
    This file contains the admin interfaces.
*/

#ifndef _ADMIN_H
#define _ADMIN_H

//**Includes
#include <stdint.h>
#include <trace.h>
#include "swap.h"
#include "TpmProfile.h"
#include "TpmSal.h"
#include "TpmError.h"

// Parameter reference and types from ref impl headers
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(a) do { (void)(a); } while (0)
#endif

#define FAIL(errorCode) (TpmFail(__FUNCTION__, __LINE__, errorCode))

#if defined(EMPTY_ASSERT)
#define pAssert(a)  ((void)0)
#else
#define pAssert(a) \
    do { \
        if (!(a)) { \
            EMSG("## ASSERT:" #a "##\n"); \
            FAIL(FATAL_ERROR_PARAMETER); \
        } \
    } while (0)
#endif

#if defined(__GNUC__)
typedef unsigned char   UCHAR;
typedef unsigned char * PUCHAR;
typedef void            VOID;
typedef void *          PVOID;
#endif

// Admin space tacked on to NV, padded out to NV_BLOCK_SIZE alignment.
#define NV_TPM_STATE_SIZE   0x200

// Actual size of Admin space used. (See note in NVMem.c)
#define TPM_STATE_SIZE      0x10

// Select TPM types/defines for AdminPPI.c
typedef UINT16  TPM_ST;
#define TPM_ST_NO_SESSIONS  (TPM_ST)(0x8001)

typedef UINT32  TPM_RC;
#define TPM_RC_SUCCESS      (TPM_RC)(0x000)
#define RC_VER1             (TPM_RC)(0x100)
#define TPM_RC_BAD_TAG      (TPM_RC)(0x01E)
#define TPM_RC_FAILURE      (TPM_RC)(RC_VER1+0x001)
#define TPM_RC_COMMAND_SIZE (TPM_RC)(RC_VER1+0x042)

// Chip flags
typedef union {
    UINT32   flags;
    struct {
        UINT32 Remanufacture   : 1;  // Ignored on OpTEE platforms
        UINT32 TpmStatePresent : 1;  // Set when sate present (startup STATE)
        UINT32 Reserved        : 30;
    }        fields;
} TPM_CHIP_STATE;

//
// The current NV Chip state
//
extern TPM_CHIP_STATE g_chipFlags;

//
// Simulated Physical Presence Interface (PPI)
//
#define FTPM_PPI_CMD_QUERY               0
#define FTPM_PPI_CMD_VERSION             1
#define FTPM_PPI_CMD_SUBMIT_OP_REQ       2
#define FTPM_PPI_CMD_GET_PENDING_OP      3
#define FTPM_PPI_CMD_GET_PLATFORM_ACTION 4
#define FTPM_PPI_CMD_RETURN_OP_RESP      5
#define FTPM_PPI_CMD_SUBMIT_USER_LANG    6
#define FTPM_PPI_CMD_SUBMIT_OP_REQ2      7
#define FTPM_PPI_CMD_GET_USER_CONF       8

#define FTPM_PPI_OP_NOP                  0
#define FTPM_PPI_OP_ENABLE               1
#define FTPM_PPI_OP_DISABLE              2
#define FTPM_PPI_OP_ACTIVATE             3
#define FTPM_PPI_OP_DEACTIVATE           4
#define FTPM_PPI_OP_CLEAR                5
#define FTPM_PPI_OP_E_A                  6
#define FTPM_PPI_OP_D_D                  7
#define FTPM_PPI_OP_OWNERINSTALL_TRUE    8
#define FTPM_PPI_OP_OWNERINSTALL_FALSE   9
#define FTPM_PPI_OP_E_A_OI_TRUE         10
#define FTPM_PPI_OP_OI_FALSE_D_D        11
#define FTPM_PPI_OP_FIELD_UPGRADE       12
#define FTPM_PPI_OP_OPERATOR_AUTH       13
#define FTPM_PPI_OP_C_E_A               14
#define FTPM_PPI_OP_SET_NO_PROV_FALSE   15
#define FTPM_PPI_OP_SET_NO_PROV_TRUE    16
#define FTPM_PPI_OP_SET_NO_CLEAR_FALSE  17
#define FTPM_PPI_OP_SET_NO_CLEAR_TRUE   18
#define FTPM_PPI_OP_SET_NO_MAINT_FALSE  19
#define FTPM_PPI_OP_SET_NO_MAINT_TRUE   20
#define FTPM_PPI_OP_E_A_C               21
#define FTPM_PPI_OP_E_A_C_E_A           22
#define FTPM_PPI_OP_RESERVED_FIRST      23
#define FTPM_PPI_OP_RESERVED_LAST      127
#define FTPM_PPI_OP_VENDOR_FIRST       128

#define FTPM_PPI_VERSION               0x00322E31 // "1.2"

#define FTPM_PPI_OP_NOT_IMPLEMENTED    0xFFFFFFFF // Any Op other than E_A_C_E_A

#pragma pack(1)
typedef struct {
    UINT32 PendingPseudoOp;
    UINT32 PseudoOpFromLastBoot;
    UINT32 ReturnResponse;
} FTPM_PPI_STATE;
#pragma pack()

//
// The types of TPM runtime state stored to NV
//
typedef enum {
    NV_TPM_STATE_FLAGS = 0,
    NV_TPM_STATE_PPI,
    NV_TPM_STATE_LAST           // A mark of the end of the TPM state
} NV_TPM_STATE;

//***_admin__NvInitState()
// Initialize the NV admin state
void
_admin__NvInitState();

//***_admin__NvReadState()
// Read TPM state data from NV memory to RAM
void
_admin__NvReadState(
    NV_TPM_STATE     type,    // IN: type of state data
    void             *buffer  // OUT: data buffer
    );

//***_admin__NvWriteState()
// Write TPM state data to NV memory
void
_admin__NvWriteState(
    NV_TPM_STATE     type,    // IN: type of state data
    void             *buffer  // IN: data buffer
    );

//
// Save and restore runtime state
//


//***_admin__SaveChipFlags()
// Save the g_chipFlags runtime state
void
_admin__SaveChipFlags();

//***_admin__RestoreChipFlags()
// Restore the g_chipFlags runtime state
void
_admin__RestoreChipFlags();

//***_admin__SavePPIState()
// Save the s_PPIState runtime state
void
_admin__SavePPIState();

//***_admin__RestorePPIState()
// Restore the s_PPIState runtime state
void
_admin__RestorePPIState();

//***_admin__PPICommand()
// Returns 1 when PPI command has been consumed
// Returns 0 when it is not a properly formated PPI command,
//           caller should pass through to TPM
//
int
_admin__PPICommand(
    UINT32 CommandSize,
    __in_ecount(CommandSize) UINT8 *CommandBuffer,
    UINT32 *ResponseSize,
    __deref_out_ecount(*ResponseSize) UINT8 **ResponseBuffer
);

#endif
