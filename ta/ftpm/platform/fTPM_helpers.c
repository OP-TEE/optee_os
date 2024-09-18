/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>

//
// Helper functions for byte ordering of TPM commands/responses
//
uint16_t SwapBytes16(uint16_t Value)
{
    return (uint16_t)((Value << 8) | (Value >> 8));
}

uint32_t SwapBytes32(uint32_t Value)
{
    uint32_t  LowerBytes;
    uint32_t  HigherBytes;

    LowerBytes = (uint32_t)SwapBytes16((uint16_t)Value);
    HigherBytes = (uint32_t)SwapBytes16((uint16_t)(Value >> 16));

    return (LowerBytes << 16 | HigherBytes);
}
