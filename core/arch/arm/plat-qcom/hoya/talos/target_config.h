/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

/* DDR outside the OP-TEE carve-out at 0x87a00000 */
#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x07a00000)
#define DRAM1_BASE			UL(0x89600000)
#define DRAM1_SIZE			UL(0x30100000)
#define DRAM2_BASE			UL(0xc0000000)
#define DRAM2_SIZE			ULL(0x1c0000000)

#define GENI_UART_REG_BASE		UL(0x880000)
#define QCOM_RNG_REG_BASE		UL(0x791000)

#endif /* TARGET_CONFIG_H */
