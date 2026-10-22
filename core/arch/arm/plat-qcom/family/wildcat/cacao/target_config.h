/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GICD_BASE			UL(0x17200000)
#define GICR_BASE			UL(0x17260000)

#define GCC_BASE			UL(0x00100000)
#define GCC_SIZE			UL(0x001f0000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x10000000)

#define GENI_UART_REG_BASE		UL(0xa94000)

#endif /* TARGET_CONFIG_H */
