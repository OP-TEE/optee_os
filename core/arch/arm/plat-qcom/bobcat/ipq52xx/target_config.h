/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GENI_UART_REG_BASE		UL(0x1A84000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			UL(0x80000000)

#define GICD_BASE			UL(0xB000000)
#define GICC_BASE			UL(0xB002000)
#define GICD_PIDR2			UL(0xFD8)

#define IMEM_BASE			UL(0x8600000)
#define IMEM_SIZE			UL(0x18000)

#endif /* TARGET_CONFIG_H */
