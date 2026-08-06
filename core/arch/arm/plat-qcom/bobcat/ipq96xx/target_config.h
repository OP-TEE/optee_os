/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GENI_UART_REG_BASE		UL(0x1A98000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			ULL(0x380000000)

#define GICD_BASE			UL(0xF200000)
#define GICR_BASE			UL(0xF240000)

#define IMEM_BASE			UL(0x8600000)
#define IMEM_SIZE			UL(0x20000)

/* eMMC (SDCC) is the ICE-backed storage controller on ipq96xx */
#define ICE_LUT_KEYS			SDCC_ICE_LUT_KEYS
#define ICE_LUT_KEYS_SIZE		SDCC_ICE_LUT_KEYS_SIZE

#endif /* TARGET_CONFIG_H */
