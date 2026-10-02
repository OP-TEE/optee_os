/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)

#define GENI_UART_REG_BASE		UL(0x04a80000)

/* GIC-500 redistributor (GICD_BASE is common to the family). */
#define GICR_BASE			UL(0x0f260000)

#endif /* TARGET_CONFIG_H */
