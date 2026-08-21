/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GENI_UART_REG_BASE		UL(0x884000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x380000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			ULL(0x800000000)

/*
 * IRIS video-codec subsystem.
 */
#define IRIS_BASE			UL(0x0aa00000)
#define IRIS_SIZE			ULL(0x00200000)

/*
 * Camera-ICP (Imaging Control Processor). Nord has two independent ICP
 * instances (PAS ID 33 / 50), unlike lemans's single Titan SS block.
 */
#define ICP0_BASE			UL(0x09a03000)
#define ICP0_SIZE			UL(0x00001000)
#define ICP1_BASE			UL(0x09a13000)
#define ICP1_SIZE			UL(0x00001000)

#endif /* TARGET_CONFIG_H */
