/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)
#define DRAM1_BASE			ULL(0x880000000)
#define DRAM1_SIZE			ULL(0x780000000)

#define GCC_BASE			UL(0x01400000)
#define GCC_SIZE			UL(0x001f0000)

#define GENI_UART_REG_BASE		UL(0x04a80000)

/* GIC-500 redistributor (GICD_BASE is common to the family). */
#define GICR_BASE			UL(0x0f260000)

#define SECURITY_CONTROL_BASE		UL(0x01b40000)
#define SECURITY_CONTROL_SIZE		UL(0x00010000)
#define TCSR_MUTEX_BASE			UL(0x00340000)
#define TCSR_MUTEX_SIZE			UL(0x00040000)
#define TCSR_BOOT_MISC_DETECT		UL(0x003d3000)

#define CFG_SEC_ELF_DDR_ADDR		UL(0x85fff000)
#define CFG_SEC_ELF_DDR_SIZE		UL(0x00001000)

#endif /* TARGET_CONFIG_H */
