/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Arm Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			64

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)

#define DRAM1_BASE			ULL(0x8080000000)
#define DRAM1_SIZE			ULL(0x80000000)

#define SYS_COUNTER_FREQ_IN_TICKS	UL(7372800)

#define UART0_BASE			UL(0x2A400000)
#define UART1_BASE			UL(0x2A410000)
#define CONSOLE_UART_BASE		UART1_BASE
#define UART_BAUDRATE			115200
#define CONSOLE_BAUDRATE		UART_BAUDRATE
#define CONSOLE_UART_CLK_IN_HZ		UL(7372800)

/* GIC related constants */
#define GICD_BASE			UL(0x30000000)
#define GICC_BASE			UL(0x2C000000)

 /* RD-1 AE topology related constants */
#define RD1AE_MAX_CPUS_PER_CLUSTER	U(1)
#define PLAT_ARM_CLUSTER_COUNT		U(1)
#define PLAT_RD1AE_CHIP_COUNT		U(1)
#define RD1AE_MAX_CLUSTERS_PER_CHIP	U(16)
#define RD1AE_MAX_PE_PER_CPU		U(1)

#endif /*PLATFORM_CONFIG_H*/
