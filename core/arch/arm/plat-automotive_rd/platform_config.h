/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 - 2025, Arm Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <util.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			64

#if defined(PLATFORM_FLAVOR_rdaspen)

/* DRAM constants */
#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			SIZE_2G
#define DRAM1_BASE			ULL(0x20000000000)
#define DRAM1_SIZE			SIZE_2G

/* UART constants */
#define UART_BAUDRATE			115200
#define CONSOLE_BAUDRATE		UART_BAUDRATE
#define UART1_BASE			UL(0x1a410000)
#define CONSOLE_UART_BASE		UART1_BASE
#define CONSOLE_UART_CLK_IN_HZ		UL(24000000)

/* GIC related constants */
#define GICD_BASE			UL(0x20000000)
#define GICR_BASE			UL(0x200C0000)
#define GICR_SIZE			UL(0xF00000)

/* RD-Aspen topology related constants */
#define RDASPEN_MAX_CPUS_PER_CLUSTER	U(4)
#define RDASPEN_MAX_PE_PER_CPU		U(1)

#elif defined(PLATFORM_FLAVOR_rd1ae)

/* DRAM constants */
#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			SIZE_2G

#define DRAM1_BASE			ULL(0x8080000000)
#define DRAM1_SIZE			SIZE_2G

#define SYS_COUNTER_FREQ_IN_TICKS	UL(7372800)
/* UART constants */
#define UART_BAUDRATE			115200
#define CONSOLE_BAUDRATE		UART_BAUDRATE
#define UART0_BASE			UL(0x2A400000)
#define UART1_BASE			UL(0x2A410000)
#define CONSOLE_UART_BASE		UART1_BASE
#define CONSOLE_UART_CLK_IN_HZ		UL(7372800)

/* GIC related constants */
#define GICD_BASE			UL(0x30000000)
#define GICC_BASE			UL(0x2C000000)

 /* RD-1 AE topology related constants */
#define RD1AE_MAX_CPUS_PER_CLUSTER	U(1)
#define RD1AE_MAX_CLUSTERS_PER_CHIP	U(16)

#else
#error "Unknown platform flavor"
#endif

#endif /* PLATFORM_CONFIG_H */
