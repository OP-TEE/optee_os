/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#if (defined(PLATFORM_FLAVOR_tc0) ||	\
	defined(PLATFORM_FLAVOR_tc1) ||	\
	defined(PLATFORM_FLAVOR_tc2))
#ifndef CFG_CORE_SEL2_SPMC
#define GIC_BASE		0x30000000
#define GICD_OFFSET		0x0
#define GICC_OFFSET		0x0
#endif

#define UART0_BASE		0x7FF70000
#define UART1_BASE		0x7FF80000

#define CONSOLE_UART_BASE	UART0_BASE

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x7d000000

#define DRAM1_BASE		0x8080000000ULL
#define DRAM1_SIZE		0x180000000ULL

#define TZCDRAM_BASE		0xff000000
#define TZCDRAM_SIZE		0x01000000

#else
#error "Unknown platform flavor"
#endif

#ifdef GIC_BASE
#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE		(GIC_BASE + GICC_OFFSET)
#endif

#define CONSOLE_UART_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	7372800

#endif /* PLATFORM_CONFIG_H */
