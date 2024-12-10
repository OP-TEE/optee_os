/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define CACHELINE_LEN		64
#define STACK_ALIGNMENT		CACHELINE_LEN

#define CONSOLE_UART0		U(0)
#define CONSOLE_UART1		U(1)

#if defined(PLATFORM_FLAVOR_generic)

#define PLM_RTCA		0xF2014000
#define PLM_RTCA_LEN		0x1000

#define GICD_BASE		U(0xE2000000)
#define GICR_BASE		U(0xE2060000)

#define UART0_BASE		U(0xF1920000)
#define UART1_BASE		U(0xF1930000)

#define IT_UART0		50
#define IT_UART1		51

#define UART_CLK_IN_HZ		100000000

#if (CFG_CONSOLE_UART == CONSOLE_UART1)
#define CONSOLE_UART_BASE       UART1_BASE
#define IT_CONSOLE_UART         IT_UART1
#else /* CFG_CONSOLE_UART == CONSOLE_UART0 (default) */
#define CONSOLE_UART_BASE	UART0_BASE
#define IT_CONSOLE_UART		IT_UART0
#endif

#define CONSOLE_UART_CLK_IN_HZ	UART_CLK_IN_HZ

#define DRAM0_BASE		0
#define DRAM0_SIZE		0x80000000

#ifndef ARM64
#error "Only ARM64 is supported!"
#endif

#else
#error "Unknown platform flavor"
#endif

#ifndef UART_BAUDRATE
#define UART_BAUDRATE		115200
#endif

#ifndef CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE	UART_BAUDRATE
#endif

#endif /* PLATFORM_CONFIG_H */
