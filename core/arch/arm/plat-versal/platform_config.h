/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define CACHELINE_LEN		64
#define STACK_ALIGNMENT		CACHELINE_LEN

#if defined(PLATFORM_FLAVOR_generic)

#define PLM_RTCA		0xF2014000
#define PLM_RTCA_LEN		0x1000

#define GIC_BASE		0xF9000000
#define UART0_BASE		0xFF000000
#define UART1_BASE		0xFF010000

#define IT_UART0		50
#define IT_UART1		51

#define UART0_CLK_IN_HZ		100000000
#define UART1_CLK_IN_HZ		100000000
#define CONSOLE_UART_BASE	UART0_BASE
#define IT_CONSOLE_UART		IT_UART0
#define CONSOLE_UART_CLK_IN_HZ	UART0_CLK_IN_HZ

#define DRAM0_BASE		0
#define DRAM0_SIZE		0x80000000

#ifdef ARM64
/* DDR High area base is only available when compiling for 64 bits */
#define DRAM1_BASE		0x800000000
#define DRAM1_SIZE		0x180000000
#define DRAM2_BASE		0x50000000000
#define DRAM2_SIZE		0x200000000
#endif

#define GICD_OFFSET		0
#define GICC_OFFSET		0x40000

#else
#error "Unknown platform flavor"
#endif

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#ifndef UART_BAUDRATE
#define UART_BAUDRATE		115200
#endif
#ifndef CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE	UART_BAUDRATE
#endif

#endif /* PLATFORM_CONFIG_H */
