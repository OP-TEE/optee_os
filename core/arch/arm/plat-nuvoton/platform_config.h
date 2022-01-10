/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <stdint.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef CFG_WITH_PAGER
#error "Pager not supported for NPCM845x"
#endif



#define DRAM0_BASE      0x00000000
#define DRAM0_SIZE      0x40000000   // 1G DDR 





#define GIC_BASE		0xDFFF8000
#define UART0_BASE		0xf0000000
#define UART1_BASE		0xf0001000
#define UART2_BASE		0xf0002000
#define UART3_BASE		0xf0003000
//#define TZC400_BASE		0x2a4a0000

#define IT_UART1		38

//#define IT_CONSOLE_UART		IT_UART1

#if defined(PLATFORM_FLAVOR_npcm845x)

#define GIC_BASE		0xDFFF8000
#define UART0_BASE		0xf0000000
#define UART1_BASE		0xf0001000
#define UART2_BASE		0xf0002000
#define UART3_BASE		0xf0003000
#define UART_REG_SIZE   0x100
//#define IT_UART1		40

#define CONSOLE_UART_BASE	UART0_BASE
#define CONSOLE_UART_CLK_IN_HZ	1
//#define IT_CONSOLE_UART		IT_UART1

#else
#error "Unknown platform flavor"
#endif


#if defined(PLATFORM_FLAVOR_npcm845x)

#define GICD_OFFSET		0x1000
#define GICC_OFFSET		0x2000

#else
#error "Unknown platform flavor"
#endif

#ifdef GIC_BASE
#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE		(GIC_BASE + GICC_OFFSET)
#endif

#ifndef UART_BAUDRATE
#define UART_BAUDRATE		115200
#endif
#ifndef CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE	UART_BAUDRATE
#endif

/* For virtual platforms where there isn't a clock */
//#ifndef CONSOLE_UART_CLK_IN_HZ
//#define CONSOLE_UART_CLK_IN_HZ	1
//#endif

#endif /*PLATFORM_CONFIG_H*/
