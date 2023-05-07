/*
 * Copyright (c) 2014-2023, Linaro Limited
 *
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <stdint.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef CFG_WITH_PAGER
#error "Pager is not supported for NPCM845x"
#endif /* CFG_WITH_PAGER */

#define DRAM0_BASE	0x00000000
#define DRAM0_SIZE	0x40000000	/* 1G DDR */

#define GIC_BASE	0xDFFF8000
#define UART0_BASE	0xf0000000
#define UART1_BASE	0xf0001000
#define UART2_BASE	0xf0002000
#define UART3_BASE	0xf0003000

#define IT_UART1	38

#define GIC_BASE	0xDFFF8000
#define UART0_BASE	0xf0000000
#define UART1_BASE	0xf0001000
#define UART2_BASE	0xf0002000
#define UART3_BASE	0xf0003000
#define UART_REG_SIZE	0x100
#define CONSOLE_UART_BASE	UART0_BASE
#define CONSOLE_UART_CLK_IN_HZ	1

#define GICD_OFFSET	0x1000
#define GICC_OFFSET	0x2000

#ifdef GIC_BASE
#define GICD_BASE	(GIC_BASE + GICD_OFFSET)
#define GICC_BASE	(GIC_BASE + GICC_OFFSET)
#endif /* GIC_BASE */

#ifndef UART_BAUDRATE
#define UART_BAUDRATE	115200
#endif

#ifndef CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE	UART_BAUDRATE
#endif

#endif /*PLATFORM_CONFIG_H*/
