/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Arm Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GIC_BASE		0x1c000000

#define UART0_BASE		0x1a510000
#define UART1_BASE		0x1a520000
#define CONSOLE_UART_BASE	UART1_BASE

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		CFG_DDR_SIZE

#define GICD_OFFSET		0x10000
#define GICC_OFFSET		0x2F000

#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE		(GIC_BASE + GICC_OFFSET)

#define MM_COMM_BUF_BASE	0x02000000
#define MM_COMM_BUF_SIZE	0x1000

#define UART_BAUDRATE		115200
#define CONSOLE_BAUDRATE	UART_BAUDRATE

#define SYS_COUNTER_FREQ_IN_TICKS	UL(50000000) /* 50MHz */

#define CONSOLE_UART_CLK_IN_HZ	UL(50000000) /* 50MHz*/

#endif /*PLATFORM_CONFIG_H*/
