// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Sequitur Labs Inc.
 * Copyright (c) 2024, EPAM Systems.
 */
#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* PL011 UART */
#define CONSOLE_UART_BASE	0x107d001000ULL /* UART0 */
#define CONSOLE_BAUDRATE	0		/* VPU will set UART for us */
#define CONSOLE_UART_CLK_IN_HZ  0

#define DRAM0_BASE		0x00000000
#define DRAM0_SIZE		0x200000000

#endif /* PLATFORM_CONFIG_H */
