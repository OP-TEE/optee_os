/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Sequitur Labs Inc.
 * Copyright (c) 2024, EPAM Systems.
 * Copyright (c) 2026, Arm Limited and Contributors. All rights reserved.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* BCM2711 PL011 UART0 */
#define CONSOLE_UART_BASE	0xfe201000
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	48000000

#define DRAM0_BASE		0x00000000
#define DRAM0_SIZE		0x200000000

#endif /* PLATFORM_CONFIG_H */
