/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Google LLC
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#define STACK_ALIGNMENT		64

#define GICD_BASE		0x05880000
#define GICR_BASE		0x05900000

#define CONSOLE_UART_BASE	0x0db62000
#define CONSOLE_UART_CLK_IN_HZ	0
#define CONSOLE_BAUDRATE	115200

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x77000000
#define DRAM1_BASE		0x880000000
#define DRAM1_SIZE		0x380000000

#endif /* PLATFORM_CONFIG_H */
