/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Altera Corporation.
 */

#ifndef __PLATFORM_CONFIG_H
#define __PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* UART settings */
#define CONSOLE_UART_BASE  0x10C02000
#define CONSOLE_BAUDRATE       115200
#define CONSOLE_UART_CLK_IN_HZ 100000000

/* Generic Interrupt Controller */
#define GIC_BASE_ADDR 0x1D000000
#define GIC_DIST_OFFSET 0x0
#define GIC_CPU_OFFSET  0x100000

/* DDR memory for dynamic shared memory */
#define DRAM0_BASE 0x80000000
#define DRAM0_SIZE 0x70000000  /* 1792 MB */

#endif /* __PLATFORM_CONFIG_H */
