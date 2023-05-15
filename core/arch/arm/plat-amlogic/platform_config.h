/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020 Carlo Caione <ccaione@baylibre.com>
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GIC_BASE		0xFFC01000
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000

#define CONSOLE_UART_BASE	0xFF803000

#endif /*PLATFORM_CONFIG_H*/
