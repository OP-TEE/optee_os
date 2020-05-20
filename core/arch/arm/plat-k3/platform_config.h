/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2016-2018 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew F. Davis <afd@ti.com>
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#define UART0_BASE      0x02800000

#define CONSOLE_UART_BASE       (UART0_BASE + CFG_CONSOLE_UART * 0x10000)
#define CONSOLE_BAUDRATE        115200
#define CONSOLE_UART_CLK_IN_HZ  48000000

#define SCU_BASE        0x01800000
#if defined(PLATFORM_FLAVOR_j721e)
#define GICC_OFFSET     0x100000
#define GICC_SIZE       0x100000
#define GICD_OFFSET     0x0
#define GICD_SIZE       0x10000
#else
#define GICC_OFFSET     0x80000
#define GICC_SIZE       0x90000
#define GICD_OFFSET     0x0
#define GICD_SIZE       0x10000
#endif
#define GICC_BASE       (SCU_BASE + GICC_OFFSET)
#define GICD_BASE       (SCU_BASE + GICD_OFFSET)

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#endif /*PLATFORM_CONFIG_H*/
