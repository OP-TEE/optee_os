/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#if defined(PLATFORM_FLAVOR_ns3)

#define STACK_ALIGNMENT		64

#define CONSOLE_UART_CLK_IN_HZ	25000000
#define CONSOLE_BAUDRATE	115200

#define CONSOLE_UART_BASE	0x68a10000
#define BCM_DEVICE0_BASE	CONSOLE_UART_BASE
#define BCM_DEVICE0_SIZE	CORE_MMU_PGDIR_SIZE

#define GICD_BASE		0x63c00000
#define BCM_DEVICE1_BASE	GICD_BASE
#define BCM_DEVICE1_SIZE	CORE_MMU_PGDIR_SIZE

#else
#error "Unknown platform flavor"
#endif
#endif /*PLATFORM_CONFIG_H*/
