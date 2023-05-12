/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Schneider Electric
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* DRAM */
#define DRAM_BASE			0x80000000
#define DRAM_SIZE			0x40000000 /* 1GB, and support 256MB */

/* GIC */
#define GIC_BASE			0x44100000
#define GICD_OFFSET			0x1000
#define GICC_OFFSET			0x2000
#define GICD_BASE			(GIC_BASE + GICD_OFFSET)
#define GICC_BASE			(GIC_BASE + GICC_OFFSET)

/* Peripheral memory map */
#define PERIPH_REG_BASE			0x40000000

/* System Control */
#define SYSCTRL_BASE			0x4000C000

/* UART */
#define CONSOLE_UART_BASE		0x40060000

#endif /* PLATFORM_CONFIG_H */
