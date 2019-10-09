/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#if defined(PLATFORM_FLAVOR_rk322x)

#define GIC_BASE		0x32010000
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000

#define GICC_BASE		(GIC_BASE + GICC_OFFSET)
#define GICD_BASE		(GIC_BASE + GICD_OFFSET)

#define SGRF_BASE		0x10140000
#define DDRSGRF_BASE		0x10150000
#define GRF_BASE		0x11000000
#define UART2_BASE		0x11030000
#define CRU_BASE		0x110E0000

/* Internal SRAM */
#define ISRAM_BASE		0x10080000
#define ISRAM_SIZE		0x8000

/* Periph IO */
#define PERIPH_BASE		0x10100000
#define PERIPH_SIZE		0x22000000

#else
#error "Unknown platform flavor"
#endif

#define CONSOLE_UART_BASE	UART2_BASE
#define CONSOLE_BAUDRATE	1500000
#define CONSOLE_UART_CLK_IN_HZ	24000000

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES		5
#endif

#endif
