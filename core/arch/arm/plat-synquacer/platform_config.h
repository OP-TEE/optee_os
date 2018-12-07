/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#define STACK_ALIGNMENT			64

#define GIC_BASE			0x30000000
#define GICD_OFFSET			0x0

/* console uart define */
#define UART0_BASE			0x2A400000
#define CONSOLE_UART_BASE		UART0_BASE
#define CONSOLE_UART_CLK_IN_HZ		62500000
#define CONSOLE_BAUDRATE		115200

#define THERMAL_SENSOR_BASE		0x54190000
#define IT_SEC_TIMER			29
#define TIMER_PERIOD_MS			2

#define DRAM0_BASE			0x80000000

/* Platform specific defines */
#if defined(PLATFORM_FLAVOR_developerbox)
#define DRAM0_SIZE			0x80000000
#endif

#endif /*PLATFORM_CONFIG_H*/
