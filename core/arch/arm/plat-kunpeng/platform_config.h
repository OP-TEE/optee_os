// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, HiSilicon Technologies Co., Ltd.
 * All rights reserved.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* UART */
#if defined(PLATFORM_FLAVOR_HIP09)
#define UART_BASE		0xc614080000
#define UART_SIZE		0x1000
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	0
#endif

#endif /* PLATFORM_CONFIG_H */