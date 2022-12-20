/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2022, Huawei Technologies Co., Ltd
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* UART */
#define UART_BASE		0x2f8
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	200

/* SEC */
#define SEC_BASE	0x141800000
#define SEC_SIZE	0x400000

#endif /* PLATFORM_CONFIG_H */
