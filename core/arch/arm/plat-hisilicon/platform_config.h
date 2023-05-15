/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, HiSilicon Technologies Co., Ltd.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <hi3519av100.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* PL011 UART */
#define CONSOLE_UART_BASE	PL011_UART0_BASE
#define CONSOLE_BAUDRATE	PL011_BAUDRATE
#define CONSOLE_UART_CLK_IN_HZ	PL011_UART0_CLK_IN_HZ

#endif /* PLATFORM_CONFIG_H */
