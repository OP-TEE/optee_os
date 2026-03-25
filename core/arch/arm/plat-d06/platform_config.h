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
#if defined(PLATFORM_FLAVOR_d06)
#define UART_BASE		0x2f8
#define CONSOLE_UART_CLK_IN_HZ	200
#endif

#if defined(PLATFORM_FLAVOR_HIP08A)
#define UART_BASE		0x94080000
#define CONSOLE_UART_CLK_IN_HZ	200000000
#endif

#define CONSOLE_BAUDRATE	115200

/* HISI_TRNG */
#define HISI_TRNG_BASE		0x2010C0000
#define HISI_TRNG_SIZE		0x100

/* SEC */
#define HISI_SEC_BASE		0x141800000
#define HISI_SEC_SIZE		0x400000

#endif /* PLATFORM_CONFIG_H */
