/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2023, Linaro Limited
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT      64
#define DRAM0_BASE           0x00000000
#define DRAM0_SIZE           0x40000000	/* 1G DDR */
#define GIC_BASE             0xDFFF8000
#define UART0_BASE           0xf0000000
#define UART_REG_SIZE        0x100
#define CONSOLE_UART_BASE    UART0_BASE
#define GICD_OFFSET          0x1000
#define GICC_OFFSET          0x2000
#define GICD_BASE            (GIC_BASE + GICD_OFFSET)
#define GICC_BASE            (GIC_BASE + GICC_OFFSET)

#endif /*PLATFORM_CONFIG_H*/
