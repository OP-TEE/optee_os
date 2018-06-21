/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2018, Amit Singh Tomar <amittomer25@gmail.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* 16550 UART */
#define CONSOLE_UART_BASE	0x01c28000 /* UART0 */
#define CONSOLE_UART_CLK_IN_HZ	24000000
#define CONSOLE_BAUDRATE	115200
#define SUNXI_UART_REG_SIZE	0x400

#if defined(PLATFORM_FLAVOR_bpi_zero)
#define GIC_BASE		0x01c80000
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000
#define SUNXI_TZPC_BASE		0x01c23400
#define SUNXI_TZPC_REG_SIZE	0x400
#define SUNXI_CPUCFG_BASE	0x01f01c00
#define SUNXI_CPUCFG_REG_SIZE	0x400
#define SUNXI_PRCM_BASE		0x01f01400
#define SUNXI_PRCM_REG_SIZE	0x400
#define PRCM_CPU_SOFT_ENTRY_REG	0x164
#endif

#if defined(PLATFORM_FLAVOR_sun50i_a64)
#define SUNXI_SMC_BASE		0x01c1e000
#endif

#endif /* PLATFORM_CONFIG_H */
