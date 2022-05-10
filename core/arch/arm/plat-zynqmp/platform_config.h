/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Xilinx Inc.
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
#define CACHELINE_LEN		64
#define STACK_ALIGNMENT		CACHELINE_LEN

#ifdef CFG_WITH_PAGER
#error "Pager not supported for zynqmp"
#endif

/* DDR Low area base */
#define DRAM0_BASE		0

#ifdef ARM64
/* DDR High area base is only available when compiling for 64 bits */
#define DRAM1_BASE		0x800000000
#endif

#ifdef CFG_CDNS_UART
#define CONSOLE_UART_BASE		(CFG_UART_BASE)
#define IT_CONSOLE_UART			(CFG_UART_IT)
#define CONSOLE_UART_CLK_IN_HZ		(CFG_UART_CLK_HZ)
#endif

#if defined(PLATFORM_FLAVOR_zc1751_dc1) || \
	defined(PLATFORM_FLAVOR_zc1751_dc2) || \
	defined(PLATFORM_FLAVOR_zcu102)

#define GIC_BASE		0xF9010000
#define UART0_BASE		0xFF000000
#define UART1_BASE		0xFF010000

#define IT_UART0		53
#define IT_UART1		54

#define UART0_CLK_IN_HZ		100000000
#define UART1_CLK_IN_HZ		100000000

#define GICD_OFFSET		0
#define GICC_OFFSET		0x20000

#elif defined(PLATFORM_FLAVOR_ultra96)

#define GIC_BASE		0xF9010000
#define UART0_BASE		0xFF000000
#define UART1_BASE		0xFF010000

#define IT_UART0		53
#define IT_UART1		54

#define UART0_CLK_IN_HZ		100000000
#define UART1_CLK_IN_HZ		100000000

#define GICD_OFFSET		0
#define GICC_OFFSET		0x20000

#else
#error "Unknown platform flavor"
#endif

#define CSUDMA_BASE		0xFFC80000
#define CSUDMA_SIZE		0x1000
#define CSU_BASE		0xFFCA0000
#define CSU_SIZE		0x5038

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#ifndef UART_BAUDRATE
#define UART_BAUDRATE		115200
#endif
#ifndef CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE	UART_BAUDRATE
#endif

/* For virtual platforms where there isn't a clock */
#ifndef CONSOLE_UART_CLK_IN_HZ
#define CONSOLE_UART_CLK_IN_HZ	1
#endif

#endif /*PLATFORM_CONFIG_H*/
