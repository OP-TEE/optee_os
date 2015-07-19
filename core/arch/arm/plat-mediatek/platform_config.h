/*
 * Copyright (c) 2015, Linaro Limited
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

#define PLATFORM_FLAVOR_ID_mt8173	0
#define PLATFORM_FLAVOR_IS(flav) \
	(PLATFORM_FLAVOR == PLATFORM_FLAVOR_ID_ ## flav)

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef ARM64
#ifdef CFG_WITH_PAGER
#error "Pager not supported for ARM64"
#endif
#endif /*ARM64*/

#if PLATFORM_FLAVOR_IS(mt8173)

#define GIC_BASE		0x10220000
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000

#define UART0_BASE		0x11002000
#define UART1_BASE		0x11003000
#define UART2_BASE		0x11004000
#define UART3_BASE		0x11005000

#define CONSOLE_UART_BASE	UART0_BASE
#define CONSOLE_BAUDRATE	921600
#define CONSOLE_UART_CLK_IN_HZ	26000000

#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		0x80000000

/* Location of trusted dram */
#define TZDRAM_BASE		0xBE000000
#define TZDRAM_SIZE		0x02000000

#define CFG_TEE_CORE_NB_CORE	4

#define CFG_SHMEM_START		(TZDRAM_BASE - 0x100000)
#define CFG_SHMEM_SIZE		0x100000

#else
#error "Unknown platform flavor"
#endif

#define HEAP_SIZE		(24 * 1024)

#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR	CFG_TEE_RAM_START
#endif

/*
 * Everything is in TZDRAM.
 * +------------------+
 * |        | TEE_RAM |
 * + TZDRAM +---------+
 * |        | TA_RAM  |
 * +--------+---------+
 */
#define CFG_TEE_RAM_PH_SIZE	CFG_TEE_RAM_VA_SIZE
#define CFG_TEE_RAM_START	TZDRAM_BASE
#define CFG_TA_RAM_START	ROUNDUP((TZDRAM_BASE + CFG_TEE_RAM_VA_SIZE), \
					CORE_MMU_DEVICE_SIZE)
#define CFG_TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - CFG_TEE_RAM_VA_SIZE), \
					  CORE_MMU_DEVICE_SIZE)

#define DEVICE0_BASE		ROUNDDOWN(CONSOLE_UART_BASE, \
					  CORE_MMU_DEVICE_SIZE)
#define DEVICE0_SIZE		CORE_MMU_DEVICE_SIZE
#define DEVICE0_TYPE		MEM_AREA_IO_NSEC

#define DEVICE1_BASE		ROUNDDOWN(GIC_BASE, CORE_MMU_DEVICE_SIZE)
#define DEVICE1_SIZE		CORE_MMU_DEVICE_SIZE
#define DEVICE1_TYPE		MEM_AREA_IO_SEC

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES		5
#endif

#endif /*PLATFORM_CONFIG_H*/
