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

#if defined(PLATFORM_FLAVOR_dra7xx) || defined(PLATFORM_FLAVOR_am57xx)

#define DRAM0_BASE		0xbe000000
#define DRAM0_SIZE		0x02000000

#ifdef CFG_WITH_PAGER
#error Pager not supported on this platform
#endif /*CFG_WITH_PAGER*/

/* Location of protected DDR on the DRA7xx platform */
#define TZDRAM_BASE		0xbe000000
#define TZDRAM_SIZE		0x01c00000

#define CFG_TEE_CORE_NB_CORE	2

#define UART1_BASE      0x4806A000
#define UART2_BASE      0x4806C000
#define UART3_BASE      0x48020000

/* UART1 */
#define CONSOLE_UART_BASE       UART1_BASE
#define CONSOLE_BAUDRATE        115200
#define CONSOLE_UART_CLK_IN_HZ	48000000

#define GIC_BASE        0x48210000
#define GICC_OFFSET     0x2000
#define GICC_SIZE       0x1000
#define GICD_OFFSET     0x1000
#define GICD_SIZE       0x1000
#define GICC_BASE       (GIC_BASE + GICC_OFFSET)
#define GICD_BASE       (GIC_BASE + GICD_OFFSET)

#define SECRAM_BASE     0x40200000

/* RNG */
#define RNG_BASE        0x48090000

#else
#error "Unknown platform flavor"
#endif

#if defined(PLATFORM_FLAVOR_am57xx)

/* UART3 */
#undef CONSOLE_UART_BASE
#define CONSOLE_UART_BASE       UART3_BASE

#endif

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* Full GlobalPlatform test suite requires CFG_SHMEM_SIZE to be at least 2MB */
#define CFG_SHMEM_START		(DRAM0_BASE + TZDRAM_SIZE)
#define CFG_SHMEM_SIZE		0x400000

#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR	(CFG_TEE_RAM_START + 0x100)
#endif

/*
 * Assumes that either TZSRAM isn't large enough or TZSRAM doesn't exist,
 * everything is in TZDRAM.
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

#define DEVICE2_PA_BASE		ROUNDDOWN(SECRAM_BASE, CORE_MMU_DEVICE_SIZE)
#define DEVICE2_VA_BASE		DEVICE2_PA_BASE
#define DEVICE2_SIZE		CORE_MMU_DEVICE_SIZE
#define DEVICE2_TYPE		MEM_AREA_IO_SEC

#endif /*PLATFORM_CONFIG_H*/
