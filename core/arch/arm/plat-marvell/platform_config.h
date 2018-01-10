/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017 Marvell International Ltd.
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

#include <util.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef ARM64
#ifdef CFG_WITH_PAGER
#error "Pager not supported yet"
#endif
#else
#error "32 bit mode not supported yet"
#endif /*ARM64*/

/* SDP enable but no pool defined: reserve 4MB for SDP tests */
#if defined(CFG_SECURE_DATA_PATH) && !defined(CFG_TEE_SDP_MEM_BASE)
#define CFG_TEE_SDP_MEM_TEST_SIZE	0x00400000
#else
#define CFG_TEE_SDP_MEM_TEST_SIZE	0
#endif

#if defined(PLATFORM_FLAVOR_armada7k8k)
/*
 * armada7k8k specifics.
 */
#define TEE_RES_CFG_8M

#define MVEBU_REGS_BASE		0xF0000000

/* GICv2 */
#define MVEBU_GICD_BASE		0x210000
#define MVEBU_GICC_BASE		0x220000
#define GIC_DIST_BASE			(MVEBU_REGS_BASE + MVEBU_GICD_BASE)
#define GIC_CPU_BASE			(MVEBU_REGS_BASE + MVEBU_GICC_BASE)

#define GIC_BASE		GIC_DIST_BASE

/* UART */
#define PLAT_MARVELL_BOOT_UART_BASE		(MVEBU_REGS_BASE + 0x512000)
#define PLAT_MARVELL_BOOT_UART_CLK_IN_HZ        200000000
#define MARVELL_CONSOLE_BAUDRATE                            115200

#define CONSOLE_UART_BASE	PLAT_MARVELL_BOOT_UART_BASE

/* Location of trusted dram */
#define TZDRAM_BASE		0x04400000
#define TZDRAM_SIZE		0x00C00000

#define CFG_TEE_CORE_NB_CORE	4

#define CFG_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define CFG_SHMEM_SIZE		0x00400000

#define GICC_OFFSET		0x10000
#define GICD_OFFSET		0x0

/* MCU */
#define MCU_BASE			0xF0020000
#define MCU_REG_SIZE		SIZE_4K
#define MC_SCR_REGISTER	0xF06F0204
#define MC_SCR_REG_SIZE	SIZE_4K

#elif defined(PLATFORM_FLAVOR_armada3700)
/*
 * armada3700 specifics.
 */
#define TEE_RES_CFG_8M

#define MVEBU_REGS_BASE		0xD0000000

/* GICv3 */
#define MVEBU_GICD_BASE		0x1D00000
#define MVEBU_GICR_BASE		0x1D40000
#define MVEBU_GICC_BASE		0x1D80000

#define GIC_DIST_BASE		(MVEBU_REGS_BASE + MVEBU_GICD_BASE)
#define GIC_RDIS_BASE		(MVEBU_REGS_BASE + MVEBU_GICR_BASE)
#define GIC_CPU_BASE		(MVEBU_REGS_BASE + MVEBU_GICC_BASE)

#define GIC_BASE		GIC_DIST_BASE
#define GICC_OFFSET		(0x80000)
#define GICR_OFFSET		(0x40000)
#define GICD_OFFSET		(0x0)

/* UART */
#define PLAT_MARVELL_BOOT_UART_BASE		(MVEBU_REGS_BASE + 0x12000)
#define PLAT_MARVELL_BOOT_UART_CLK_IN_HZ	25804800
#define MARVELL_CONSOLE_BAUDRATE		115200
#define CONSOLE_UART_BASE	PLAT_MARVELL_BOOT_UART_BASE

/* Location of trusted dram */
#define TZDRAM_BASE		0x04400000
#define TZDRAM_SIZE		0x00C00000

#define CFG_TEE_CORE_NB_CORE	2

#define CFG_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define CFG_SHMEM_SIZE		0x00400000

#else
#error "Unknown platform flavor"
#endif

#define CFG_TEE_RAM_VA_SIZE	SIZE_4M

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR	CFG_TEE_RAM_START
#endif

/*
 * everything is in TZDRAM.
 * +------------------+
 * |        | TEE_RAM |
 * | TZDRAM +---------+
 * |        | TA_RAM  |
 * |        +---------+
 * |        | SDP RAM | (test pool, optional)
 * +--------+---------+
 */
#define CFG_TEE_RAM_PH_SIZE	CFG_TEE_RAM_VA_SIZE
#define CFG_TEE_RAM_START	TZDRAM_BASE
#define CFG_TA_RAM_START	ROUNDUP(TZDRAM_BASE + CFG_TEE_RAM_VA_SIZE, \
					CORE_MMU_DEVICE_SIZE)

#define CFG_TA_RAM_SIZE		ROUNDDOWN(TZDRAM_SIZE - \
					  (CFG_TA_RAM_START - TZDRAM_BASE) - \
					  CFG_TEE_SDP_MEM_TEST_SIZE, \
					  CORE_MMU_DEVICE_SIZE)

/* Secure data path test memory pool: located at end of TA RAM */
#if CFG_TEE_SDP_MEM_TEST_SIZE
#define CFG_TEE_SDP_MEM_SIZE		CFG_TEE_SDP_MEM_TEST_SIZE
#define CFG_TEE_SDP_MEM_BASE		(TZDRAM_BASE + TZDRAM_SIZE - \
						CFG_TEE_SDP_MEM_SIZE)
#endif

#ifdef GIC_BASE
#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE			(GIC_BASE + GICC_OFFSET)
#endif

#define UART_BAUDRATE			MARVELL_CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE		UART_BAUDRATE
#define CONSOLE_UART_CLK_IN_HZ	PLAT_MARVELL_BOOT_UART_CLK_IN_HZ

#endif /*PLATFORM_CONFIG_H*/
