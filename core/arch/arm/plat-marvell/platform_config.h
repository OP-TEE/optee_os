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

#include <mm/generic_ram_layout.h>
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

#define GICC_OFFSET		0x10000
#define GICD_OFFSET		0x0

#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE		(GIC_BASE + GICC_OFFSET)

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

#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE		(GIC_BASE + GICC_OFFSET)

/* UART */
#define PLAT_MARVELL_BOOT_UART_BASE		(MVEBU_REGS_BASE + 0x12000)
#define PLAT_MARVELL_BOOT_UART_CLK_IN_HZ	25804800
#define MARVELL_CONSOLE_BAUDRATE		115200
#define CONSOLE_UART_BASE	PLAT_MARVELL_BOOT_UART_BASE

#elif defined(PLATFORM_FLAVOR_otx2t96) || defined(PLATFORM_FLAVOR_otx2f95) || \
	defined(PLATFORM_FLAVOR_otx2t98)
/*
 * OcteonTX2(otx2) specifics.
 */

/* GICv3 */
#define GIC_BASE		0x801000000000ll
#define GICD_OFFSET             (0x0)

#define GICD_BASE		(GIC_BASE + GICD_OFFSET)

/* UART */
#define PLAT_MARVELL_BOOT_UART_BASE		0x87E028000000ll
#define PLAT_MARVELL_BOOT_UART_CLK_IN_HZ	16666656
#define MARVELL_CONSOLE_BAUDRATE		115200
#define CONSOLE_UART_BASE			PLAT_MARVELL_BOOT_UART_BASE

/* eFUSE */
#define PLAT_MARVELL_FUSF_FUSE_BASE		0x87E004000000ll
#define PLAT_MARVELL_FUSF_HUK_OFFSET		(0x90)

#elif defined(PLATFORM_FLAVOR_cn10ka) || defined(PLATFORM_FLAVOR_cn10kb) || \
	defined(PLATFORM_FLAVOR_cnf10ka) || defined(PLATFORM_FLAVOR_cnf10kb)
/*
 * cn10k specifics.
 */

/* GICv3 */
#define GIC_BASE		0x801000000000ll
#define GICD_OFFSET		0x0

#define GICD_BASE		(GIC_BASE + GICD_OFFSET)

/* UART */
#define PLAT_MARVELL_BOOT_UART_BASE		0x87E028000000ll
#define PLAT_MARVELL_BOOT_UART_CLK_IN_HZ	16666656
#define MARVELL_CONSOLE_BAUDRATE		115200
#define CONSOLE_UART_BASE			PLAT_MARVELL_BOOT_UART_BASE

#else
#error "Unknown platform flavor"
#endif

#define UART_BAUDRATE			MARVELL_CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE		UART_BAUDRATE
#define CONSOLE_UART_CLK_IN_HZ	PLAT_MARVELL_BOOT_UART_CLK_IN_HZ

#endif /*PLATFORM_CONFIG_H*/
