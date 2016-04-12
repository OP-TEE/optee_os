/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
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

#define PLATFORM_FLAVOR_ID_mx6ulevk	0
#define PLATFORM_FLAVOR_IS(flav) \
	(PLATFORM_FLAVOR_ID_ ## flav == PLATFORM_FLAVOR)

#define STACK_ALIGNMENT			64

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform imx"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported for now"
#endif

/* For i.MX 6UltraLite EVK board */
#if  PLATFORM_FLAVOR_IS(mx6ulevk)
#define GIC_BASE			0xA00000
#define GIC_SIZE			0x8000
#define GICC_OFFSET			0x2000
#define GICD_OFFSET			0x1000
#define UART0_BASE			0x2020000
#define UART1_BASE			0x21E8000
#define UART2_BASE			0x21EC000

#define AHB1_BASE			0x02000000
#define AHB1_SIZE			0x100000
#define AHB2_BASE			0x02100000
#define AHB2_SIZE			0x100000
#define AHB3_BASE			0x02200000
#define AHB3_SIZE			0x100000

#define AIPS_TZ1_BASE_ADDR		0x02000000
#define AIPS1_OFF_BASE_ADDR             (AIPS_TZ1_BASE_ADDR + 0x80000)

#define DRAM0_BASE			0x80000000
#define DRAM0_SIZE			0x20000000

#define CFG_TEE_CORE_NB_CORE		1

#define DDR_PHYS_START			DRAM0_BASE
#define DDR_SIZE			DRAM0_SIZE

#define CFG_DDR_START			DDR_PHYS_START
#define CFG_DDR_SIZE			DDR_SIZE

/* Full GlobalPlatform test suite requires CFG_SHMEM_SIZE to be at least 2MB */
#define CFG_SHMEM_START			(TZDRAM_BASE - 0x100000)
#define CFG_SHMEM_SIZE			0x100000

#else
#error "Unknown platform flavor"
#endif

#define HEAP_SIZE			(24 * 1024)

/* Location of trusted dram on imx */
#define TZDRAM_BASE			(0x9c100000)
#define TZDRAM_SIZE			(0x03000000)

#define CFG_TEE_RAM_VA_SIZE		(1024 * 1024)

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR		CFG_TEE_RAM_START
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

#define DEVICE0_PA_BASE		ROUNDDOWN(UART0_BASE, \
					  CORE_MMU_DEVICE_SIZE)
#define DEVICE0_VA_BASE		(64 * 1024 * 1024)
#define DEVICE0_SIZE		CORE_MMU_DEVICE_SIZE
#define DEVICE0_TYPE		MEM_AREA_IO_NSEC

/*
 * console uart virtual address
 * The physical address is 0x2020000, we mapped it to 0x4020000,
 * see DEVICE0_VA_BASE and DEVICE0_PA_BASE
 */
#define CONSOLE_UART_BASE	(0x4020000)
#define CONSOLE_UART_PA_BASE	(UART0_BASE)

#endif /*PLATFORM_CONFIG_H*/
