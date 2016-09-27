/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright (c) 2016, Wind River Systems.
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

#define STACK_ALIGNMENT			64

/* For i.MX 6UltraLite EVK board */

#if defined(PLATFORM_FLAVOR_mx6ulevk)

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform mx6ulevk"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported for now"
#endif

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

#define AIPS_TZ1_BASE_ADDR	0x02000000
#define AIPS1_OFF_BASE_ADDR	(AIPS_TZ1_BASE_ADDR + 0x80000)

#define DRAM0_BASE			0x80000000
#define DRAM0_SIZE			0x20000000

#define CFG_TEE_CORE_NB_CORE		1

#define DDR_PHYS_START		DRAM0_BASE
#define DDR_SIZE			DRAM0_SIZE

#define CFG_DDR_START		DDR_PHYS_START
#define CFG_DDR_SIZE		DDR_SIZE

/* Full GlobalPlatform test suite requires CFG_SHMEM_SIZE to be at least 2MB */
#define CFG_SHMEM_START		(TZDRAM_BASE - 0x100000)
#define CFG_SHMEM_SIZE		0x100000

/* Location of trusted dram on imx */
#define TZDRAM_BASE			(0x9c100000)
#define TZDRAM_SIZE			(0x03000000)

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
#define CONSOLE_UART_BASE		(0x4020000)
#define CONSOLE_UART_PA_BASE	(UART0_BASE)

/* For i.MX6 Quad SABRE Lite and Smart Device board */

#elif defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)

#define SCU_BASE				0x00A00000
#define PL310_BASE				0x00A02000
#define SRC_BASE				0x020D8000
#define SRC_SCR					0x000
#define SRC_GPR1				0x020
#define SRC_SCR_ENABLE_OFFSET	22
#define GIC_BASE				0x00A00000
#define GICC_OFFSET				0x100
#define GICD_OFFSET				0x1000
#define GIC_CPU_BASE			(GIC_BASE + GICC_OFFSET)
#define GIC_DIST_BASE			(GIC_BASE + GICD_OFFSET)
#define UART1_BASE				0x02020000
#define UART2_BASE				0x021E8000
#define CSU_CSL_START			0x021C0000
#define CSU_CSL_END				0x021C00A0
#define CSU_CSL_5				0x021C0014
#define CSU_CSL_16				0x021C0040

#if defined(PLATFORM_FLAVOR_mx6qsabrelite)
#define CONSOLE_UART_BASE		UART2_BASE
#define CONSOLE_UART_PA_BASE	UART2_BASE
#endif
#if defined(PLATFORM_FLAVOR_mx6qsabresd)
#define CONSOLE_UART_BASE		UART1_BASE
#define CONSOLE_UART_PA_BASE	UART1_BASE
#endif
#define DRAM0_BASE				0x10000000
#define DRAM0_SIZE				0x40000000

#define HEAP_SIZE				(24 * 1024)

#define CFG_TEE_RAM_VA_SIZE		(1024 * 1024)

#define CFG_TEE_CORE_NB_CORE	4

#define DDR_PHYS_START			DRAM0_BASE
#define DDR_SIZE				DRAM0_SIZE

#define CFG_DDR_START			DDR_PHYS_START
#define CFG_DDR_SIZE			DDR_SIZE

/* define the memory areas */

#ifdef CFG_WITH_PAGER

/*
 * TEE/TZ RAM layout:
 *
 *  +-----------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEETZ private RAM  |  TEE_RAM (SRAM)    |   ^
 *  |                    +--------------------+   |
 *  |                    |  TA_RAM            |   |
 *  +-----------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  |                    |      teecore alloc |   |
 *  |  TEE/TZ and NSec   |  PUB_RAM   --------|   |
 *  |   shared memory    |         NSec alloc |   |
 *  +-----------------------------------------+   v
 *
 *  TEE_RAM : 256KByte
 *  PUB_RAM : 1MByte
 *  TA_RAM  : all what is left (at least 2MByte !)
 */

/* emulated SRAM, at start of secure DDR */

#define TZSRAM_BASE				0x4E000000
#define TZSRAM_SIZE				CFG_CORE_TZSRAM_EMUL_SIZE

/* Location of trusted dram */

#define CFG_DDR_TEETZ_RESERVED_START	0x4E100000
#define CFG_DDR_TEETZ_RESERVED_SIZE		0x01F00000

#define CFG_PUB_RAM_SIZE		(1 * 1024 * 1024)

#define TZDRAM_BASE				(CFG_DDR_TEETZ_RESERVED_START)
#define TZDRAM_SIZE				(CFG_DDR_TEETZ_RESERVED_SIZE - \
						CFG_PUB_RAM_SIZE)

#define CFG_TA_RAM_START		TZDRAM_BASE
#define CFG_TA_RAM_SIZE			TZDRAM_SIZE

#define CFG_SHMEM_START			(CFG_DDR_TEETZ_RESERVED_START + \
						TZDRAM_SIZE)
#define CFG_SHMEM_SIZE			CFG_PUB_RAM_SIZE

#define CFG_TEE_RAM_START		TZSRAM_BASE
#define CFG_TEE_RAM_PH_SIZE		TZSRAM_SIZE

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR		TZSRAM_BASE
#endif

#else /* CFG_WITH_PAGER */

/*
 * TEE/TZ RAM layout:
 *
 *  +-----------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEETZ private RAM  |  TEE_RAM           |   ^
 *  |                    +--------------------+   |
 *  |                    |  TA_RAM            |   |
 *  +-----------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  |                    |      teecore alloc |   |
 *  |  TEE/TZ and NSec   |  PUB_RAM   --------|   |
 *  |   shared memory    |         NSec alloc |   |
 *  +-----------------------------------------+   v
 *
 *  TEE_RAM : 1MByte
 *  PUB_RAM : 1MByte
 *  TA_RAM  : all what is left (at least 2MByte !)
 */

#define CFG_DDR_TEETZ_RESERVED_START	0x4E000000
#define CFG_DDR_TEETZ_RESERVED_SIZE		0x02000000

#define CFG_PUB_RAM_SIZE		(1 * 1024 * 1024)
#define CFG_TEE_RAM_PH_SIZE		(1 * 1024 * 1024)

#define TZDRAM_BASE				(CFG_DDR_TEETZ_RESERVED_START)
#define TZDRAM_SIZE				(CFG_DDR_TEETZ_RESERVED_SIZE - \
						CFG_PUB_RAM_SIZE)

#define CFG_TA_RAM_START		(CFG_DDR_TEETZ_RESERVED_START + \
						CFG_TEE_RAM_PH_SIZE)
#define CFG_TA_RAM_SIZE			(CFG_DDR_TEETZ_RESERVED_SIZE - \
						CFG_TEE_RAM_PH_SIZE - \
						CFG_PUB_RAM_SIZE)

#define CFG_SHMEM_START			(CFG_DDR_TEETZ_RESERVED_START + \
				TZDRAM_SIZE)
#define CFG_SHMEM_SIZE			CFG_PUB_RAM_SIZE

#define CFG_TEE_RAM_START		TZDRAM_BASE

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR		TZDRAM_BASE
#endif

#endif /* CFG_WITH_PAGER */

#else
#error "Unknown platform flavor"
#endif /* defined(PLATFORM_FLAVOR_mx6ulevk) */

#endif /*PLATFORM_CONFIG_H*/
