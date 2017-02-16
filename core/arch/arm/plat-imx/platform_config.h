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

#define DDR_PHYS_START			DRAM0_BASE
#define DDR_SIZE			DRAM0_SIZE

#define CFG_DDR_START			DDR_PHYS_START
#define CFG_DDR_SIZE			DDR_SIZE

/* Full GlobalPlatform test suite requires CFG_SHMEM_SIZE to be at least 2MB */
#define CFG_SHMEM_START			(TZDRAM_BASE - 0x100000)
#define CFG_SHMEM_SIZE			0x100000

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

#define CONSOLE_UART_BASE		(UART0_BASE)

/* Central Security Unit register values */
#define CSU_BASE			0x021C0000
#define CSU_CSL_START			0x0
#define CSU_CSL_END			0xA0
#define CSU_ACCESS_ALL			0x00FF00FF
#define CSU_SETTING_LOCK		0x01000100

/* For i.MX6 Quad SABRE Lite and Smart Device board */

#elif defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd) || \
	defined(PLATFORM_FLAVOR_mx6dlsabresd)

#define SCU_BASE			0x00A00000
#define PL310_BASE			0x00A02000
#define SRC_BASE			0x020D8000
#define SRC_SCR				0x000
#define SRC_GPR1			0x020
#define SRC_SCR_CPU_ENABLE_ALL		SHIFT_U32(0x7, 22)
#define SRC_SCR_CORE1_RST_OFFSET	14
#define SRC_SCR_CORE1_ENABLE_OFFSET	22
#define GIC_BASE			0x00A00000
#define GICC_OFFSET			0x100
#define GICD_OFFSET			0x1000
#define GIC_CPU_BASE			(GIC_BASE + GICC_OFFSET)
#define GIC_DIST_BASE			(GIC_BASE + GICD_OFFSET)

#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)
#define UART1_BASE			0x02020000
#define UART2_BASE			0x021E8000
#else
#define UART1_BASE			0x02020000
#define UART3_BASE			0x021EC000
#define UART5_BASE			0x021F4000
#endif

/* Central Security Unit register values */
#define CSU_BASE			0x021C0000
#define CSU_CSL_START			0x0
#define CSU_CSL_END			0xA0
#define CSU_CSL5			0x14
#define CSU_CSL16			0x40
#define	CSU_ACCESS_ALL			0x00FF00FF
#define CSU_SETTING_LOCK		0x01000100

#if defined(PLATFORM_FLAVOR_mx6qsabrelite)
#define CONSOLE_UART_BASE		UART2_BASE
#endif
#if defined(PLATFORM_FLAVOR_mx6qsabresd)
#define CONSOLE_UART_BASE		UART1_BASE
#endif
#if defined(PLATFORM_FLAVOR_mx6dlsabresd)
#define CONSOLE_UART_BASE		UART1_BASE
#endif
#define DRAM0_BASE			0x10000000
#define DRAM0_SIZE			0x40000000

#define CFG_TEE_RAM_VA_SIZE		(1024 * 1024)

#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)
#define CFG_TEE_CORE_NB_CORE		4
#else
#define CFG_TEE_CORE_NB_CORE		2
#endif

#define DDR_PHYS_START			DRAM0_BASE
#define DDR_SIZE			DRAM0_SIZE

#define CFG_DDR_START			DDR_PHYS_START
#define CFG_DDR_SIZE			DDR_SIZE

/*
 * PL310 TAG RAM Control Register
 *
 * bit[10:8]:1 - 2 cycle of write accesses latency
 * bit[6:4]:1 - 2 cycle of read accesses latency
 * bit[2:0]:1 - 2 cycle of setup latency
 */
#ifndef PL310_TAG_RAM_CTRL_INIT
#define PL310_TAG_RAM_CTRL_INIT		0x00000111
#endif

/*
 * PL310 DATA RAM Control Register
 *
 * bit[10:8]:2 - 3 cycle of write accesses latency
 * bit[6:4]:2 - 3 cycle of read accesses latency
 * bit[2:0]:2 - 3 cycle of setup latency
 */
#ifndef PL310_DATA_RAM_CTRL_INIT
#define PL310_DATA_RAM_CTRL_INIT	0x00000222
#endif

/*
 * PL310 Auxiliary Control Register
 *
 * I/Dcache prefetch enabled (bit29:28=2b11)
 * NS can access interrupts (bit27=1)
 * NS can lockown cache lines (bit26=1)
 * Pseudo-random replacement policy (bit25=0)
 * Force write allocated (default)
 * Shared attribute internally ignored (bit22=1, bit13=0)
 * Parity disabled (bit21=0)
 * Event monitor disabled (bit20=0)
 * Platform fmavor specific way config:
 * - 64kb way size (bit19:17=3b011)
 * - 16-way associciativity (bit16=1)
 * Store buffer device limitation enabled (bit11=1)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) disabled (bit0=0)
 */
#ifndef PL310_AUX_CTRL_INIT
#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)
#define PL310_AUX_CTRL_INIT		0x3C470800
#else
#define PL310_AUX_CTRL_INIT		0x3C440800
#endif
#endif

/*
 * PL310 Prefetch Control Register
 *
 * Double linefill disabled (bit30=0)
 * I/D prefetch enabled (bit29:28=2b11)
 * Prefetch drop enabled (bit24=1)
 * Incr double linefill disable (bit23=0)
 * Prefetch offset = 7 (bit4:0)
 */
#define PL310_PREFETCH_CTRL_INIT	0x31000007

/*
 * PL310 Power Register
 *
 * Dynamic clock gating enabled
 * Standby mode enabled
 */
#define PL310_POWER_CTRL_INIT		0x00000003

/*
 * SCU Invalidate Register
 *
 * Invalidate all registers
 */
#define	SCU_INV_CTRL_INIT		0xFFFFFFFF

/*
 * SCU Access Register
 * - both secure CPU access SCU
 */
#define SCU_SAC_CTRL_INIT		0x0000000F

/*
 * SCU NonSecure Access Register
 * - both nonsec cpu access SCU, private and global timer
 */
#define SCU_NSAC_CTRL_INIT		0x00000FFF

/* define the memory areas */

#ifdef CFG_WITH_PAGER

/*
 * TEE/TZ RAM layout:
 *
 *  +---------------------------------------+  <- CFG_CORE_TZSRAM_EMUL_START
 *  | TEE private highly | TEE_RAM          |   ^
 *  |   secure memory    |                  |   | CFG_CORE_TZSRAM_EMUL_SIZE
 *  +---------------------------------------+   v
 *
 *  +---------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEE private secure |  TA_RAM          |   ^
 *  |   external memory  |                  |   |
 *  +---------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  |     Non secure     |  SHM             |   |
 *  |   shared memory    |                  |   |
 *  +---------------------------------------+   v
 *
 *  TEE_RAM : default 256kByte
 *  TA_RAM  : all what is left in DDR TEE reserved area
 *  PUB_RAM : default 2MByte
 */

/* emulated SRAM, at start of secure DDR */

#define CFG_CORE_TZSRAM_EMUL_START	0x4E000000

#define TZSRAM_BASE			CFG_CORE_TZSRAM_EMUL_START
#define TZSRAM_SIZE			CFG_CORE_TZSRAM_EMUL_SIZE

/* Location of trusted dram */

#define CFG_DDR_TEETZ_RESERVED_START	0x4E100000
#define CFG_DDR_TEETZ_RESERVED_SIZE	0x01F00000

#define CFG_PUB_RAM_SIZE		(1 * 1024 * 1024)
#define CFG_TEE_RAM_PH_SIZE		TZSRAM_SIZE

#define TZDRAM_BASE			(CFG_DDR_TEETZ_RESERVED_START)
#define TZDRAM_SIZE			(CFG_DDR_TEETZ_RESERVED_SIZE - \
				CFG_PUB_RAM_SIZE)

#define CFG_TA_RAM_START		TZDRAM_BASE
#define CFG_TA_RAM_SIZE			TZDRAM_SIZE

#define CFG_SHMEM_START			(CFG_DDR_TEETZ_RESERVED_START + \
						TZDRAM_SIZE)
#define CFG_SHMEM_SIZE			CFG_PUB_RAM_SIZE

#define CFG_TEE_RAM_START		TZSRAM_BASE

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR		TZSRAM_BASE
#endif

#else /* CFG_WITH_PAGER */

/*
 * TEE/TZ RAM layout:
 *
 *  +---------------------------------------+  <- CFG_DDR_TEETZ_RESERVED_START
 *  | TEE private secure |  TEE_RAM         |   ^
 *  |   external memory  +------------------+   |
 *  |                    |  TA_RAM          |   |
 *  +---------------------------------------+   | CFG_DDR_TEETZ_RESERVED_SIZE
 *  |     Non secure     |  SHM             |   |
 *  |   shared memory    |                  |   |
 *  +---------------------------------------+   v
 *
 *  TEE_RAM : default 1MByte
 *  PUB_RAM : default 2MByte
 *  TA_RAM  : all what is left
 */

#define CFG_DDR_TEETZ_RESERVED_START	0x4E000000
#define CFG_DDR_TEETZ_RESERVED_SIZE	0x02000000

#define CFG_PUB_RAM_SIZE		(1 * 1024 * 1024)
#define CFG_TEE_RAM_PH_SIZE		(1 * 1024 * 1024)

#define TZDRAM_BASE			(CFG_DDR_TEETZ_RESERVED_START)
#define TZDRAM_SIZE			(CFG_DDR_TEETZ_RESERVED_SIZE - \
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

#ifdef CFG_PL310
/*
 * PL310 TAG RAM Control Register
 *
 * bit[10:8]:1 - 2 cycle of write accesses latency
 * bit[6:4]:1 - 2 cycle of read accesses latency
 * bit[2:0]:1 - 2 cycle of setup latency
 */
#define PL310_TAG_RAM_CTRL_INIT		0x00000111

/*
 * DATA RAM Control Register
 *
 * bit[10:8]:2 - 3 cycle of write accesses latency
 * bit[6:4]:2 - 3 cycle of read accesses latency
 * bit[2:0]:2 - 3 cycle of setup latency
 */
#define PL310_DATA_RAM_CTRL_INIT	0x00000222

/*
 * Auxiliary Control Register
 *
 * I/Dcache prefetch enabled (bit29:28=2b11)
 * NS can access interrupts (bit27=1)
 * NS can lockown cache lines (bit26=1)
 * Pseudo-random replacement policy (bit25=0)
 * Force write allocated (default)
 * Shared attribute internally ignored (bit22=1, bit13=0)
 * Parity disabled (bit21=0)
 * Event monitor disabled (bit20=0)
 * 64kB ways, 16-way associativity (bit19:17=3b011 bit16=1)
 * Store buffer device limitation enabled (bit11=1)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) disabled (bit0=0)
 */
#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)
#define PL310_AUX_CTRL_INIT		0x3C470800
#else
#define PL310_AUX_CTRL_INIT		0x3C440800
#endif

/*
 * Prefetch Control Register
 *
 * Double linefill disabled (bit30=0)
 * I/D prefetch enabled (bit29:28=2b11)
 * Prefetch drop enabled (bit24=1)
 * Incr double linefill disable (bit23=0)
 * Prefetch offset = 7 (bit4:0)
 */
#define PL310_PREFETCH_CTRL_INIT	0x31000007

/*
 * Power Register = 0x00000003
 *
 * Dynamic clock gating enabled
 * Standby mode enabled
 */
#define PL310_POWER_CTRL_INIT		0x00000003

#endif

#endif /*PLATFORM_CONFIG_H*/
