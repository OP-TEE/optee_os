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

#include <imx-regs.h>

#define STACK_ALIGNMENT			64

/* For i.MX7D/S platforms */
#if defined(CFG_MX7)
#include <config/config_imx7.h>

/* For i.MX 6UltraLite and 6ULL EVK board */
#elif defined(CFG_MX6UL) || defined(CFG_MX6ULL)
#include <imx-regs.h>

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform mx6ulevk"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported for now"
#endif


#define CFG_TEE_CORE_NB_CORE		1

#define DDR_PHYS_START			DRAM0_BASE
#define DDR_SIZE			DRAM0_SIZE

#define CFG_DDR_START			DDR_PHYS_START
#define CFG_DDR_SIZE			DDR_SIZE

#ifndef CFG_DDR_TEETZ_RESERVED_START
#define CFG_DDR_TEETZ_RESERVED_START	0x9E000000
#endif

#define CFG_DDR_TEETZ_RESERVED_SIZE	0x02000000

#define CFG_PUB_RAM_SIZE	(2 * 1024 * 1024)

#define TZDRAM_BASE		(CFG_DDR_TEETZ_RESERVED_START)
#define TZDRAM_SIZE		(CFG_DDR_TEETZ_RESERVED_SIZE - \
				 CFG_PUB_RAM_SIZE)

#define CFG_SHMEM_START		(CFG_DDR_TEETZ_RESERVED_START + \
				 TZDRAM_SIZE)
/* Full GlobalPlatform test suite requires CFG_SHMEM_SIZE to be at least 2MB */
#define CFG_SHMEM_SIZE		CFG_PUB_RAM_SIZE

/*
 * Everything is in TZDRAM.
 * +------------------+
 * |        | TEE_RAM |
 * + TZDRAM +---------+
 * |        | TA_RAM  |
 * +--------+---------+
 */
#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)
#define CFG_TEE_RAM_PH_SIZE	CFG_TEE_RAM_VA_SIZE
#define CFG_TEE_RAM_START	TZDRAM_BASE
#define CFG_TA_RAM_START	ROUNDUP((TZDRAM_BASE + CFG_TEE_RAM_VA_SIZE), \
					CORE_MMU_DEVICE_SIZE)
#define CFG_TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - CFG_TEE_RAM_VA_SIZE), \
					  CORE_MMU_DEVICE_SIZE)
#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR	CFG_TEE_RAM_START
#endif


#define CONSOLE_UART_BASE	(UART1_BASE)

/* For i.MX6 Quad SABRE Lite and Smart Device board */

#elif defined(CFG_MX6Q) || defined(CFG_MX6D) || defined(CFG_MX6DL) || \
	defined(CFG_MX6S)

#include <imx-regs.h>

/* Board specific console UART */
#if defined(PLATFORM_FLAVOR_mx6qsabrelite)
#define CONSOLE_UART_BASE		UART2_BASE
#endif
#if defined(PLATFORM_FLAVOR_mx6qsabresd)
#define CONSOLE_UART_BASE		UART1_BASE
#endif
#if defined(PLATFORM_FLAVOR_mx6dlsabresd)
#define CONSOLE_UART_BASE		UART1_BASE
#endif

/* Board specific RAM size */
#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd) || \
	defined(PLATFORM_FLAVOR_mx6dlsabresd)
#define DRAM0_SIZE			0x40000000
#endif

/* Core number depends of SoC version. */
#if defined(CFG_MX6Q)
#define CFG_TEE_CORE_NB_CORE		4
#endif
#if defined(CFG_MX6D) || defined(CFG_MX6DL)
#define CFG_TEE_CORE_NB_CORE		2
#endif
#if defined(CFG_MX6S)
#define CFG_TEE_CORE_NB_CORE		1
#endif

/* Common RAM and cache controller configuration */
#define CFG_TEE_RAM_VA_SIZE		(1024 * 1024)

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
 * Platform fmavor specific way config (dual / quad):
 * - 64kb way size (bit19:17=3b011)
 * - 16-way associciativity (bit16=1)
 * Platform fmavor specific way config (dual lite / solo):
 * - 32kb way size (bit19:17=3b010)
 * - no 16-way associciativity (bit16=0)
 * Store buffer device limitation enabled (bit11=1)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) disabled (bit0=0)
 */
#ifndef PL310_AUX_CTRL_INIT
#if defined(CFG_MX6Q) || defined(CFG_MX6D)
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

#endif /* CFG_WITH_PAGER */

#define CFG_SHMEM_START			(CFG_DDR_TEETZ_RESERVED_START + \
					 TZDRAM_SIZE)
#define CFG_SHMEM_SIZE			CFG_PUB_RAM_SIZE

#define CFG_TEE_RAM_START		TZDRAM_BASE

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR		TZDRAM_BASE
#endif

#else
#error "Unknown platform flavor"
#endif

#endif /*PLATFORM_CONFIG_H*/
