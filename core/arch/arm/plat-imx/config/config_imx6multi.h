/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#ifndef __CONFIG_IMX6MULTI_H
#define __CONFIG_IMX6MULTI_H

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

#define TZDRAM_BASE			(CFG_DDR_TEETZ_RESERVED_START)
#define TZDRAM_SIZE			(CFG_DDR_TEETZ_RESERVED_SIZE - \
						TEE_SHMEM_SIZE)

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
 *  SHM_RAM : default 2MByte
 */

/* emulated SRAM, at start of secure DDR */

#define TZSRAM_BASE			CFG_CORE_TZSRAM_EMUL_START
#define TZSRAM_SIZE			CFG_CORE_TZSRAM_EMUL_SIZE

/* Location of trusted dram */
#define TEE_RAM_START			TZSRAM_BASE
#define TEE_RAM_VA_SIZE			(1 * 1024 * 1024)
#define TEE_RAM_PH_SIZE			TZSRAM_SIZE

#define TA_RAM_START			TZDRAM_BASE
#define TA_RAM_SIZE			TZDRAM_SIZE

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
 *  SHM_RAM : default 2MByte
 *  TA_RAM  : all what is left
 */

#define TEE_RAM_START			TZDRAM_BASE
#define TEE_RAM_VA_SIZE			(1 * 1024 * 1024)
#define TEE_RAM_PH_SIZE			TEE_RAM_VA_SIZE

#define TA_RAM_START			(TZDRAM_BASE + TEE_RAM_PH_SIZE)
#define TA_RAM_SIZE			(TZDRAM_SIZE - TEE_RAM_PH_SIZE)

#endif /* CFG_WITH_PAGER */

#define TEE_SHMEM_START			(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE			CFG_SHMEM_SIZE

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#endif /*__CONFIG_IMX6MULTI_H*/
