/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */

#ifndef PLATFORM_CONFIG_IMX6SLL_H
#define PLATFORM_CONFIG_IMX6SLL_H

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform mx6sllevk"
#endif

#ifndef CFG_DDR_SIZE
#error "CFG_DDR_SIZE not defined"
#endif

#define DRAM0_SIZE		CFG_DDR_SIZE

#define CFG_PUB_RAM_SIZE	(2 * 1024 * 1024)

/* Location of trusted dram */
#define TZDRAM_BASE		(DRAM0_BASE - 32 * 1024 * 1024 + CFG_DDR_SIZE)
#define TZDRAM_SIZE		(30 * 1024 * 1024)

#define CFG_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)

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
#define PL310_AUX_CTRL_INIT		0x3C430800
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

#endif /* PLATFORM_CONFIG_IMX6SLL_H */
