/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 */

#ifndef PLATFORM_CONFIG_IMX6UL_H
#define PLATFORM_CONFIG_IMX6UL_H

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform mx6ulevk"
#endif
#ifdef CFG_WITH_LPAE
#error "i.MX 6UL/6ULL does not support LPAE"
#endif

#define CFG_TEE_CORE_NB_CORE		1

#define DRAM0_SIZE		CFG_DDR_SIZE
#define DDR_SIZE			DRAM0_SIZE
#define DDR_PHYS_START			DRAM0_BASE
#define CFG_DDR_START			DDR_PHYS_START

#if defined(PLATFORM_FLAVOR_mx6ul9x9evk)
#define CFG_DDR_TEETZ_RESERVED_START	0x8E000000
#endif

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
#endif
