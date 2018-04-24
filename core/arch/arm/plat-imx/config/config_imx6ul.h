/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018 Linaro Limited
 */

#ifndef __CONFIG_IMX6UL_H
#define __CONFIG_IMX6UL_H

/* For i.MX 6UltraLite and 6ULL EVK board */

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

#define TEE_SHMEM_START		(CFG_DDR_TEETZ_RESERVED_START + \
				 TZDRAM_SIZE)
/* Full GlobalPlatform test suite requires TEE_SHMEM_SIZE to be at least 2MB */
#define TEE_SHMEM_SIZE		CFG_PUB_RAM_SIZE

/*
 * Everything is in TZDRAM.
 * +------------------+
 * |        | TEE_RAM |
 * + TZDRAM +---------+
 * |        | TA_RAM  |
 * +--------+---------+
 */
#define TEE_RAM_VA_SIZE		(1024 * 1024)
#define TEE_RAM_PH_SIZE		TEE_RAM_VA_SIZE
#define TEE_RAM_START		TZDRAM_BASE
#define TA_RAM_START		ROUNDUP((TZDRAM_BASE + TEE_RAM_VA_SIZE), \
					CORE_MMU_DEVICE_SIZE)
#define TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - TEE_RAM_VA_SIZE), \
					  CORE_MMU_DEVICE_SIZE)
#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR		CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR		TEE_RAM_START
#endif

#define CONSOLE_UART_BASE	UART1_BASE

#endif /*__CONFIG_IMX6UL_H*/

