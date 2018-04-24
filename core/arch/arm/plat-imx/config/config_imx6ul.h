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

#define CONSOLE_UART_BASE	UART1_BASE

#define TZDRAM_BASE		(CFG_DDR_TEETZ_RESERVED_START)
#define TZDRAM_SIZE		(CFG_DDR_TEETZ_RESERVED_SIZE - \
					TEE_SHMEM_SIZE)

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x00200000

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

#endif /*__CONFIG_IMX6UL_H*/

