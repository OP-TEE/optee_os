/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025-2026, Renesas Electronics Corporation.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#define RCAR_CACHE_LINE_SZ		64

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			RCAR_CACHE_LINE_SZ

#if defined(CFG_RCAR_GEN5)
#define GICD_BASE			0x39000000
#define GICR_BASE			0x39080000

#define CONSOLE_UART_BASE		0xC0710000
/* Config for MMU mapping */
#define RCAR_SRAM_BASE			CFG_TZDRAM_START
#define TZDRAM_BASE			RCAR_SRAM_BASE
#define TZDRAM_SIZE			0x02000000U	/* 32*1024*1024 */

/* TEE RAM address and size */
#define TEE_RAM_START			RCAR_SRAM_BASE
#define TEE_RAM_SIZE			0x00300000U

#ifdef CFG_TEE_RAM_VA_SIZE
#define TEE_RAM_PH_SIZE			TEE_RAM_SIZE
#endif

#ifndef TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

/* TA RAM address and size */
#define TA_RAM_START			(TEE_RAM_START + TEE_RAM_SIZE)
#define TA_RAM_SIZE			0x01400000U

/* OP-TEE Log Area address and size */
#define OPTEE_LOG_BASE			(TA_RAM_START + TA_RAM_SIZE)
#define OPTEE_LOG_SIZE			0x900000U

/* Non Cache Area address and size */
#define NONCACHE_WORK_BASE		(OPTEE_LOG_BASE + OPTEE_LOG_SIZE)
#define NONCACHE_WORK_SIZE		0x00100000U

/* Shared Memory address and size */
#define TEE_SHMEM_START			(NONCACHE_WORK_BASE + 0x1D00000U)
#define TEE_SHMEM_SIZE			0x00100000U

/* For Soc Register mapping function */
#define MAP_DEV_REG_RCAR_BASE		0xC0400000
#define MAP_DEV_REG_RCAR_SIZE		0x1FC00000

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES	CFG_MMAP_REGIONS
#endif

#endif /* CFG_RCAR_GEN5 */

#endif /* PLATFORM_CONFIG_H */
