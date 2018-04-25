/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef ARM64
#ifdef CFG_WITH_PAGER
#error "Pager not supported for ARM64"
#endif
#endif /*ARM64*/

#if defined(PLATFORM_FLAVOR_mt8173)

#define GIC_BASE		0x10220000
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000

#define UART0_BASE		0x11002000
#define UART1_BASE		0x11003000
#define UART2_BASE		0x11004000
#define UART3_BASE		0x11005000

#define CONSOLE_UART_BASE	UART0_BASE
#define CONSOLE_BAUDRATE	921600
#define CONSOLE_UART_CLK_IN_HZ	26000000

#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		0x80000000

/* Location of trusted dram */
#define TZDRAM_BASE		0xBE000000
#define TZDRAM_SIZE		0x02000000

/* Full GlobalPlatform test suite requires TEE_SHMEM_SIZE to be at least 2MB */
#define TEE_SHMEM_START		(TZDRAM_BASE - 0x200000)
#define TEE_SHMEM_SIZE		0x200000

#else
#error "Unknown platform flavor"
#endif

#define TEE_RAM_VA_SIZE		(1024 * 1024)

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

/*
 * Everything is in TZDRAM.
 * +------------------+
 * |        | TEE_RAM |
 * + TZDRAM +---------+
 * |        | TA_RAM  |
 * +--------+---------+
 */
#define TEE_RAM_PH_SIZE		TEE_RAM_VA_SIZE
#define TEE_RAM_START		TZDRAM_BASE
#define TA_RAM_START		ROUNDUP((TZDRAM_BASE + TEE_RAM_VA_SIZE), \
					CORE_MMU_DEVICE_SIZE)
#define TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - TEE_RAM_VA_SIZE), \
					  CORE_MMU_DEVICE_SIZE)

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES		5
#endif

#endif /*PLATFORM_CONFIG_H*/
