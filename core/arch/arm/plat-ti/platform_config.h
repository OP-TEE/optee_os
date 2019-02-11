/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#define DRAM0_BASE      0x80000000
#define DRAM0_SIZE      0x80000000

#if defined(PLATFORM_FLAVOR_dra7xx) || defined(PLATFORM_FLAVOR_am57xx)

/* Location of protected DDR on the DRA7xx platform */
#define TZDRAM_BASE     0xbdb00000
#define TZDRAM_SIZE     0x01c00000

#ifdef CFG_WITH_PAGER
#define TZSRAM_BASE     0x40300000
#define TZSRAM_SIZE     (256 * 1024)
#endif /* CFG_WITH_PAGER */


#define UART1_BASE      0x4806A000
#define UART2_BASE      0x4806C000
#define UART3_BASE      0x48020000

#if defined(PLATFORM_FLAVOR_dra7xx)
#define CONSOLE_UART_BASE       UART1_BASE
#elif defined(PLATFORM_FLAVOR_am57xx)
#define CONSOLE_UART_BASE       UART3_BASE
#else
#error "Unknown platform flavor"
#endif

#define CONSOLE_BAUDRATE        115200
#define CONSOLE_UART_CLK_IN_HZ	48000000

#define SCU_BASE        0x48210000
#define GICC_OFFSET     0x2000
#define GICC_SIZE       0x1000
#define GICD_OFFSET     0x1000
#define GICD_SIZE       0x1000
#define GICC_BASE       (SCU_BASE + GICC_OFFSET)
#define GICD_BASE       (SCU_BASE + GICD_OFFSET)

#define SECRAM_BASE     0x40200000
#define SECRAM_SIZE     0x00100000

/* RNG */
#define RNG_BASE        0x48090000

#elif defined(PLATFORM_FLAVOR_am43xx)

/* Location of protected DDR on the AM43xx platform */
#define TZDRAM_BASE     0xbdb00000
#define TZDRAM_SIZE     0x01c00000

#define UART0_BASE      0x44E09000
#define UART1_BASE      0x48022000
#define UART2_BASE      0x48024000
#define UART3_BASE      0x481A6000
#define UART4_BASE      0x481A8000
#define UART5_BASE      0x481AA000

#define CONSOLE_UART_BASE       UART0_BASE
#define CONSOLE_BAUDRATE        115200
#define CONSOLE_UART_CLK_IN_HZ	48000000

#define SCU_BASE        0x48240000
#define GICD_OFFSET     0x1000
#define GICD_SIZE       0x1000
#define GICC_OFFSET     0x0100
#define GICC_SIZE       0x0100
#define PL310_OFFSET    0x2000
#define PL310_SIZE      0x1000
#define GICD_BASE       (SCU_BASE + GICD_OFFSET)
#define GICC_BASE       (SCU_BASE + GICC_OFFSET)
#define PL310_BASE      (SCU_BASE + PL310_OFFSET)

#define SECRAM_BASE     0x402F0000
#define SECRAM_SIZE     0x00100000

/* RNG */
#define RNG_BASE        0x48310000

#else
#error "Unknown platform flavor"
#endif

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef CFG_WITH_PAGER
/*
 * Use TZSRAM for TEE, page out everything else to TZDRAM.
 * +--------+----------+
 * |  DRAM  |  SHMEM   |
 * +--------+----------+
 * |        | TA_RAM   |
 * | TZDRAM +----------+
 * |        | PAGE_RAM |
 * +--------+----------+
 * | TZSRAM | TEE_RAM  |
 * +--------+----------+
 */
#define TEE_RAM_VA_SIZE		(1 * 1024 * 1024)
#define TEE_RAM_PH_SIZE		TZSRAM_SIZE
#define TEE_RAM_START		TZSRAM_BASE
#define TEE_LOAD_ADDR		(TEE_RAM_START + 0x1000)

#else /* CFG_WITH_PAGER */
/*
 * Assumes that either TZSRAM isn't large enough or TZSRAM doesn't exist,
 * everything is in TZDRAM.
 * +--------+---------+
 * |  DRAM  |  SHMEM  |
 * +--------+---------+
 * |        | TA_RAM  |
 * | TZDRAM +---------+
 * |        | TEE_RAM |
 * +--------+---------+
 */
#define TEE_RAM_VA_SIZE		(1 * 1024 * 1024)
#define TEE_RAM_PH_SIZE		TEE_RAM_VA_SIZE
#define TEE_RAM_START		TZDRAM_BASE
#define TEE_LOAD_ADDR		TEE_RAM_START

#endif /* CFG_WITH_PAGER */

#ifdef CFG_SECURE_DATA_PATH
/* SDP memory at end of TZDRAM (config directives set CFG_TEE_SDP_MEM_SIZE) */
#define TEE_SDP_TEST_MEM_BASE	(TZDRAM_BASE + TZDRAM_SIZE - \
					CFG_TEE_SDP_MEM_SIZE)
#define TEE_SDP_TEST_MEM_SIZE	CFG_TEE_SDP_MEM_SIZE
#else
#define TEE_SDP_TEST_MEM_SIZE	0
#endif /*CFG_SECURE_DATA_PATH*/

#define TA_RAM_START		ROUNDUP((TZDRAM_BASE + TEE_RAM_VA_SIZE), \
					CORE_MMU_PGDIR_SIZE)

#define TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - TEE_RAM_VA_SIZE) - \
					  TEE_SDP_TEST_MEM_SIZE, \
					  CORE_MMU_PGDIR_SIZE)

/* Full GlobalPlatform test suite requires TEE_SHMEM_SIZE to be at least 2MB */
#define TEE_SHMEM_START         (TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE          (4 * 1024 * 1024)

#endif /*PLATFORM_CONFIG_H*/
