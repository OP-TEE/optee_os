/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#ifndef CFG_UART_BASE
#define CFG_UART_BASE	(UART1_BASE)
#endif

#ifndef CFG_DDR_SIZE
#error "CFG_DDR_SIZE not defined"
#endif

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		CFG_DDR_SIZE

#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)

/*
 * Everything is in TZDRAM.
 * +------------------+
 * |        | TEE_RAM |
 * + TZDRAM +---------+
 * |        | TA_RAM  |
 * +--------+---------+
 */
#define CFG_TEE_RAM_PH_SIZE     CFG_TEE_RAM_VA_SIZE
#define CFG_TEE_RAM_START	CFG_TZDRAM_BASE
#define TA_RAM_START		ROUNDUP((CFG_TZDRAM_BASE + \
					CFG_TEE_RAM_VA_SIZE), \
					CORE_MMU_DEVICE_SIZE)
#define TA_RAM_SIZE		ROUNDDOWN((CFG_TZDRAM_SIZE - \
					  CFG_TEE_RAM_VA_SIZE), \
					  CORE_MMU_DEVICE_SIZE)

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR	CFG_TEE_RAM_START
#endif

#define CONSOLE_UART_BASE	(CFG_UART_BASE)
