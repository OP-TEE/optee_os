/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <hi3798cv200.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* PL011 UART */
#define CONSOLE_UART_BASE	PL011_UART0_BASE
#define CONSOLE_BAUDRATE	PL011_BAUDRATE
#define CONSOLE_UART_CLK_IN_HZ	PL011_UART0_CLK_IN_HZ

/*
 * Poplar memory map
 *
 * Note: the physical address ranges below correspond to DRAM which is
 * non-secure by default. Therefore, the terms TZDRAM and TZSRAM may not
 * reflect the reality and only indicate areas that "would normally be"
 * secure DRAM and secure SRAM in a more complete implementation.
 * The memory map was defined like this for lack of better documentation.
 * It is good enough for development/testing purposes.
 *
 *  0xFF00_0000 [DRAM2_LIMIT]
 *    other (devmem)
 *  0xF000_0000 [DRAM2_BASE]
 *
 *  0x8000_0000 (0x4000_0000 for 1GB board) [DRAM0_LIMIT]
 *    u-boot + ree memory: 1144 MiB (144 MiB for 1GB board)
 *  0x3700_0000 CONFIG_SYS_TEXT_BASE (u-boot)
 *		PLAT_POPLAR_NS_IMAGE_OFFSET (arm-tf)
 *    ramdisk: 76 MiB
 *  0x3240_0000
 *    fdt: 2 MiB
 *  0x3220_0000
 *    pxe file or script addr: 2 MiB
 *  0x3200_0000
 *    kernel/android: 32 MiB
 *  0x3000_0000
 *    ree memory: 696 MiB
 *  0x0480_0000 CONFIG_SYS_LOAD_ADDR (defined in u-boot)
 *    other: 6 MiB
 *  0x0420_0000 CONFIG_SYS_INIT_SP_ADDR (defined in u-boot)
 *  0x0408_0000 KERNEL_TEXT_OFFSET (defined in u-boot)
 *    unused: 512 KiB
 *  0x0400_0000
 *
 *  0x0400_0000                                  -
 *    TA RAM: 14 MiB                             | TZDRAM
 *  0x0320_0000                                  -
 *
 * CFG_WITH_PAGER=n                              -
 *    TEE RAM: 2 MiB (TEE_RAM_VA_SIZE)           | TZDRAM
 *  0x0300_0000 [TZDRAM_BASE, TEE_LOAD_ADDR]     -
 *
 * CFG_WITH_PAGER=y
 *    Unused
 *  0x030A_0000                                  -
 *    TEE RAM: 640 KiB (TZSRAM_SIZE)             | TZSRAM
 *  0x0300_0000 [TZSRAM_BASE, TEE_LOAD_ADDR]     -
 *
 *  0x0300_0000 [TZDRAM_BASE, TZSRAM_BASE, TEE_LOAD_ADDR]
 *    OP-TEE Future Use: 4 MiB
 *  0x02C0_0000
 *
 *  0x02C0_0000
 *    Secure Data Path buffers: 4 MiB
 *  0x0280_0000 [CFG_TEE_SDP_MEM_BASE]
 *    Shared memory: 4 MiB
 *  0x0240_0000
 *    OP-TEE Future Use: 2 MiB
 *  0x0220_0000
 *
 *  0x0220_0000
 *    unused: 64 KiB
 *  0x021F_0000 l-loader limit (len/size set by poplar-l-loader.git)
 *    unused (cannot be used)
 *  0x0210_0000 l-loader limit (max bootrom can accept)
 *    fip.bin load zone: 768 KiB
 *  0x0204_0000
 *    bl31: 80 KiB
 *  0x0202_A000
 *    bl2: 48 KiB
 *  0x0201_E000
 *    bl1: 64 KiB
 *  0x0200_E000
 *    l-loader text: 52 KiB
 *  0x0200_1000
 *    unused
 *  0x0200_0000
 *    TA virtual memory space
 *  0x0000_0000 [DRAM0_BASE]
 */
#define DRAM0_BASE		0x00000000
#if (CFG_DRAM_SIZE_GB == 2)
#define DRAM0_SIZE		0x80000000
#elif (CFG_DRAM_SIZE_GB == 1)
#define DRAM0_SIZE		0x40000000
#else
#error Unsupported DRAM size
#endif

#define DRAM0_BASE_NSEC	0x04080000
#define DRAM0_SIZE_NSEC	(DRAM0_SIZE - DRAM0_BASE_NSEC)

#define DRAM2_BASE		0xF0000000
#define DRAM2_SIZE		0x0F000000

#ifdef CFG_WITH_PAGER

#define TZSRAM_BASE		0x03000000
#define TZSRAM_SIZE		CFG_CORE_TZSRAM_EMUL_SIZE

#define TZDRAM_BASE		0x03200000
#define TZDRAM_SIZE		(14 * 1024 * 1024)

#define TEE_RAM_START		TZSRAM_BASE
#define TEE_RAM_PH_SIZE		TZSRAM_SIZE
#define TA_RAM_START		ROUNDUP(TZDRAM_BASE, CORE_MMU_PGDIR_SIZE)
#define TA_RAM_SIZE		ROUNDDOWN(TZDRAM_SIZE, CORE_MMU_PGDIR_SIZE)

#else /* CFG_WITH_PAGER */

#define TZDRAM_BASE		0x03000000
#define TZDRAM_SIZE		(16 * 1024 * 1024)

#define TEE_RAM_START		TZDRAM_BASE
#define TEE_RAM_PH_SIZE		TEE_RAM_VA_SIZE
#define TA_RAM_START		ROUNDUP((TZDRAM_BASE + TEE_RAM_VA_SIZE), \
					CORE_MMU_PGDIR_SIZE)

#define TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - TEE_RAM_VA_SIZE),\
					CORE_MMU_PGDIR_SIZE)

#endif /* CFG_WITH_PAGER */

#define TEE_SHMEM_START		0x02400000
#define TEE_SHMEM_SIZE		(4 * 1024 * 1024)

#define TEE_RAM_VA_SIZE		(2 * 1024 * 1024)

#define TEE_LOAD_ADDR		0x03000000 /* BL32_BASE */

#endif /* PLATFORM_CONFIG_H */
