/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2017, Socionext Inc.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* GIC */
#define GIC_BASE		0x5FE00000
#define GICD_OFFSET		0
#define GICC_OFFSET		0x80000

/* UART */
#define UART_CH			0
#define UART_BASE		0x54006800
#define CONSOLE_UART_BASE	(UART_BASE + 0x100 * UART_CH)
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	58820000

/*
 * UniPhier memory map
 *
 *  0xXXXX_XXXX
 *    Linux kernel and user space             | DRAM#0-#x | Normal memory
 *  0x8200_0000 [DRAM0_BASE]                  -           -
 *    unused                                  |           |
 *  0x81E8_0000                               |           |
 *    TA RAM: 13 MiB                          | TZDRAM    |
 *  0x8118_0000                               |           | Secure memory
 *    TEE RAM: 1 MiB (CFG_TEE_RAM_VA_SIZE)    |           |
 *  0x8108_0000 [CFG_TZDRAM_START]            -           |
 *    BL31 runtime: 512 KiB                   |           |
 *  0x8100_0000                               |           -
 *    Shared memory: 2 MiB (CFG_SHMEM_SIZE)   |           |
 *  0x80E0_0000 [CFG_SHMEM_START]             | DRAM#0    | Normal memory
 *    reserved                                |           |
 *  0x8008_0000                               |           |
 *    BL2: 512 KiB                            |           |
 *  0x8000_0000 [CFG_DRAM0_BASE]              -           -
 */

#define DRAM0_BASE		(CFG_DRAM0_BASE + CFG_DRAM0_RSV_SIZE)
#define DRAM0_SIZE		(CFG_DRAM0_SIZE - CFG_DRAM0_RSV_SIZE)

#define CFG_TEE_LOAD_ADDR	CFG_TZDRAM_START

#endif /* PLATFORM_CONFIG_H */
