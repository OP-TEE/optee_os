/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <stdint.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#if defined(PLATFORM_FLAVOR_fvp)

#define GIC_BASE		0x2c000000
#define UART0_BASE		0x1c090000
#define UART1_BASE		0x1c0a0000
#define UART2_BASE		0x1c0b0000
#define UART3_BASE		0x1c0c0000
#define TZC400_BASE		0x2a4a0000

#define IT_UART1		38

#define CONSOLE_UART_BASE	UART1_BASE
#define IT_CONSOLE_UART		IT_UART1

#elif defined(PLATFORM_FLAVOR_juno)

#define GIC_BASE		0x2c010000

/* FPGA UART0 */
#define UART0_BASE		0x1c090000
/* FPGA UART1 */
#define UART1_BASE		0x1c0a0000
/* SoC UART0 */
#define UART2_BASE		0x7ff80000
/* SoC UART1 */
#define UART3_BASE		0x7ff70000


#define UART0_CLK_IN_HZ		24000000
#define UART1_CLK_IN_HZ		24000000
#define UART2_CLK_IN_HZ		7273800
#define UART3_CLK_IN_HZ		7273800


#define IT_UART3		116

#define CONSOLE_UART_BASE	UART3_BASE
#define IT_CONSOLE_UART		IT_UART3
#define CONSOLE_UART_CLK_IN_HZ	UART3_CLK_IN_HZ

#elif defined(PLATFORM_FLAVOR_qemu_virt)

#define GIC_BASE		0x08000000
#define UART0_BASE		0x09000000
#define UART1_BASE		0x09040000
#define PCSC_BASE		0x09100000

#define IT_UART1		40
#define IT_PCSC			37

#define CONSOLE_UART_BASE	UART1_BASE
#define IT_CONSOLE_UART		IT_UART1

#elif defined(PLATFORM_FLAVOR_qemu_armv8a)

#define UART0_BASE		0x09000000
#define UART1_BASE		0x09040000

#define CONSOLE_UART_BASE	UART1_BASE

#else
#error "Unknown platform flavor"
#endif

#if defined(PLATFORM_FLAVOR_fvp)
/*
 * FVP specifics.
 */

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x7f000000

#define DRAM1_BASE		0x880000000UL
#define DRAM1_SIZE		0x180000000UL

#define TZCDRAM_BASE		0xff000000
#define TZCDRAM_SIZE		0x01000000

#ifdef CFG_WITH_PAGER

/* Emulated SRAM */
#define TZSRAM_BASE		(0x06000000)
#define TZSRAM_SIZE		CFG_CORE_TZSRAM_EMUL_SIZE

#define TZDRAM_BASE		(TZSRAM_BASE + TEE_RAM_VA_SIZE)
#define TZDRAM_SIZE		(0x02000000 - TEE_RAM_VA_SIZE)

#else /*CFG_WITH_PAGER*/

/* Location of trusted dram on the base fvp */
#define TZDRAM_BASE		0x06000000
#define TZDRAM_SIZE		0x02000000

#endif /*CFG_WITH_PAGER*/

#define TEE_SHMEM_START		(DRAM0_BASE + 0x3000000)
#define TEE_SHMEM_SIZE		0x200000

#define GICC_OFFSET		0x0
#define GICD_OFFSET		0x3000000

#elif defined(PLATFORM_FLAVOR_juno)
/*
 * Juno specifics.
 */

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x7F000000

#define DRAM1_BASE		0x880000000UL
#define DRAM1_SIZE		0x180000000UL

#ifdef CFG_WITH_PAGER

/* Emulated SRAM */
#define TZSRAM_BASE		0xFF000000
#define TZSRAM_SIZE		CFG_CORE_TZSRAM_EMUL_SIZE

#define TZDRAM_BASE		(TZSRAM_BASE + TEE_RAM_VA_SIZE)
#define TZDRAM_SIZE		(0x00E00000 - TEE_RAM_VA_SIZE)

#else /*CFG_WITH_PAGER*/
/*
 * Last part of DRAM is reserved as secure dram, note that the last 32KiB
 * of DRAM0 is used by SCP for DDR retraining.
 */
#define TZDRAM_BASE		0xFF000000
#define TZDRAM_SIZE		0x00FF8000

#endif /*CFG_WITH_PAGER*/

#define TEE_SHMEM_START		(DRAM0_BASE + DRAM0_SIZE - TEE_SHMEM_SIZE)
#define TEE_SHMEM_SIZE		0x200000

#define GICC_OFFSET		0x1f000
#define GICD_OFFSET		0

#elif defined(PLATFORM_FLAVOR_qemu_virt)
/*
 * QEMU virt specifics.
 */

#define DRAM0_BASE		UINTPTR_C(0x40000000)
#define DRAM0_SIZE		(UINTPTR_C(0x42100000) - TEE_SHMEM_SIZE)

#define DRAM0_TEERES_BASE	(DRAM0_BASE + DRAM0_SIZE)
#define DRAM0_TEERES_SIZE	TEE_SHMEM_SIZE

#define SECRAM_BASE		0x0e000000
#define SECRAM_SIZE		0x01000000
#define SECRAM_COHERENT_SIZE	4096

#ifdef CFG_WITH_PAGER

/* Emulated SRAM */
/* First 1MByte of the secure RAM is reserved to ARM-TF boot services */
#define TZSRAM_BASE		(SECRAM_BASE + 0x00100000)
#define TZSRAM_SIZE		CFG_CORE_TZSRAM_EMUL_SIZE

#define TZDRAM_BASE		(TZSRAM_BASE + TEE_RAM_VA_SIZE)
#define TZDRAM_SIZE		(SECRAM_SIZE - TEE_RAM_VA_SIZE - \
					TZSRAM_SIZE - 0x00100000)

#else /* CFG_WITH_PAGER */

#define TZDRAM_BASE		(SECRAM_BASE + 0x00100000)
#define TZDRAM_SIZE		(SECRAM_SIZE - 0x00100000)

#endif /* CFG_WITH_PAGER */

#define TEE_SHMEM_START		(DRAM0_TEERES_BASE + \
					(DRAM0_TEERES_SIZE - TEE_SHMEM_SIZE))
#define TEE_SHMEM_SIZE		0x200000

#define GICD_OFFSET		0
#define GICC_OFFSET		0x10000


#elif defined(PLATFORM_FLAVOR_qemu_armv8a)

#define DRAM0_BASE		UINTPTR_C(0x40000000)
#define DRAM0_SIZE		(UINTPTR_C(0x40000000) - TEE_SHMEM_SIZE)

#define SECRAM_BASE		0x0e000000
#define SECRAM_SIZE		0x01000000

#ifdef CFG_WITH_PAGER

/* Emulated SRAM */
/* First 1MByte of the secure RAM is reserved to ARM-TF runtime services */
#define TZSRAM_BASE		(SECRAM_BASE + 0x00100000)
#define TZSRAM_SIZE		CFG_CORE_TZSRAM_EMUL_SIZE

#define TZDRAM_BASE		(TZSRAM_BASE + TZSRAM_SIZE)
#define TZDRAM_SIZE		(SECRAM_SIZE - TZSRAM_SIZE - 0x00100000)

#else /* CFG_WITH_PAGER */

/* First 1MByte of the secure RAM is reserved to ARM-TF runtime services */
#define TZDRAM_BASE		(SECRAM_BASE + 0x00100000)
#define TZDRAM_SIZE		(SECRAM_SIZE - 0x00100000)

#endif /* CFG_WITH_PAGER */

/*
 * TEE_SHMEM_START chosen arbitrary, in a way that it does not interfere
 * with initial location of linux kernel, dtb and initrd
 */
#define TEE_SHMEM_START		(DRAM0_BASE + 0x2000000)
#define TEE_SHMEM_SIZE		0x200000

#else
#error "Unknown platform flavor"
#endif

#define TEE_RAM_VA_SIZE		(2 * 1024 * 1024)

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			CFG_TEE_LOAD_ADDR
#else
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#ifdef CFG_WITH_PAGER
/*
 * Have TZSRAM either as real physical or emulated by reserving an area
 * somewhere else.
 *
 * +------------------+
 * | TZSRAM | TEE_RAM |
 * +--------+---------+
 * | TZDRAM | TA_RAM  |
 * |        +---------+
 * |        | SDP RAM | (SDP test pool, optional)
 * +--------+---------+
 */
#define TEE_RAM_PH_SIZE		TZSRAM_SIZE
#define TEE_RAM_START		TZSRAM_BASE
#define TA_RAM_START		ROUNDUP(TZDRAM_BASE, CORE_MMU_DEVICE_SIZE)

#else
/*
 * Assumes that either TZSRAM isn't large enough or TZSRAM doesn't exist,
 * everything is in TZDRAM.
 * +------------------+
 * |        | TEE_RAM |
 * | TZDRAM +---------+
 * |        | TA_RAM  |
 * |        +---------+
 * |        | SDP RAM | (test pool, optional)
 * +--------+---------+
 */
#define TEE_RAM_PH_SIZE		TEE_RAM_VA_SIZE
#define TEE_RAM_START		TZDRAM_BASE
#define TA_RAM_START		ROUNDUP(TZDRAM_BASE + TEE_RAM_VA_SIZE, \
					CORE_MMU_DEVICE_SIZE)
#endif

#define TA_RAM_SIZE		ROUNDDOWN(TZDRAM_SIZE - \
					  (TA_RAM_START - TZDRAM_BASE) - \
					  TEE_SDP_TEST_MEM_SIZE, \
					  CORE_MMU_DEVICE_SIZE)

/* SDP enable but no pool defined: reserve 4MB for SDP tests */
#if defined(CFG_SECURE_DATA_PATH) && !defined(CFG_TEE_SDP_MEM_BASE)
#ifdef CFG_TEE_SDP_TEST_MEM_SIZE
#define TEE_SDP_TEST_MEM_SIZE	CFG_TEE_SDP_TEST_MEM_SIZE
#else
#define TEE_SDP_TEST_MEM_SIZE	0x00400000
#endif
#define TEE_SDP_TEST_MEM_BASE	(TZDRAM_BASE + TZDRAM_SIZE - \
					TEE_SDP_TEST_MEM_SIZE)
#endif
#ifndef TEE_SDP_TEST_MEM_SIZE
#define TEE_SDP_TEST_MEM_SIZE	0
#endif

#ifdef GIC_BASE
#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE		(GIC_BASE + GICC_OFFSET)
#endif

#ifndef UART_BAUDRATE
#define UART_BAUDRATE		115200
#endif
#ifndef CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE	UART_BAUDRATE
#endif

/* For virtual platforms where there isn't a clock */
#ifndef CONSOLE_UART_CLK_IN_HZ
#define CONSOLE_UART_CLK_IN_HZ	1
#endif

#endif /*PLATFORM_CONFIG_H*/
