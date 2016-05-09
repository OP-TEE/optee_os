/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#define PLATFORM_FLAVOR_ID_fvp		0
#define PLATFORM_FLAVOR_ID_qemu_armv8a	1
#define PLATFORM_FLAVOR_ID_qemu_virt	2
#define PLATFORM_FLAVOR_ID_juno		3
#define PLATFORM_FLAVOR_IS(flav) \
	(PLATFORM_FLAVOR == PLATFORM_FLAVOR_ID_ ## flav)

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef ARM64
#ifdef CFG_WITH_PAGER
#error "Pager not supported for ARM64"
#endif
#endif /*ARM64*/

#if PLATFORM_FLAVOR_IS(fvp)

#define GIC_BASE		0x2c000000
#define UART0_BASE		0x1c090000
#define UART1_BASE		0x1c0a0000
#define UART2_BASE		0x1c0b0000
#define UART3_BASE		0x1c0c0000

#define IT_UART1		38

#define CONSOLE_UART_BASE	UART1_BASE
#define IT_CONSOLE_UART		IT_UART1

#elif PLATFORM_FLAVOR_IS(juno)

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

#elif PLATFORM_FLAVOR_IS(qemu_virt)

#define GIC_BASE		0x08000000
#define UART0_BASE		0x09000000
#define UART1_BASE		0x09040000
#define PCSC_BASE		0x09100000

#define IT_UART1		40
#define IT_PCSC			37

#define CONSOLE_UART_BASE	UART1_BASE
#define IT_CONSOLE_UART		IT_UART1

#elif PLATFORM_FLAVOR_IS(qemu_armv8a)

#define UART0_BASE		0x09000000
#define UART1_BASE		0x09040000

#define CONSOLE_UART_BASE	UART1_BASE

#else
#error "Unknown platform flavor"
#endif

#define HEAP_SIZE		(24 * 1024)

#if PLATFORM_FLAVOR_IS(fvp)
/*
 * FVP specifics.
 */

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x80000000

#ifdef CFG_WITH_PAGER

/* Emulated SRAM */
#define TZSRAM_BASE		(0x06000000)
#define TZSRAM_SIZE		(200 * 1024)

#define TZDRAM_BASE		(TZSRAM_BASE + CFG_TEE_RAM_VA_SIZE)
#define TZDRAM_SIZE		(0x02000000 - CFG_TEE_RAM_VA_SIZE)

#else /*CFG_WITH_PAGER*/

/* Location of trusted dram on the base fvp */
#define TZDRAM_BASE		0x06000000
#define TZDRAM_SIZE		0x02000000

#endif /*CFG_WITH_PAGER*/

#define CFG_TEE_CORE_NB_CORE	8

#define CFG_SHMEM_START		(DRAM0_BASE + 0x3000000)
#define CFG_SHMEM_SIZE		0x200000

#define GICC_OFFSET		0x0
#define GICD_OFFSET		0x3000000

#elif PLATFORM_FLAVOR_IS(juno)
/*
 * Juno specifics.
 */

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x7F000000

#ifdef CFG_WITH_PAGER

/* Emulated SRAM */
#define TZSRAM_BASE		0xFF000000
#define TZSRAM_SIZE		(200 * 1024)

#define TZDRAM_BASE		(TZSRAM_BASE + CFG_TEE_RAM_VA_SIZE)
#define TZDRAM_SIZE		(0x00E00000 - CFG_TEE_RAM_VA_SIZE)

#else /*CFG_WITH_PAGER*/
/*
 * Last part of DRAM is reserved as secure dram, note that the last 2MiB
 * of DRAM0 is used by SCP dor DDR retraining.
 */
#define TZDRAM_BASE		0xFF000000
/*
 * Should be
 * #define TZDRAM_SIZE		0x00FF8000
 * but is smaller due to SECTION_SIZE alignment, can be fixed once
 * OP-TEE OS is mapped using small pages instead.
 */
#define TZDRAM_SIZE		0x00E00000
#endif /*CFG_WITH_PAGER*/

#define CFG_TEE_CORE_NB_CORE	6

#define CFG_SHMEM_START		(DRAM0_BASE + DRAM0_SIZE - CFG_SHMEM_SIZE)
#define CFG_SHMEM_SIZE		0x200000

#define GICC_OFFSET		0x1f000
#define GICD_OFFSET		0

#elif PLATFORM_FLAVOR_IS(qemu_virt)
/*
 * QEMU virt specifics.
 */

#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		(0x40000000 - DRAM0_TEERES_SIZE)

#define DRAM0_TEERES_BASE	(DRAM0_BASE + DRAM0_SIZE)
#define DRAM0_TEERES_SIZE	(33 * 1024 * 1024)

#ifdef CFG_WITH_PAGER

/* Emulated SRAM */
#define TZSRAM_BASE		DRAM0_TEERES_BASE
#define TZSRAM_SIZE		(200 * 1024)

#define TZDRAM_BASE		(DRAM0_TEERES_BASE + CFG_TEE_RAM_VA_SIZE)
#define TZDRAM_SIZE		(DRAM0_TEERES_SIZE - CFG_TEE_RAM_VA_SIZE \
					- CFG_SHMEM_SIZE)

#else /* CFG_WITH_PAGER */

#define TZDRAM_BASE		DRAM0_TEERES_BASE
#define TZDRAM_SIZE		(DRAM0_TEERES_SIZE - CFG_SHMEM_SIZE)

#endif /* CFG_WITH_PAGER */

#define CFG_TEE_CORE_NB_CORE	2

#define CFG_SHMEM_START		(DRAM0_TEERES_BASE + \
					(DRAM0_TEERES_SIZE - CFG_SHMEM_SIZE))
#define CFG_SHMEM_SIZE		0x200000

#define GICD_OFFSET		0
#define GICC_OFFSET		0x10000


#elif PLATFORM_FLAVOR_IS(qemu_armv8a)

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform vexpress-qemu_armv8a"
#endif

#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		(0x40000000 - DRAM0_TEERES_SIZE)

#define DRAM0_TEERES_BASE	(DRAM0_BASE + DRAM0_SIZE)
#define DRAM0_TEERES_SIZE	(33 * 1024 * 1024)

#define TZDRAM_BASE		0x0e100000
#define TZDRAM_SIZE		0x00f00000

#define CFG_TEE_CORE_NB_CORE	2

#define CFG_SHMEM_START		(DRAM0_TEERES_BASE + \
					(DRAM0_TEERES_SIZE - CFG_SHMEM_SIZE))
#define CFG_SHMEM_SIZE		0x200000

#else
#error "Unknown platform flavor"
#endif

#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR	CFG_TEE_RAM_START
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
 * +--------+---------+
 */
#define CFG_TEE_RAM_PH_SIZE	TZSRAM_SIZE
#define CFG_TEE_RAM_START	TZSRAM_BASE
#define CFG_TA_RAM_START	ROUNDUP(TZDRAM_BASE, CORE_MMU_DEVICE_SIZE)
#define CFG_TA_RAM_SIZE		ROUNDDOWN(TZDRAM_SIZE, CORE_MMU_DEVICE_SIZE)
#else
/*
 * Assumes that either TZSRAM isn't large enough or TZSRAM doesn't exist,
 * everything is in TZDRAM.
 * +------------------+
 * |        | TEE_RAM |
 * + TZDRAM +---------+
 * |        | TA_RAM  |
 * +--------+---------+
 */
#define CFG_TEE_RAM_PH_SIZE	CFG_TEE_RAM_VA_SIZE
#define CFG_TEE_RAM_START	TZDRAM_BASE
#define CFG_TA_RAM_START	ROUNDUP((TZDRAM_BASE + CFG_TEE_RAM_VA_SIZE), \
					CORE_MMU_DEVICE_SIZE)
#define CFG_TA_RAM_SIZE		ROUNDDOWN((TZDRAM_SIZE - CFG_TEE_RAM_VA_SIZE), \
					  CORE_MMU_DEVICE_SIZE)
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
