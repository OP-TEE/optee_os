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
#define PLATFORM_FLAVOR_ID_qemu		1
#define PLATFORM_FLAVOR_ID_qemu_virt	2
#define PLATFORM_FLAVOR_ID_juno		3
#define PLATFORM_FLAVOR_IS(flav) \
	(PLATFORM_FLAVOR == PLATFORM_FLAVOR_ID_ ## flav)

#define STACK_ALIGNMENT		8

#define PLATFORM_LINKER_FORMAT	"elf32-littlearm"
#define PLATFORM_LINKER_ARCH	arm

#if PLATFORM_FLAVOR_IS(fvp) || PLATFORM_FLAVOR_IS(qemu)

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
#define UART1_BASE		0x09010000

#define IT_UART1		34

#define CONSOLE_UART_BASE	UART1_BASE
#define IT_CONSOLE_UART		IT_UART1

#else
#error "Unknown platform flavor"
#endif

#define STACK_TMP_SIZE		1024
#if CFG_TRACE_LEVEL > 0
#define STACK_ABT_SIZE		2048
#else
#define STACK_ABT_SIZE		1024
#endif
#define STACK_THREAD_SIZE	8192

#if PLATFORM_FLAVOR_IS(fvp)
/*
 * FVP specifics.
 */

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x80000000

/* Location of trusted dram on the base fvp */
#define TZDRAM_BASE		0x06000000
#define TZDRAM_SIZE		0x02000000

#define CFG_TEE_CORE_NB_CORE	4

#define DDR_PHYS_START		DRAM0_BASE
#define DDR_SIZE		DRAM0_SIZE

#define CFG_DDR_START		DDR_PHYS_START
#define CFG_DDR_SIZE		DDR_SIZE

#define CFG_DDR_TEETZ_RESERVED_START	TZDRAM_BASE
#define CFG_DDR_TEETZ_RESERVED_SIZE	TZDRAM_SIZE

#define TEE_RAM_START		(TZDRAM_BASE + 0x1000)
#define TEE_RAM_SIZE		0x0010000

#define CFG_SHMEM_START		(DDR_PHYS_START + 0x1000000)
#define CFG_SHMEM_SIZE		0x100000

#define GICC_OFFSET		0x0
#define GICD_OFFSET		0x3000000

#elif PLATFORM_FLAVOR_IS(juno)

/*
 * Juno specifics.
 */

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x7F000000

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

#define CFG_TEE_CORE_NB_CORE	6

#define DDR_PHYS_START		DRAM0_BASE
#define DDR_SIZE		DRAM0_SIZE

#define CFG_DDR_START		DDR_PHYS_START
#define CFG_DDR_SIZE		DDR_SIZE

#define CFG_DDR_TEETZ_RESERVED_START	TZDRAM_BASE
#define CFG_DDR_TEETZ_RESERVED_SIZE	TZDRAM_SIZE

#define TEE_RAM_START		(TZDRAM_BASE)
#define TEE_RAM_SIZE		0x0010000

#define CFG_SHMEM_START		(DRAM0_BASE + DRAM0_SIZE - CFG_SHMEM_SIZE)
#define CFG_SHMEM_SIZE		0x100000

#define GICC_OFFSET		0x1f000
#define GICD_OFFSET		0

#elif PLATFORM_FLAVOR_IS(qemu)
/*
 * QEMU specifics.
 */
#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x40000000

/* Location of "trusted dram" */
#define TZDRAM_BASE		0xC0000000
#define TZDRAM_SIZE		0x02000000

#define DDR_PHYS_START		DRAM0_BASE
#define DDR_SIZE		DRAM0_SIZE

#define CFG_DDR_START		DDR_PHYS_START
#define CFG_DDR_SIZE		DDR_SIZE

#define CFG_TEE_CORE_NB_CORE	2


#define CFG_DDR_TEETZ_RESERVED_START	TZDRAM_BASE
#define CFG_DDR_TEETZ_RESERVED_SIZE	TZDRAM_SIZE

#define TEE_RAM_START		TZDRAM_BASE
#define TEE_RAM_SIZE		0x0010000

#define CFG_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define CFG_SHMEM_SIZE		0x100000

#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000

#elif PLATFORM_FLAVOR_IS(qemu_virt)
/*
 * QEMU virt specifics.
 */
#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		0x40000000

/* Location of "trusted dram" */
#define TZDRAM_BASE		(DRAM0_BASE + (DRAM0_SIZE - \
				 TZDRAM_SIZE - CFG_SHMEM_SIZE))
#define TZDRAM_SIZE		0x02000000

#define DDR_PHYS_START		DRAM0_BASE
#define DDR_SIZE		DRAM0_SIZE

#define CFG_DDR_START		DDR_PHYS_START
#define CFG_DDR_SIZE		DDR_SIZE

#define CFG_TEE_CORE_NB_CORE	2


#define CFG_DDR_TEETZ_RESERVED_START	TZDRAM_BASE
#define CFG_DDR_TEETZ_RESERVED_SIZE	TZDRAM_SIZE

#define TEE_RAM_START		TZDRAM_BASE
#define TEE_RAM_SIZE		0x0010000

#define CFG_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define CFG_SHMEM_SIZE		0x100000

#define GICD_OFFSET		0
#define GICC_OFFSET		0x10000


#else
#error "Unknown platform flavor"
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
