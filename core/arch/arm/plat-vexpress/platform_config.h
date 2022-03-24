/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
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

#define GIC_BASE		0x08000000
#define UART0_BASE		0x09000000
#define UART1_BASE		0x09040000

#define IT_UART1		40

#define CONSOLE_UART_BASE	UART1_BASE
#define IT_CONSOLE_UART		IT_UART1

#define TPM2_BASE		0x0c000000

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

#define GICC_OFFSET		0x1f000
#define GICD_OFFSET		0

#elif defined(PLATFORM_FLAVOR_qemu_virt)
/*
 * QEMU virt specifics.
 */

#define SECRAM_BASE		0x0e000000
#define SECRAM_COHERENT_SIZE	4096

#define GICD_OFFSET		0
#define GICC_OFFSET		0x10000

#elif defined(PLATFORM_FLAVOR_qemu_armv8a)

#define GICD_OFFSET		0
#define GICC_OFFSET		0x10000

#else
#error "Unknown platform flavor"
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
