/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2025 NXP
 *
 * Brief CVA6 APU platform configuration.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <riscv.h>

/* DRAM */
#ifndef DRAM_BASE
#define DRAM_BASE		0x80000000
#define DRAM_SIZE		0x40000000
#endif

/* CLINT */
#ifndef CLINT_BASE
#define CLINT_BASE		0x02000000
#endif

/* PLIC */
#ifndef PLIC_BASE
#define PLIC_BASE		0x0c000000
#define PLIC_REG_SIZE   0x4000000
#define PLIC_NUM_SOURCES	30
#endif

/* UART */
#ifndef UART0_BASE
#define UART0_BASE		0x10000000
#endif

#ifdef CFG_RISCV_MTIME_RATE
#define RISCV_MTIME_RATE CFG_RISCV_MTIME_RATE
#else
#define RISCV_MTIME_RATE 1000000
#endif

#define PLAT_THREAD_EXCP_FOREIGN_INTR	\
	(CSR_XIE_EIE | CSR_XIE_TIE | CSR_XIE_SIE)
#define PLAT_THREAD_EXCP_NATIVE_INTR	(0)

#endif /*PLATFORM_CONFIG_H*/
