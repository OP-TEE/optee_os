/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SpacemiT K1 platform configuration
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <riscv.h>

/* DDR: up to 2 GiB at 0, the rest above 4 GiB */
#define DRAM0_BASE		0x00000000
#define DRAM0_SIZE		0x80000000
#define DRAM1_BASE		0x100000000ULL
#define DRAM1_SIZE		0x80000000

#define CLINT_BASE		0xe4000000
#define PLIC_BASE		0xe0000000

/* PXA/XScale 8250, 32-bit registers */
#define UART0_BASE		0xd4017000
#define UART0_REG_SHIFT		2

/* Every interrupt belongs to Linux: OP-TEE returns to it to have them served */
#define PLAT_THREAD_EXCP_FOREIGN_INTR	\
	(CSR_XIE_EIE | CSR_XIE_TIE | CSR_XIE_SIE)
#define PLAT_THREAD_EXCP_NATIVE_INTR	(0)

#endif /* PLATFORM_CONFIG_H */
